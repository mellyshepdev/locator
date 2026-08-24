import os
import yaml
import subprocess
import json
import requests
from datetime import datetime, timezone

SSH_USER = os.environ.get("SSH_USER", "swoopg111")
SSH_KEY = os.environ.get("SSH_KEY", "")  # Optional path to id_rsa / private key


def get_best_unit(preferred_servers=None):
    """
    Returns (node_id, ip) for the ONLINE node with the most headroom.
    """
    data_dir = os.environ.get("DATA_DIR", "/app/data")
    registry_path = os.path.join(data_dir, "registry.json")

    if not os.path.exists(registry_path):
        return "unit1", "127.0.0.1"

    try:
        with open(registry_path, 'r') as f:
            reg = json.load(f)

        nodes = reg.get("nodes", {})
        candidates = []

        for node_id, info in nodes.items():
            if info.get("status") != "ONLINE":
                continue

            ip = (
                info.get("tailscale_ip")
                or info.get("ip", "127.0.0.1").split("-")[0].strip().split()[0]
                or info.get("openvpn_ip", "").split("-")[0].strip().split()[0]
                or "127.0.0.1"
            )

            cpu  = info.get("cpu_percent")
            mem  = info.get("mem_percent")
            disk = info.get("disk_percent")

            if cpu is not None and mem is not None:
                divisor = 3 if disk is not None else 2
                score = (cpu + mem + (disk or 0)) / divisor
            else:
                ram_str = info.get("metadata", {}).get("ram", "0").lower()
                try:
                    ram_gb = int(''.join(filter(str.isdigit, ram_str)))
                except Exception:
                    ram_gb = 1
                score = max(0, 100 - ram_gb)

            # Preferred nodes get a 20-point load reduction priority
            if preferred_servers and node_id in preferred_servers:
                score -= 20

            candidates.append({"id": node_id, "ip": ip, "score": score})

        if not candidates:
            return "unit1", "127.0.0.1"

        candidates.sort(key=lambda x: x["score"])
        best = candidates[0]
        return best["id"], best["ip"]

    except Exception as e:
        print(f"⚠️ Error scoring nodes: {e}")
        return "unit1", "127.0.0.1"


def deploy_from_browse(folder_path, target_servers=None, join_networks=None):
    compose_file = os.path.join(folder_path, 'docker-compose.yml')
    if not os.path.exists(compose_file):
        compose_file = os.path.join(folder_path, 'docker-compose.yaml')
        if not os.path.exists(compose_file):
            return {"error": "No docker-compose.yml found in selected folder"}

    target_unit, target_ip = get_best_unit(target_servers)
    local_unit = os.environ.get("UNIT_NAME", "unit1")

    print(f"🏗️ Selected target node: {target_unit} ({target_ip})")

    try:
        with open(compose_file, 'r') as f:
            compose_data = yaml.safe_load(f) or {}

        services = compose_data.get('services', {})
        if not services:
            return {"error": "No services defined in compose file"}

        # Inject requested networks
        if join_networks:
            for s_name, s_cfg in services.items():
                if not isinstance(s_cfg, dict):
                    continue
                if 'networks' not in s_cfg:
                    s_cfg['networks'] = []
                for net in join_networks:
                    if net not in s_cfg['networks']:
                        s_cfg['networks'].append(net)

            # Save modified layout back to folder before dispatching
            with open(compose_file, 'w') as f:
                yaml.dump(compose_data, f)

        project_name = os.path.basename(os.path.normpath(folder_path))

        # DIRECTORY DEPLOYMENT ROUTING: Local vs Remote SSH/SCP
        if target_unit == local_unit or target_ip in ("127.0.0.1", "localhost"):
            result = subprocess.run(
                ["docker", "compose", "up", "-d"],
                cwd=folder_path,
                capture_output=True,
                text=True
            )
            if result.returncode != 0:
                # Fallback for systems running legacy docker-compose v1
                result = subprocess.run(
                    ["docker-compose", "up", "-d"],
                    cwd=folder_path,
                    capture_output=True,
                    text=True
                )
        else:
            remote_dir = f"/tmp/locator_deploy/{project_name}"
            remote_file = f"{remote_dir}/docker-compose.yml"
            ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]
            if SSH_KEY:
                ssh_opts += ["-i", SSH_KEY]
            ssh_target = f"{SSH_USER}@{target_ip}"

            # 1. Create directory on target node
            subprocess.run(["ssh"] + ssh_opts + [ssh_target, f"mkdir -p {remote_dir}"], check=True, timeout=15)
            # 2. SCP modified compose file over
            subprocess.run(["scp"] + ssh_opts + [compose_file, f"{ssh_target}:{remote_file}"], check=True, timeout=15)
            # 3. Trigger remote stack boot
            result = subprocess.run(
                ["ssh"] + ssh_opts + [ssh_target, f"cd {remote_dir} && docker compose up -d"],
                capture_output=True,
                text=True,
                timeout=120
            )

        if result.returncode != 0:
            return {"error": f"Deployment execution failed on {target_unit}: {result.stderr}"}

        # Notify Locator's API to keep live memory state updated
        locator_port = os.environ.get("LOCATOR_PORT", "5000")
        deployment_results = {}
        for service_name in services:
            try:
                requests.post(
                    f"http://127.0.0.1:{locator_port}/register",
                    json={
                        "name": service_name,
                        "host": target_unit,
                        "type": "container",
                        "category": "docker containers",
                        "metadata": {
                            "joined_networks": join_networks,
                            "deployed_via": "deploy_from_browse",
                            "project": project_name
                        }
                    },
                    timeout=3
                )
            except Exception:
                pass
            deployment_results[service_name] = target_unit

        return {"status": "Success", "target": target_unit, "deployed": deployment_results}

    except Exception as e:
        return {"error": f"Deploy exception: {str(e)}"}