import os
import yaml
import subprocess
import json
from datetime import datetime, timezone

# This would be your existing registry and gRPC data
UNITS = {
    "unit1": {"ip": "192.168.1.x", "type": "home_server"},
    "unit2": {"ip": "vps_ip", "type": "vps"},
    # ... add all 6 units here
}


def get_best_unit(preferred_servers=None):
    """
    Returns (node_id, ip) for the ONLINE node with the most headroom.
    Uses live cpu/mem/disk metrics when available; falls back to seeded RAM.
    Nodes in preferred_servers get a 20-point load bonus (treated as more free).
    """
    data_dir = os.environ.get("DATA_DIR", "data")
    registry_path = os.path.join(data_dir, "registry.json")

    if not os.path.exists(registry_path):
        return "unit1", "localhost"

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
                or info.get("ip", "localhost").split("-")[0].strip().split()[0]
                or info.get("openvpn_ip", "").split("-")[0].strip().split()[0]
                or "localhost"
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

            # Preferred nodes get a bonus (lower score = more headroom)
            if preferred_servers and node_id in preferred_servers:
                score -= 20

            candidates.append({"id": node_id, "ip": ip, "score": score})

        if not candidates:
            return "unit1", "localhost"

        candidates.sort(key=lambda x: x["score"])
        best = candidates[0]
        return best["id"], best["ip"]

    except Exception as e:
        print(f"⚠️ Error scoring nodes: {e}")
        return "unit1", "localhost"

def deploy_from_browse(folder_path, target_servers=None, join_networks=None):
    compose_file = os.path.join(folder_path, 'docker-compose.yml')
    
    if not os.path.exists(compose_file):
        return {"error": "No docker-compose.yml found in selected folder"}

    # 1. SEARCH THE NETWORK (Respecting user checkbox choices)
    target_unit, target_ip = get_best_unit(target_servers)
    
    print(f"🏗️ Selected node: {target_unit} (User Selection/Scoring Applied)")
    print(f"🌐 Networks requested: {join_networks}")

    try:
        with open(compose_file, 'r') as f:
            compose_data = yaml.safe_load(f) or {}
            services = compose_data.get('services', {})

        # Modify the compose data in memory if specific networks were requested
        if join_networks:
            for s_name, s_cfg in services.items():
                if 'networks' not in s_cfg: s_cfg['networks'] = []
                for net in join_networks:
                    if net not in s_cfg['networks']: s_cfg['networks'].append(net)
            
            # Write back temporary modified compose if needed, 
            # or just rely on existing environment-based network joining.
            pass

        # Run docker-compose up -d
        result = subprocess.run(
            ["docker-compose", "up", "-d"], 
            cwd=folder_path, 
            capture_output=True, 
            text=True
        )
        
        if result.returncode != 0:
            return {"error": result.stderr}

        deployment_results = {}
        for service_name in services:
            update_registry(service_name, target_unit, metadata={"joined_networks": join_networks})
            deployment_results[service_name] = target_unit

        return {"status": "Success", "target": target_unit, "deployed": deployment_results}

    except Exception as e:
        return {"error": str(e)}

def update_registry(container_name, unit_id, metadata=None):
    # Use the same data directory as locator.py
    data_dir = os.environ.get("DATA_DIR", "data")
    os.makedirs(data_dir, exist_ok=True)
    registry_path = os.path.join(data_dir, "registry.json")
    
    data = {"services": {}, "nodes": {}, "updated": ""}
    if os.path.exists(registry_path):
        with open(registry_path, 'r') as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                pass
    
    if "services" not in data:
        data = {"services": {}, "nodes": {}, "updated": ""}

    now = datetime.now(timezone.utc).isoformat()
    service_id = f"{container_name}@{unit_id}"
    
    existing_meta = data["services"].get(service_id, {}).get("metadata", {})
    if metadata:
        existing_meta.update(metadata)

    data["services"][service_id] = {
        "name": container_name,
        "host": unit_id,
        "status": "ONLINE",
        "category": "docker containers",
        "last_heartbeat": now,
        "registered_at": now,
        "metadata": existing_meta
    }
    data["updated"] = now
    
    with open(registry_path, 'w') as f:
        json.dump(data, f, indent=4)

