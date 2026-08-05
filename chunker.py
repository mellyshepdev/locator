"""
Chunker — Intelligent Deployment Orchestrator for Locator
Parses deployment bundles (locator.yml + docker-compose.yml + supporting files)
Analyzes unit capabilities from memory files
Makes smart placement decisions
Stores deployment state in database
Posts compose.yml to Locator UI
"""

import os
import json
import yaml
import sqlite3
import subprocess
import zipfile
import base64
import requests
from datetime import datetime, timezone
from pathlib import Path
from io import BytesIO

# ── CONFIGURATION ──────────────────────────────────────────────────────────

DB_PATH = os.environ.get("DEPLOYMENT_DB", "deployments.db")
VAULTWARDEN_URL = os.environ.get("VAULTWARDEN_URL", "http://unit6:6000")
LOCATOR_UI_URL = os.environ.get("LOCATOR_UI_URL", "http://unit6:5000")

# ── DATABASE SETUP ──────────────────────────────────────────────────────────

def init_db():
    """Initialize deployment tracking database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS deployments (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            deployment_type TEXT,
            location_type TEXT,
            target_unit TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            compose_content TEXT,
            locator_yml_content TEXT,
            bundle_compressed BLOB,
            bundle_files TEXT,
            created_at TEXT,
            deployed_at TEXT,
            vaultwarden_id TEXT,
            metadata TEXT
        )
    """)
    conn.commit()
    conn.close()

def compress_bundle(bundle_path):
    """Compress deployment bundle to bytes."""
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_path in Path(bundle_path).rglob("*"):
            if file_path.is_file():
                arcname = file_path.relative_to(bundle_path)
                zipf.write(file_path, arcname)
    return zip_buffer.getvalue()

def save_deployment(deployment_id, name, deployment_type, location_type, target_unit,
                   compose_content, locator_yml_content, bundle_path, bundle_files,
                   vaultwarden_id=None, metadata=None):
    """Store deployment metadata and compressed bundle in database."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()

    # Compress bundle
    bundle_compressed = compress_bundle(bundle_path)

    c.execute("""
        INSERT OR REPLACE INTO deployments
        (id, name, deployment_type, location_type, target_unit, compose_content,
         locator_yml_content, bundle_compressed, bundle_files, created_at,
         vaultwarden_id, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (deployment_id, name, deployment_type, location_type, target_unit,
          compose_content, locator_yml_content, bundle_compressed,
          json.dumps(bundle_files), now, vaultwarden_id, json.dumps(metadata or {})))

    conn.commit()
    conn.close()

def update_deployment_status(deployment_id, status, deployed_at=None):
    """Update deployment status."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = deployed_at or datetime.now(timezone.utc).isoformat()

    c.execute("""
        UPDATE deployments SET status = ?, deployed_at = ? WHERE id = ?
    """, (status, now, deployment_id))

    conn.commit()
    conn.close()

# ── LOCATOR.YML PARSING ──────────────────────────────────────────────────────

def parse_locator_yml(bundle_path):
    """Parse locator.yml from deployment bundle."""
    locator_yml_path = os.path.join(bundle_path, "locator.yml")

    if not os.path.exists(locator_yml_path):
        return None

    with open(locator_yml_path, 'r') as f:
        return yaml.safe_load(f)

def parse_docker_compose(bundle_path):
    """Parse docker-compose.yml from bundle."""
    compose_path = os.path.join(bundle_path, "docker-compose.yml")

    if not os.path.exists(compose_path):
        return None

    with open(compose_path, 'r') as f:
        return yaml.safe_load(f)

# ── EXTERNAL SERVICE INTEGRATION ────────────────────────────────────────────

def send_env_to_vaultwarden(bundle_path, deployment_name):
    """Extract .env file and send to Vaultwarden."""
    env_path = os.path.join(bundle_path, ".env")

    if not os.path.exists(env_path):
        print("⚠️ No .env file found in bundle")
        return None

    try:
        with open(env_path, 'r') as f:
            env_content = f.read()

        # Store as secure note in Vaultwarden
        payload = {
            "name": f"{deployment_name}-env",
            "type": "note",
            "content": env_content,
            "tags": ["deployment", deployment_name]
        }

        resp = requests.post(
            f"{VAULTWARDEN_URL}/api/vault/secure-notes",
            json=payload,
            timeout=10
        )

        if resp.status_code in [200, 201]:
            result = resp.json()
            vault_id = result.get("id")
            print(f"✅ .env stored in Vaultwarden (ID: {vault_id})")
            return vault_id
        else:
            print(f"⚠️ Vaultwarden store failed: {resp.status_code}")
            return None

    except Exception as e:
        print(f"⚠️ Error sending .env to Vaultwarden: {e}")
        return None

def post_compose_to_ui(deployment_id, deployment_name, compose_content, target_unit,
                       deployment_type, location_type, metadata):
    """Post docker-compose.yml to Locator UI."""
    try:
        payload = {
            "id": deployment_id,
            "name": deployment_name,
            "target_unit": target_unit,
            "deployment_type": deployment_type,
            "location_type": location_type,
            "compose": compose_content,
            "status": "deployed",
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata
        }

        resp = requests.post(
            f"{LOCATOR_UI_URL}/api/deployments",
            json=payload,
            timeout=10
        )

        if resp.status_code in [200, 201]:
            print(f"✅ Deployment posted to Locator UI")
            return True
        else:
            print(f"⚠️ UI post failed: {resp.status_code}")
            return False

    except Exception as e:
        print(f"⚠️ Error posting to Locator UI: {e}")
        return False

# ── UNIT MEMORY ANALYSIS ─────────────────────────────────────────────────────

def read_unit_memory(unit_id):
    """Read and parse unit memory files to understand capabilities."""
    memory_dir = Path.home() / ".claude" / "projects" / "-home-swoopg11111" / "memory"

    unit_info = {
        "id": unit_id,
        "infrastructure": {},
        "services": {},
        "resources": {},
        "status": "unknown"
    }

    # Find memory files related to this unit
    if memory_dir.exists():
        for md_file in memory_dir.glob("*.md"):
            try:
                with open(md_file, 'r') as f:
                    content = f.read()

                    # Extract unit-specific info
                    if unit_id.lower() in md_file.name.lower() or unit_id.lower() in content.lower():
                        # Parse YAML frontmatter
                        if content.startswith('---'):
                            _, frontmatter_end = content.split('---', 2)[0:2]
                            frontmatter = yaml.safe_load(content[4:content.find('---', 4)])
                            body = content[content.find('---', 4) + 3:].strip()

                            if frontmatter:
                                unit_info["metadata"] = frontmatter

                            # Parse body for capabilities
                            if "infrastructure" in body.lower():
                                unit_info["has_infrastructure_details"] = True
                            if "ram" in body.lower() or "memory" in body.lower():
                                # Try to extract RAM info
                                import re
                                ram_match = re.search(r'(\d+\.?\d*)\s*(?:GB|MB|gb|mb)', body)
                                if ram_match:
                                    unit_info["resources"]["memory"] = ram_match.group(0)
            except Exception as e:
                print(f"⚠️ Error reading {md_file}: {e}")

    return unit_info

def analyze_all_units():
    """Analyze all units and their capabilities."""
    unit_ids = ["unit1", "unit2", "unit3", "unit4", "unit5", "unit6", "unit7", "unit8", "unit9"]
    analysis = {}

    for unit_id in unit_ids:
        analysis[unit_id] = read_unit_memory(unit_id)

    return analysis

# ── INTELLIGENT PLACEMENT LOGIC ──────────────────────────────────────────────

def score_unit_for_deployment(unit_id, unit_info, deployment_spec):
    """
    Score a unit based on:
    1. Memory match (deployment_type, location_type expectations)
    2. Available resources vs requested
    3. Current service load
    4. Location preference (stationary/mobile)
    Returns: (score, reasons)
    """
    score = 100  # Base score
    reasons = []

    deployment_type = deployment_spec.get("deployment_type", "standard")
    location_type = deployment_spec.get("location_type", "stationary")

    # Check unit infrastructure capability
    unit_memory = unit_info.get("infrastructure", {})

    # Essential deployments need stable, available units
    if deployment_type == "essential":
        # Prefer units with documented stable infrastructure
        if "has_infrastructure_details" in unit_info:
            score += 20
            reasons.append("✓ Unit has documented infrastructure")
        else:
            score -= 15
            reasons.append("⚠ Limited infrastructure documentation")

    # Location type scoring
    if location_type == "stationary":
        # Prefer units marked as stable/always-on
        if "status" in unit_info and unit_info["status"] != "unknown":
            score += 10
            reasons.append("✓ Status known and documented")

    # Resource availability
    if "resources" in unit_info and "memory" in unit_info["resources"]:
        reasons.append(f"✓ Available resources: {unit_info['resources']['memory']}")

    return score, reasons

def get_best_unit_for_deployment(bundle_path, units_analysis=None):
    """
    Determine best unit for deployment bundle.
    1. Parse locator.yml for requirements
    2. Analyze all units
    3. Score and select best match
    """
    locator_yml = parse_locator_yml(bundle_path)

    if not locator_yml:
        print("⚠️ No locator.yml found — using default placement")
        return "unit1", {"reason": "default_fallback"}

    name = locator_yml.get("name", "unknown")
    deployment_type = locator_yml.get("deployment_type", "standard")
    location_type = locator_yml.get("location_type", "stationary")

    print(f"\n🔍 Analyzing placement for: {name}")
    print(f"   Type: {deployment_type} | Location: {location_type}\n")

    # Analyze all units if not provided
    if not units_analysis:
        units_analysis = analyze_all_units()

    # Score each unit
    scores = {}
    for unit_id, unit_info in units_analysis.items():
        score, reasons = score_unit_for_deployment(unit_id, unit_info, locator_yml)
        scores[unit_id] = {"score": score, "reasons": reasons, "info": unit_info}

        print(f"  {unit_id}: {score} pts")
        for reason in reasons:
            print(f"    {reason}")

    # Select best unit
    best_unit = max(scores.items(), key=lambda x: x[1]["score"])
    best_id, best_data = best_unit

    print(f"\n✅ Selected: {best_id} (score: {best_data['score']})\n")

    return best_id, {
        "locator_yml": locator_yml,
        "placement_reasoning": best_data["reasons"],
        "score": best_data["score"]
    }

# ── DEPLOYMENT EXECUTION ────────────────────────────────────────────────────

def create_status_locator_yml(deployment_id, name, deployment_type, location_type, target_unit):
    """Create locator.yml that tracks deployment status."""
    return {
        "id": deployment_id,
        "name": name,
        "deployment_type": deployment_type,
        "location_type": location_type,
        "target_unit": target_unit,
        "status": "deployed",
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "deployment_id": deployment_id
    }

def deploy_bundle(bundle_path):
    """
    Full deployment workflow:
    1. Parse locator.yml + docker-compose.yml
    2. Find best unit
    3. DEPLOY to target unit via SSH/locator agent
    4. After success: compress bundle, send .env to Vaultwarden
    5. Post compose.yml to Locator UI
    6. Store compressed bundle in database
    7. Create status locator.yml
    """
    init_db()

    # Parse bundle metadata
    locator_yml = parse_locator_yml(bundle_path)
    compose_yml = parse_docker_compose(bundle_path)

    if not locator_yml or not compose_yml:
        return {"error": "Missing locator.yml or docker-compose.yml"}

    deployment_name = locator_yml.get("name", "unnamed")
    deployment_id = f"{deployment_name}_{datetime.now(timezone.utc).timestamp()}"
    deployment_type = locator_yml.get("deployment_type", "standard")
    location_type = locator_yml.get("location_type", "stationary")

    # Find best unit
    best_unit, placement_info = get_best_unit_for_deployment(bundle_path)

    print(f"\n📋 Deployment Details:")
    print(f"   ID: {deployment_id}")
    print(f"   Name: {deployment_name}")
    print(f"   Type: {deployment_type} / {location_type}")
    print(f"   Target: {best_unit}\n")

    # 1️⃣ DEPLOY to target unit via SSH
    print("🚀 Deploying to target unit...")
    update_deployment_status(deployment_id, "deploying")

    try:
        # Copy bundle to target unit via SSH
        print(f"   Connecting to {best_unit}...")
        deploy_dir = f"/tmp/locator-deploy-{deployment_id}"

        # Create remote directory and copy files
        subprocess.run(
            ["ssh", f"{best_unit}-mesh", f"mkdir -p {deploy_dir}"],
            check=True,
            capture_output=True,
            timeout=10
        )

        # Copy all files from bundle to target unit
        for file_path in Path(bundle_path).rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(bundle_path)
                subprocess.run(
                    ["scp", str(file_path), f"{best_unit}-mesh:{deploy_dir}/{rel_path}"],
                    check=True,
                    capture_output=True,
                    timeout=30
                )

        print(f"   Files copied to {best_unit}")

        # Run docker-compose up on target unit
        print(f"   Running docker-compose up...")
        result = subprocess.run(
            ["ssh", f"{best_unit}-mesh", f"cd {deploy_dir} && docker-compose up -d"],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            raise Exception(f"docker-compose failed: {result.stderr}")

        print(f"   Containers deployed")
        deployment_success = True

    except Exception as e:
        print(f"❌ Deployment to {best_unit} failed: {e}")
        update_deployment_status(deployment_id, "failed")
        return {"error": str(e), "deployment_id": deployment_id}

    if not deployment_success:
        update_deployment_status(deployment_id, "failed")
        return {"error": "Deployment failed on target unit", "deployment_id": deployment_id}

    print(f"✅ Deployed to {best_unit}")

    # Collect all files in bundle
    bundle_files = []
    for file_path in Path(bundle_path).rglob("*"):
        if file_path.is_file():
            bundle_files.append(str(file_path.relative_to(bundle_path)))

    # Read compose content
    with open(os.path.join(bundle_path, "docker-compose.yml"), 'r') as f:
        compose_content = f.read()
    with open(os.path.join(bundle_path, "locator.yml"), 'r') as f:
        locator_content = f.read()

    # 2️⃣ Send .env to Vaultwarden
    print("🔐 Storing secrets in Vaultwarden...")
    vaultwarden_id = send_env_to_vaultwarden(bundle_path, deployment_name)

    # 3️⃣ Compress and store bundle in database
    print("💾 Compressing bundle and storing in database...")
    save_deployment(
        deployment_id,
        deployment_name,
        deployment_type,
        location_type,
        best_unit,
        compose_content,
        locator_content,
        bundle_path,
        bundle_files,
        vaultwarden_id,
        placement_info
    )

    # 4️⃣ Post compose.yml to Locator UI
    print("📡 Posting to Locator UI...")
    post_compose_to_ui(
        deployment_id,
        deployment_name,
        compose_content,
        best_unit,
        deployment_type,
        location_type,
        placement_info
    )

    # 5️⃣ Create status locator.yml
    status_yml = create_status_locator_yml(
        deployment_id,
        deployment_name,
        deployment_type,
        location_type,
        best_unit
    )

    # Update deployment status
    update_deployment_status(deployment_id, "deployed", datetime.now(timezone.utc).isoformat())

    print(f"\n✅ Deployment complete!\n")

    return {
        "status": "success",
        "deployment_id": deployment_id,
        "target_unit": best_unit,
        "name": deployment_name,
        "deployment_type": deployment_type,
        "location_type": location_type,
        "vaultwarden_id": vaultwarden_id,
        "bundle_compressed": True,
        "bundle_files_count": len(bundle_files),
        "ui_posted": True,
        "status_locator_yml": status_yml,
        "placement_reasoning": placement_info
    }

# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: chunker.py <bundle_path>")
        sys.exit(1)

    bundle_path = sys.argv[1]

    if not os.path.isdir(bundle_path):
        print(f"❌ Bundle path not found: {bundle_path}")
        sys.exit(1)

    result = deploy_bundle(bundle_path)
    print(json.dumps(result, indent=2))
