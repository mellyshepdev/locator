# The Locator — Universal Service Registry

The Locator is the single source of truth for every process, container, API, and script in the Beast ecosystem. It tracks what is running, where it is running, and how to reach it.

## Features

1. **Active Traefik Discovery**: Automatically scans Traefik APIs on all known servers to find live websites/services and records their hostnames and host server.
2. **Self-Registration & Heartbeat**: Services can POST to `/register` periodically. If a service stops sending heartbeats (default 90s), it is marked `OFFLINE`.
3. **Universal Access**: Can be queried via HTTP, HTTPS, or by directly reading the `registry.json` file.
4. **Node Tracking**: Keeps a directory of servers (`devices.json` integration).

## Endpoints

- `GET /` — Full registry
- `GET /services` — List all services
- `GET /services/<name>` — Specific service info
- `GET /nodes` — List all nodes
- `POST /register` — Register a service / send heartbeat
- `POST /nodes` — Update node info
- `GET /registry.json` — Download the current registry file

## Beast Agent (Unit Sync & Migration)

The `locator_agent.py` script runs on each Unit server to provide real-time synchronization and migration capabilities.

### Features
- **Docker Sync**: Automatically pushes local container status and OpenVPN IPs to the Locator.
- **Git Protection**: Pushes container code to Git before any migration operation.
- **SCP/SSH Migration**: Moves container volumes and configurations between Units seamlessly.
- **Registry Watcher**: Monitors local `registry.json` changes to trigger immediate syncs.

### Usage
```bash
export LOCATOR_URL="http://locator.network"
export UNIT_ID="unit1"
python3 locator_agent.py
```

## Setup & Deployment

1. Make sure Traefik is running and the `proxy` network exists.
2. Run `docker compose up -d`
3. Point your DNS for `locator.theofficialblacksheepco.info` to the server running this container.

All containers on the same host can reach it internally at `http://locator:5000/`. External services and browsers can use the HTTPS domain.
