#!/usr/bin/env python3
"""CLI for starting/stopping containers registered in the Locator.

The Locator never touches Docker itself — start/stop goes through the same
/api/container/toggle endpoint the web dashboard's Deploy/Shutdown button
uses, which queues a command for the Lokey agent running on the container's
actual host. Lokey picks it up, runs it locally, and reports back — so
`start`/`stop` here only confirm the command was *queued*, not that it's
done yet. Use `status`/`list` (or watch the dashboard) to see it land.

Usage:
    export LOCATOR_URL="https://tobsco-locator.fly.dev"   # default shown
    locatorctl.py start <container-name>
    locatorctl.py stop  <container-name>
    locatorctl.py status <container-name>
    locatorctl.py list
"""
import argparse
import os
import sys

import requests

LOCATOR_URL = os.environ.get("LOCATOR_URL", "https://tobsco-locator.fly.dev")


def toggle(name, action):
    resp = requests.post(
        f"{LOCATOR_URL}/api/container/toggle",
        json={"name": name, "action": action},
        timeout=30,
    )
    data = resp.json()
    if resp.status_code != 200 or data.get("error"):
        print(f"error: {data.get('error', resp.text)}", file=sys.stderr)
        sys.exit(1)
    unit = data.get("unit", "?")
    print(f"queued: {action} '{name}' on {unit} (lokey will execute it shortly)")


def status(name):
    resp = requests.get(f"{LOCATOR_URL}/services/{name}", timeout=10)
    if resp.status_code != 200:
        print(f"error: {resp.text}", file=sys.stderr)
        sys.exit(1)
    data = resp.json()
    print(f"{name}: {data.get('status', 'unknown')}")


def list_services():
    resp = requests.get(f"{LOCATOR_URL}/services", timeout=10)
    resp.raise_for_status()
    for name, svc in sorted(resp.json().items()):
        print(f"{svc.get('status', '?'):8s} {name}")


def migrate(name, to_node):
    resp = requests.post(
        f"{LOCATOR_URL}/api/migrations",
        json={"name": name, "to_node": to_node},
        timeout=30,
    )
    data = resp.json()
    if resp.status_code != 200 or data.get("error"):
        print(f"error: {data.get('error', resp.text)}", file=sys.stderr)
        sys.exit(1)
    print(f"queued: migrate '{name}' → {to_node} (id {data['id']}, executing on {data['unit']})")
    print("Native migrations can take a while (venv rebuild) — use `status`/`list` or the dashboard's Migration Queue panel to watch it land.")


COMMANDS = {
    "list":    "List every registered service with its current status",
    "status":  "Show the current status of one service",
    "start":   "Queue a container start on its host (runs via Lokey)",
    "stop":    "Queue a container stop on its host (runs via Lokey)",
    "migrate": "Queue a move of a container or native service to another unit",
}

EPILOG = """\
Environment:
  LOCATOR_URL  Registry URL (default: https://tobsco-locator.fly.dev)

start/stop only confirm the command was queued — Lokey executes it on the
container's actual host. Use `status`/`list` or the dashboard to see it land.

migrate works for both Docker containers and native (systemd/venv) services —
the target service's registered type decides how it's moved. For native
services, Lokey detects at run time whether it's a real systemd unit or a
bare background process and migrates accordingly; native moves that need a
venv are rebuilt from requirements.txt on the target, so they take longer
than a container move.
"""


def main():
    parser = argparse.ArgumentParser(
        prog="locator",
        description="Terminal client for the Locator registry — start/stop containers and check service status.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    for cmd in ("start", "stop", "status"):
        p = sub.add_parser(cmd, help=COMMANDS[cmd], description=COMMANDS[cmd])
        p.add_argument("name", help="service/container name as registered in the Locator")

    sub.add_parser("list", help=COMMANDS["list"], description=COMMANDS["list"])

    p = sub.add_parser("migrate", help=COMMANDS["migrate"], description=COMMANDS["migrate"])
    p.add_argument("name", help="service/container name as registered in the Locator")
    p.add_argument("to_node", help="unit to migrate it to, e.g. unit5")

    args = parser.parse_args()

    if args.command in ("start", "stop"):
        toggle(args.name, args.command)
    elif args.command == "status":
        status(args.name)
    elif args.command == "list":
        list_services()
    elif args.command == "migrate":
        migrate(args.name, args.to_node)


if __name__ == "__main__":
    main()
