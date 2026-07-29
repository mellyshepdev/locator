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


COMMANDS = {
    "list":   "List every registered service with its current status",
    "status": "Show the current status of one service",
    "start":  "Queue a container start on its host (runs via Lokey)",
    "stop":   "Queue a container stop on its host (runs via Lokey)",
}

EPILOG = """\
Environment:
  LOCATOR_URL  Registry URL (default: https://tobsco-locator.fly.dev)

start/stop only confirm the command was queued — Lokey executes it on the
container's actual host. Use `status`/`list` or the dashboard to see it land.
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

    args = parser.parse_args()

    if args.command in ("start", "stop"):
        toggle(args.name, args.command)
    elif args.command == "status":
        status(args.name)
    elif args.command == "list":
        list_services()


if __name__ == "__main__":
    main()
