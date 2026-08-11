#!/usr/bin/env python3
"""CLI for starting/stopping containers registered in the Locator.

The Locator never touches Docker itself — start/stop goes through the same
/api/container/toggle endpoint the web dashboard's Deploy/Shutdown button
uses, which queues a command for the Lokey agent running on the container's
actual host. Lokey picks it up, runs it locally, and reports back — so
`start`/`stop` here only confirm the command was *queued*, not that it's
done yet. Use `status`/`registry ls` (or watch the dashboard) to see it land.

migrate/dns follow the same "queue it, agent executes it" philosophy: migrate
queues a job in Locator's migration_queue (container or native, picked
automatically from the service's registered type) that the target/source
unit's agent picks up and runs; dns sync only confirms ns1 sent a NOTIFY, not
that a secondary applied it.

Usage:
    export LOCATOR_URL="https://tobsco-locator.fly.dev"   # default shown
    locatorctl.py start <container-name>
    locatorctl.py stop  <container-name>
    locatorctl.py status <container-name>
    locatorctl.py registry ls
    locatorctl.py migrate <name@host> --to <unit> [--force]
    locatorctl.py dns status
    locatorctl.py dns sync <zone>
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


def migrate(name, to_node, force):
    resp = requests.post(
        f"{LOCATOR_URL}/api/migrations",
        json={"service": name, "to_node": to_node, "force": force},
        timeout=30,
    )
    data = resp.json()
    if resp.status_code != 200:
        print(f"error: {data.get('error', resp.text)}", file=sys.stderr)
        if data.get("missing"):
            print(f"  missing dependencies: {', '.join(data['missing'])}", file=sys.stderr)
            print("  pass --force to migrate anyway", file=sys.stderr)
        sys.exit(1)
    print(f"queued: migration {data['id']} ({data['type']}) — '{name}' → {to_node}")


def dns_status():
    resp = requests.get(f"{LOCATOR_URL}/api/dns/status", timeout=30)
    resp.raise_for_status()
    data = resp.json()
    print(f"ns1: {data.get('ns1_host')}")
    for zone, info in sorted(data.get("zones", {}).items()):
        if info.get("ok"):
            print(f"\n== {zone} ==\n{info['content']}")
        else:
            print(f"\n== {zone} ==\nerror: {info.get('error')}")


def dns_sync(zone):
    resp = requests.post(f"{LOCATOR_URL}/api/dns/sync", json={"zone": zone}, timeout=30)
    data = resp.json()
    if resp.status_code != 200 or not data.get("ok"):
        print(f"error: {data.get('error', data.get('output', resp.text))}", file=sys.stderr)
        sys.exit(1)
    print(f"notified: {zone} from {data.get('notified_from')}")
    print(f"  {data.get('note')}")


COMMANDS = {
    "registry": "Inspect the service registry",
    "status":  "Show the current status of one service",
    "start":   "Queue a container start on its host (runs via Lokey)",
    "stop":    "Queue a container stop on its host (runs via Lokey)",
    "migrate": "Migrate a service to another node (container or native, auto-detected)",
    "dns":     "Check or trigger a sync of the PowerDNS zones ns1 serves",
}

EPILOG = """\
Environment:
  LOCATOR_URL  Registry URL (default: https://tobsco-locator.fly.dev)

start/stop only confirm the command was queued — Lokey executes it on the
container's actual host. Use `status`/`registry ls` or the dashboard to see it land.
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

    reg_p = sub.add_parser("registry", help=COMMANDS["registry"], description=COMMANDS["registry"])
    reg_sub = reg_p.add_subparsers(dest="registry_command", required=True, metavar="<registry-command>")
    reg_sub.add_parser("ls", help="List every registered service with its current status")

    # Legacy spelling of `registry ls`, kept working but hidden from help.
    sub.add_parser("list")

    mig_p = sub.add_parser("migrate", help=COMMANDS["migrate"], description=COMMANDS["migrate"])
    mig_p.add_argument("name", help="service_id as shown by `list` (name@host)")
    mig_p.add_argument("--to", required=True, dest="to_node", help="destination unit/node id")
    mig_p.add_argument("--force", action="store_true", help="ignore unmet dependencies")

    dns_p = sub.add_parser("dns", help=COMMANDS["dns"], description=COMMANDS["dns"])
    dns_sub = dns_p.add_subparsers(dest="dns_command", required=True, metavar="<dns-command>")
    dns_sub.add_parser("status", help="Show each configured zone's content as served by ns1")
    sync_p = dns_sub.add_parser("sync", help="Force ns1 to NOTIFY secondaries of a zone")
    sync_p.add_argument("zone", help="zone name, e.g. theofficialblacksheepco.com")

    args = parser.parse_args()

    if args.command in ("start", "stop"):
        toggle(args.name, args.command)
    elif args.command == "status":
        status(args.name)
    elif args.command == "registry":
        if args.registry_command == "ls":
            list_services()
    elif args.command == "list":
        list_services()
    elif args.command == "migrate":
        migrate(args.name, args.to_node, args.force)
    elif args.command == "dns":
        if args.dns_command == "status":
            dns_status()
        elif args.dns_command == "sync":
            dns_sync(args.zone)


if __name__ == "__main__":
    main()
