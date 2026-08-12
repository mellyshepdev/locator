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
    export LOCATOR_URL="https://locator.theofficialblacksheepco.online"   # default shown
    locatorctl.py start <container-name>
    locatorctl.py stop  <container-name>
    locatorctl.py status <container-name>
    locatorctl.py registry ls
    locatorctl.py health [--since 6h] [--all]
    locatorctl.py migrate <name@host> --to <unit> [--force]
    locatorctl.py dns status
    locatorctl.py dns sync <zone>
"""
import argparse
import collections
import datetime as dt
import json
import os
import re
import subprocess
import sys

import requests

LOCATOR_URL = os.environ.get("LOCATOR_URL", "https://locator.theofficialblacksheepco.online")


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


def _fetch(path, timeout=30):
    resp = requests.get(f"{LOCATOR_URL}{path}", timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _endpoint(svc):
    """Best reachable address for a service, preferring the public one.

    Agents publish these inconsistently — some register a public `url`, some
    only an `internal` address, some just a port — so fall back through them
    rather than showing a blank cell.
    """
    url = (svc.get("url") or "").strip()
    if url:
        return url
    internal = (svc.get("internal") or "").strip()
    if internal:
        return internal
    port = svc.get("port")
    if port:
        return f"{svc.get('host', '?')}:{port}"
    return "-"


def _mem(svc):
    md = svc.get("metadata") or {}
    if not isinstance(md, dict):
        return "-"
    used = md.get("mem_usage_mb")
    limit = md.get("mem_limit_mb")
    if used is None:
        return "-"
    if limit:
        return f"{used:.0f}/{limit:.0f}M"
    return f"{used:.0f}M"


def _fresh_enough(svc, max_age_days=30):
    beat = svc.get("last_heartbeat") or svc.get("offline_since")
    if not beat:
        # Statically seeded entries (cloud/external) never heartbeat at all.
        return str(svc.get("status", "")).upper() == "ONLINE"
    try:
        stamp = dt.datetime.fromisoformat(beat.replace("Z", "+00:00"))
    except ValueError:
        return True
    age = (dt.datetime.now(dt.timezone.utc) - stamp).total_seconds()
    return age <= max_age_days * 86400


def list_services(host_filter=None, online_only=False, show_all=False):
    services = _fetch("/services")

    rows, hidden = [], 0
    for name, svc in services.items():
        if not show_all and not _fresh_enough(svc):
            hidden += 1
            continue
        status = str(svc.get("status", "?")).upper()
        if online_only and status != "ONLINE":
            continue
        host = svc.get("host") or (svc.get("hosts") or ["-"])[0]
        if host_filter and host != host_filter:
            continue
        rows.append((host, name, status, svc))

    if not rows:
        print("no services matched")
        return

    name_w = min(max(len(r[1]) for r in rows), 34)
    ep_w = min(max(len(_endpoint(r[3])) for r in rows), 46)
    header = (f"{'STATUS':<8} {'NODE':<8} {'NAME':<{name_w}} {'TYPE':<10} "
              f"{'ENDPOINT':<{ep_w}} {'MEM':>10}")
    print(header)
    print("-" * len(header))

    for host, name, status, svc in sorted(rows, key=lambda r: (r[0], r[1].lower())):
        mark = "up" if status == "ONLINE" else "down"
        print(f"{mark:<8} {host[:8]:<8} {name[:name_w]:<{name_w}} "
              f"{str(svc.get('type', '-'))[:10]:<10} "
              f"{_endpoint(svc)[:ep_w]:<{ep_w}} {_mem(svc):>10}")

    up = sum(1 for r in rows if r[2] == "ONLINE")
    print(f"\n{up} up / {len(rows) - up} down")
    if hidden:
        print(f"({hidden} entries with no heartbeat in 30d hidden — pass --all)")


def list_nodes(show_all=False):
    """Capacity and addressing per node — the 'where can this actually run' view."""
    nodes = _fetch("/api/nodes")

    rows = []
    for name, node in sorted(nodes.items()):
        if not isinstance(node, dict):
            continue
        status = str(node.get("status", "?")).upper()
        if not show_all and status != "ONLINE" and not node.get("last_seen"):
            continue
        rows.append((name, node, status))

    header = (f"{'NODE':<20} {'ST':<6} {'RAM':<16} {'DISK':<20} "
              f"{'LAN IP':<18} {'TAILSCALE':<16} {'VPN IP':<16}")
    print(header)
    print("-" * len(header))

    for name, node, status in rows:
        mem_total = node.get("mem_total_gb")
        mem_pct = node.get("mem_percent")
        ram = f"{mem_total:.1f}G {mem_pct:.0f}%" if mem_total and mem_pct is not None else "-"

        disk_total = node.get("disk_total_gb")
        disk_free = node.get("disk_free_gb")
        disk_pct = node.get("disk_percent")
        if disk_total and disk_pct is not None:
            free = f"{disk_free:.0f}G free" if disk_free is not None else ""
            disk = f"{disk_total:.0f}G {disk_pct:.0f}% {free}".strip()
        else:
            disk = "-"

        # These arrive from agents as free text and sometimes carry a
        # trailing "- hostname" comment; keep just the address.
        def addr(value):
            if not value:
                return "-"
            return str(value).split("-")[0].strip() or "-"

        print(f"{name[:20]:<20} {('up' if status == 'ONLINE' else 'down'):<6} "
              f"{ram:<16} {disk:<20} {addr(node.get('ip')):<18} "
              f"{addr(node.get('tailscale_ip')):<16} {addr(node.get('openvpn_ip')):<16}")


def show_service(name):
    """Everything the registry knows about one service, nothing elided."""
    services = _fetch("/services")
    match = services.get(name)
    if match is None:
        hits = [k for k in services if name.lower() in k.lower()]
        if len(hits) == 1:
            name, match = hits[0], services[hits[0]]
        elif hits:
            print(f"'{name}' is ambiguous:", file=sys.stderr)
            for h in sorted(hits)[:20]:
                print(f"  {h}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"error: no service matching '{name}'", file=sys.stderr)
            sys.exit(1)

    print(f"{name}\n" + "=" * len(name))
    fields = [
        ("status", match.get("status")),
        ("type", match.get("type")),
        ("category", match.get("category")),
        ("host", match.get("host")),
        ("hosts", ", ".join(match.get("hosts") or []) or None),
        ("url", match.get("url")),
        ("internal", match.get("internal")),
        ("port", match.get("port")),
        ("openvpn", match.get("openvpn")),
        ("tags", ", ".join(match.get("tags") or []) or None),
        ("depends_on", ", ".join(match.get("depends_on") or []) or None),
        ("prereqs", ", ".join(match.get("prereqs") or []) or None),
        ("registered_at", match.get("registered_at")),
        ("last_heartbeat", match.get("last_heartbeat")),
        ("offline_since", match.get("offline_since")),
    ]
    for key, value in fields:
        if value not in (None, "", []):
            print(f"  {key:<16} {value}")

    md = match.get("metadata") or {}
    if isinstance(md, dict) and md:
        print("  metadata")
        for key in sorted(md):
            print(f"    {key:<14} {md[key]}")


# Several nodes are registered in the Locator under a different name than the
# one they joined the tailnet with, so a naive name match reports them as
# absent from the tailnet when they're actually up.
TAILNET_ALIASES = {
    "unit6": "claude-sandbox",
    "zebra tc22": "swoops-tc22",
}


def _tailscale_nodes():
    """Ground truth for node reachability, keyed by hostname.

    Locator only knows what agents told it, so a node that dies without
    deregistering looks identical to one whose agent crashed. Tailscale sees
    the link itself, which is what makes the two views worth diffing.
    Returns {} if tailscale isn't installed here — the column is then omitted.
    """
    try:
        out = subprocess.run(
            ["tailscale", "status", "--json"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    if out.returncode != 0:
        return {}
    try:
        data = json.loads(out.stdout)
    except ValueError:
        return {}

    nodes = {}
    for peer in list(data.get("Peer", {}).values()) + [data.get("Self", {})]:
        host = peer.get("HostName")
        if host:
            nodes[host.lower()] = {
                "online": bool(peer.get("Online")),
                "last_seen": peer.get("LastSeen"),
            }
    return nodes


def _parse_since(text):
    m = re.fullmatch(r"(\d+)([hmd])", text.strip().lower())
    if not m:
        raise argparse.ArgumentTypeError("expected a duration like 30m, 6h or 2d")
    n, unit = int(m.group(1)), m.group(2)
    return n * {"m": 60, "h": 3600, "d": 86400}[unit]


def _flaps(since_seconds):
    """Count offline/re-register cycles per node from the locator container log.

    Only works where the container actually runs; elsewhere the section is
    skipped rather than faked, since there's no remote log endpoint yet.
    """
    try:
        out = subprocess.run(
            ["docker", "logs", "locator", "--since", f"{since_seconds}s", "-t"],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None

    offline = collections.Counter()
    last_at = {}
    for line in (out.stdout + out.stderr).splitlines():
        m = re.search(r"^(\S+)\s+.*NODE OFFLINE:\s*(.+?)\s*$", line)
        if m:
            node = m.group(2)
            offline[node] += 1
            last_at[node] = m.group(1)
    return offline, last_at


def _age(iso_text):
    if not iso_text:
        return "never"
    try:
        stamp = dt.datetime.fromisoformat(iso_text.replace("Z", "+00:00"))
    except ValueError:
        return "?"
    secs = int((dt.datetime.now(dt.timezone.utc) - stamp).total_seconds())
    if secs < 0:
        secs = 0
    if secs < 90:
        return f"{secs}s ago"
    if secs < 5400:
        return f"{secs // 60}m ago"
    if secs < 172800:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


def health(since_seconds, show_all, stale_after):
    resp = requests.get(f"{LOCATOR_URL}/services", timeout=30)
    resp.raise_for_status()
    services = resp.json()

    hosts = collections.defaultdict(lambda: {"up": 0, "down": 0, "heartbeat": None})
    for svc in services.values():
        for host in (svc.get("hosts") or ([svc["host"]] if svc.get("host") else [])):
            entry = hosts[host]
            if str(svc.get("status", "")).upper() == "ONLINE":
                entry["up"] += 1
            else:
                entry["down"] += 1
            beat = svc.get("last_heartbeat")
            if beat and (entry["heartbeat"] is None or beat > entry["heartbeat"]):
                entry["heartbeat"] = beat

    ts = _tailscale_nodes()
    now = dt.datetime.now(dt.timezone.utc)

    rows, hidden = [], 0
    for host, entry in sorted(hosts.items()):
        fresh = False
        beat = entry["heartbeat"]
        if beat:
            try:
                stamp = dt.datetime.fromisoformat(beat.replace("Z", "+00:00"))
                fresh = (now - stamp).total_seconds() <= stale_after
            except ValueError:
                pass
        # A node nobody has heard from in a month is decommissioned, not down.
        if not show_all and not fresh and entry["up"] == 0:
            try:
                stamp = dt.datetime.fromisoformat((beat or "").replace("Z", "+00:00"))
                if (now - stamp).total_seconds() > 30 * 86400:
                    hidden += 1
                    continue
            except ValueError:
                hidden += 1
                continue
        key = host.lower()
        rows.append((host, entry, fresh, ts.get(TAILNET_ALIASES.get(key, key))))

    ts_col = bool(ts)
    header = f"{'NODE':<14} {'LOCATOR':<9} "
    if ts_col:
        header += f"{'TAILSCALE':<10} "
    header += f"{'SERVICES':<16} LAST HEARTBEAT"
    print(header)
    print("-" * len(header))

    disagree = []
    for host, entry, fresh, peer in rows:
        loc = "live" if fresh else "offline"
        line = f"{host:<14} {loc:<9} "
        if ts_col:
            if peer is None:
                reach = "-"
            else:
                reach = "online" if peer["online"] else "offline"
            line += f"{reach:<10} "
            if peer is not None and peer["online"] != fresh:
                disagree.append((host, fresh, peer["online"]))
        line += f"{entry['up']} up / {entry['down']} down".ljust(16)
        line += " " + _age(entry["heartbeat"])
        print(line)

    if hidden:
        print(f"\n({hidden} node(s) with no heartbeat in 30d hidden — pass --all to show)")

    if disagree:
        print("\nDisagreements (locator vs link layer):")
        for host, fresh, online in disagree:
            if online and not fresh:
                print(f"  {host}: reachable on tailscale but its agent stopped reporting "
                      f"— agent problem, not a dead node")
            else:
                print(f"  {host}: agent still reporting but tailscale calls it offline "
                      f"— stale heartbeat or split path")

    flaps = _flaps(since_seconds)
    if flaps is None:
        print("\n(flap history unavailable — run this on the host where the "
              "locator container lives)")
        return
    offline, last_at = flaps
    if not offline:
        print(f"\nNo nodes went offline in the window.")
        return
    print(f"\nWent offline in window:")
    for node, count in offline.most_common():
        note = "  <- flapping" if count > 1 else ""
        print(f"  {node:<14} {count}x   last {last_at.get(node, '?')}{note}")


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
    "health":  "Per-node health: locator's view vs tailscale, plus recent flaps",
    "status":  "Show the current status of one service",
    "start":   "Queue a container start on its host (runs via Lokey)",
    "stop":    "Queue a container stop on its host (runs via Lokey)",
    "migrate": "Migrate a service to another node (container or native, auto-detected)",
    "dns":     "Check or trigger a sync of the PowerDNS zones ns1 serves",
}

EPILOG = """\
Environment:
  LOCATOR_URL  Registry URL (default: https://locator.theofficialblacksheepco.online)

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
    ls_p = reg_sub.add_parser("ls", help="List registered services with node, endpoint and memory")
    ls_p.add_argument("--host", dest="host_filter", metavar="UNIT",
                      help="only services registered on this node")
    ls_p.add_argument("--online", action="store_true", help="hide anything not currently up")
    ls_p.add_argument("--all", action="store_true", dest="show_all",
                      help="include entries with no heartbeat in the last 30 days")

    nodes_p = reg_sub.add_parser("nodes", help="Per-node RAM, disk and addressing (LAN/tailscale/VPN)")
    nodes_p.add_argument("--all", action="store_true", dest="show_all",
                         help="include nodes that never reported")

    show_p = reg_sub.add_parser("show", help="Everything the registry knows about one service")
    show_p.add_argument("name", help="service name (substring match is allowed)")

    # Legacy spelling of `registry ls`, kept working but hidden from help.
    sub.add_parser("list")

    hp = sub.add_parser("health", help=COMMANDS["health"], description=COMMANDS["health"])
    hp.add_argument("--since", type=_parse_since, default=6 * 3600,
                    help="how far back to look for flaps (e.g. 30m, 6h, 2d; default 6h)")
    hp.add_argument("--all", action="store_true", dest="show_all",
                    help="include nodes with no heartbeat in the last 30 days")
    hp.add_argument("--stale-after", type=int, default=180, metavar="SECONDS",
                    help="heartbeat age at which a node counts as offline (default 180)")

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
            list_services(args.host_filter, args.online, args.show_all)
        elif args.registry_command == "nodes":
            list_nodes(args.show_all)
        elif args.registry_command == "show":
            show_service(args.name)
    elif args.command == "list":
        list_services()
    elif args.command == "health":
        health(args.since, args.show_all, args.stale_after)
    elif args.command == "migrate":
        migrate(args.name, args.to_node, args.force)
    elif args.command == "dns":
        if args.dns_command == "status":
            dns_status()
        elif args.dns_command == "sync":
            dns_sync(args.zone)


if __name__ == "__main__":
    main()
