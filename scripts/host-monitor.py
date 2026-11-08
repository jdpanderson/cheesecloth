#!/usr/bin/env python3
"""Check now and then that cheesecloth peers stay reachable in the mesh.

Each check:
  1. Reads `cheesecloth status` and `cheesecloth peers`. This sends nothing on
     the network, so it shows the mesh as it was before the check.
  2. Probes each peer's overlay addresses with ping, and with a TCP connect
     if --tcp-port is given.
  3. Reads `cheesecloth peers` again, to show what the probe changed.

It writes one JSON object per line to stdout. It only reads and reports; it
never changes anything.

By default it waits a random time between 0 and 4 hours between checks, so
its own traffic does not keep the tunnels busy. Run it for days or weeks:

    ./host-monitor.py [peer ...] > monitor.log

A peer is a name or a node ID prefix. With no peers, it checks all of them.
It needs the same access as the cheesecloth CLI (root, or the API group).
"""

import argparse
import json
import random
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

DEFAULT_MAX_WAIT = 4 * 60 * 60
PING_COUNT = 3
PING_TIMEOUT = 2
TCP_TIMEOUT = 5
CLI_TIMEOUT = 30


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def emit(event, **fields):
    print(json.dumps({"time": now(), "event": event, **fields}), flush=True)


class CliError(Exception):
    pass


def cli(binary, *args):
    """Run the cheesecloth CLI with --json and return its answer."""
    cmd = [binary, "--json", *args]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CLI_TIMEOUT
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        raise CliError(f"{' '.join(cmd)}: {e}") from e
    try:
        doc = json.loads(out.stdout)
    except json.JSONDecodeError as e:
        raise CliError(
            f"{' '.join(cmd)}: no valid JSON (exit {out.returncode}): "
            f"{out.stderr.strip() or out.stdout.strip()}"
        ) from e
    if out.returncode != 0:
        error = doc.get("error", {}) if isinstance(doc, dict) else {}
        raise CliError(
            f"{' '.join(cmd)}: {error.get('code', 'unknown')}: "
            f"{error.get('message', '')}"
        )
    return doc


def ping(addr):
    """Ping addr. Return the number of replies out of PING_COUNT."""
    cmd = ["ping", "-n", "-q", "-c", str(PING_COUNT), "-W", str(PING_TIMEOUT), addr]
    try:
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=PING_COUNT * (PING_TIMEOUT + 1) + 5,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"replies": 0, "error": str(e)}
    match = re.search(r"(\d+) (?:packets )?received", out.stdout)
    replies = int(match.group(1)) if match else 0
    result = {"replies": replies}
    if out.returncode not in (0, 1):
        result["error"] = out.stderr.strip() or f"exit {out.returncode}"
    return result


def tcp(addr, port):
    """Connect to addr:port.

    A refused connection still proves the host is reachable, because the
    refusal came back through the tunnel.
    """
    try:
        with socket.create_connection((addr, port), timeout=TCP_TIMEOUT):
            return {"result": "open"}
    except ConnectionRefusedError:
        return {"result": "refused"}
    except socket.timeout:
        return {"result": "timeout"}
    except OSError as e:
        return {"result": "error", "error": str(e)}


def matches(peer, wanted):
    return peer["name"] == wanted or peer["node_id"].startswith(wanted)


def pick_targets(peers, wanted):
    """Return (targets, names that matched no peer)."""
    others = [p for p in peers if not p["this_node"]]
    if not wanted:
        return others, []
    targets = [p for p in others if any(matches(p, w) for w in wanted)]
    missing = [w for w in wanted if not any(matches(p, w) for p in others)]
    return targets, missing


def view(peer):
    """The fields of a peer that show how the daemon sees its path."""
    keys = (
        "connected",
        "present",
        "path",
        "path_state",
        "path_detail",
        "wg_endpoint",
        "handshake_age_secs",
    )
    return {k: peer.get(k) for k in keys}


def check_status(status):
    problems = []
    if status.get("phase") != "member":
        problems.append(f"phase is {status.get('phase')}")
    if status.get("changes_paused"):
        problems.append("changes paused")
    for mapping in status.get("port_mapping") or []:
        if mapping.get("error"):
            problems.append(f"port mapping {mapping['port']}: {mapping['error']}")
    problems.extend(f"warning: {w}" for w in status.get("warnings") or [])
    return problems


def probe_peer(peer, tcp_port):
    probes = {}
    for family in ("ipv4", "ipv6"):
        addr = peer.get(family)
        if not addr:
            continue
        probes[family] = {"addr": addr, "ping": ping(addr)}
        if tcp_port is not None:
            probes[family]["tcp"] = tcp(addr, tcp_port)
    return probes


def reachable(probe):
    if probe["ping"]["replies"] > 0:
        return True
    return probe.get("tcp", {}).get("result") in ("open", "refused")


def peer_problems(before, probes):
    problems = []
    if not before["present"]:
        problems.append("not present")
    if before["path_state"] != "up":
        problems.append(f"path state was {before['path_state']} before probe")
    if not probes:
        problems.append("no overlay address")
    for family, probe in probes.items():
        replies = probe["ping"]["replies"]
        if replies < PING_COUNT:
            problems.append(f"{family} ping {replies}/{PING_COUNT}")
        result = probe.get("tcp", {}).get("result")
        if result in ("timeout", "error"):
            problems.append(f"{family} tcp {result}")
    any_reachable = any(reachable(p) for p in probes.values())
    if before["path_state"] == "up" and probes and not any_reachable:
        problems.append("mismatch: daemon said up, but probe failed")
    if before["path_state"] != "up" and any_reachable:
        problems.append("mismatch: daemon said not up, but probe worked")
    return problems


def run_check(binary, wanted, tcp_port):
    try:
        status = cli(binary, "status")
        peers_before = cli(binary, "peers")
    except CliError as e:
        emit("error", message=str(e))
        return

    problems = check_status(status)
    emit(
        "status",
        ok=not problems,
        problems=problems,
        name=status.get("name"),
        phase=status.get("phase"),
        quorum=status.get("quorum"),
        reachable_voters=status.get("reachable_voters"),
        members=status.get("members"),
        public=status.get("public"),
        relay=status.get("relay"),
    )

    targets, missing = pick_targets(peers_before, wanted)
    for name in missing:
        emit("peer", ok=False, peer=name, problems=["no such peer"])

    results = [(p, probe_peer(p, tcp_port)) for p in targets]

    try:
        after = {p["node_id"]: p for p in cli(binary, "peers")}
    except CliError as e:
        emit("error", message=str(e))
        after = {}

    for peer, probes in results:
        before = view(peer)
        problems = peer_problems(before, probes)
        later = after.get(peer["node_id"])
        emit(
            "peer",
            ok=not problems,
            peer=peer["name"],
            node_id=peer["node_id"],
            problems=problems,
            before=before,
            probes=probes,
            after=view(later) if later else None,
        )


def positive_seconds(text):
    value = float(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be more than 0")
    return value


def port(text):
    value = int(text)
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError("must be 1 to 65535")
    return value


def main():
    parser = argparse.ArgumentParser(
        description="Check now and then that cheesecloth peers stay "
        "reachable in the mesh. Writes JSON lines to stdout."
    )
    parser.add_argument(
        "peers", nargs="*", help="peer names or node ID prefixes (default: all)"
    )
    parser.add_argument(
        "--interval",
        type=positive_seconds,
        help="seconds between checks (default: random, 0 to 4 hours)",
    )
    parser.add_argument(
        "--tcp-port", type=port, help="also try a TCP connect to this port"
    )
    parser.add_argument(
        "--once", action="store_true", help="check once, then stop"
    )
    parser.add_argument(
        "--cheesecloth",
        default="cheesecloth",
        metavar="PATH",
        help="the cheesecloth CLI (default: cheesecloth)",
    )
    args = parser.parse_args()

    emit(
        "start",
        peers=args.peers or "all",
        interval=args.interval or f"random 0-{DEFAULT_MAX_WAIT}",
        tcp_port=args.tcp_port,
    )
    try:
        while True:
            run_check(args.cheesecloth, args.peers, args.tcp_port)
            if args.once:
                break
            wait = args.interval or random.uniform(0, DEFAULT_MAX_WAIT)
            emit("wait", seconds=round(wait))
            time.sleep(wait)
    except KeyboardInterrupt:
        emit("stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
