# Quick start on Linux

This builds Cheesecloth, makes a network on one machine, and adds a second
machine to it.

## What you need

- Rust 1.95 or later.
- Clocks that are in sync on every machine.
- `systemd-resolved` running, or another `resolvconf`. Cheesecloth uses it to
  clean up DNS settings.
- Root, to run the daemon. These examples use `sudo` for everything.

## Steps

1. Build and install, from the repository root:

   ```sh
   cargo build --release --locked
   sudo install -m 755 target/release/cheesecloth /usr/local/bin/cheesecloth
   ```

2. Start the daemon on each machine, and leave it running:

   ```sh
   sudo cheesecloth daemon
   ```

3. On the first machine, in another terminal, make the network and an
   invite:

   ```sh
   sudo cheesecloth init
   sudo cheesecloth invite
   ```

4. On the second machine, join with the token that `invite` printed, then
   check the result:

   ```sh
   sudo cheesecloth join '<token>'
   sudo cheesecloth status
   sudo cheesecloth peers
   ```

An invite works once, for 30 minutes. Make a new one for each machine.

A new member can do everything: manage the network, vote and relay. For a
machine that should only use the network, such as a friend's, use
`cheesecloth invite --no-admin --no-vote --no-relay`. See
[permissions](SECURITY.md#permissions).

## Ports and files

- UDP **51821**: control messages.
- UDP **51820**: WireGuard traffic.
- `/var/lib/cheesecloth`: state.

Open both ports on machines that others should reach directly. Cheesecloth
owns its WireGuard interface, `cheesecloth0`, and removes any peers you add to
it by hand.

## Network options

These are the usual daemon options. `cheesecloth daemon --help` lists all of
them.

| Option | Use |
| --- | --- |
| `--advertise IP` | Tell others an address they can reach, such as a cloud VM's public IP. Repeatable. |
| `--relay MODE` | `auto` (default) relays when reachable from the internet; `always` or `never`. |
| `--no-port-mapping` | Do not open ports on the router with UPnP or PCP. |
| `--wireguard MODE` | `auto` (default), `kernel` or `userspace`. |
| `--keepalive SECONDS` | WireGuard keepalive. |

`status` shows if the machine is reachable from the internet, and its router
port mappings.

Behind NAT, machines need a relay to exchange control messages. WireGuard
traffic is never relayed: if hole punching and port mapping both fail, add a
reachable address or forward the port. NAT traversal works for IPv4 only.

## Running without root

The daemon needs root, or `CAP_NET_ADMIN` and `CAP_NET_RAW`. To use the CLI
without root, start the daemon with `--api-group <group>`. Members of that
group can then run every command except `stop`. See
[the local API](LOCAL-API.md#access).

## If the daemon will not start

If cleanup failed last time, the daemon waits for the old interface to go.
Remove it with `sudo ip link delete cheesecloth0`.

## More than one network

Each daemon serves one network. To run more than one daemon on a machine,
give each its own state directory, interface and ports. Pass the same
`--state-dir` or `--socket` to the CLI.
