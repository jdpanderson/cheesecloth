# <picture><source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg"><img src="assets/logo-light.svg" alt="" height="40"></picture> Cheesecloth

A loosely woven mesh, traditionally used to separate curds from whey.

## Purpose

Cheesecloth is a small-batch peer-to-peer mesh networking tool for homelab-scale networks, for tinkerers that want to knit devices together securely with little management effort.

Cheesecloth:
 - Makes it intentionally easy to create and manage its private network composed of public and private nodes.
 - Supports differing levels of security, all cut to fit personal or homelab-scale networks.
 - Lets you invite friends, with optional levels of trust.
 - Tries to map ports and punch holes through NAT firewalls, but this is probably limited to configurations similar to my own setup.

It is not:
 - An enterprise networking tool. [Nebula](https://github.com/slackhq/nebula), [Netbird](https://github.com/netbirdio/netbird), and [Tailscale](https://tailscale.com/) are better suited.
 - Efficient. It connects every node directly to every other node to keep inter-node traffic fast, which puts some strain on larger networks.
 - Mesh routed. It intentionally does not support sending traffic through router nodes. Only control traffic can be forwarded.
 - Firewalled or ACL'ed. That's outside this tool's scope. Use your operating system's firewall if you want.
 - A hacker. It won't punch through unmapped NAT or figure out weird network topology, though I'd consider adding support if the concept is straightforward (and legal) if pressed.

## What it is, More Formally

Cheesecloth builds a peer-to-peer WireGuard mesh without a central server.
Members agree on membership and settings through an authenticated, adaptive
CASPaxos protocol. Relays help control messages cross NAT; WireGuard traffic
always travels directly between peers.

**Pre-release, still maturing.** Linux has end-to-end coverage with kernel WireGuard. macOS
CI tests userspace WireGuard; multi-machine and NAT operation remain unvalidated.
FreeBSD is unvalidated. Windows CI builds and tests the daemon and CLI on x64
and arm64. The daemon runs as a Windows service; multi-machine operation
there remains unvalidated. Mobile is not
supported. See [Windows](docs/WINDOWS.md) for the service and what is weaker
there. The consensus security layer has regression tests, but no independent
audit or machine-checked Byzantine proof.

## Quick Start

Skim [the quick start](docs/QUICKSTART.md) to build Cheesecloth, start the
daemon, join a second machine on Linux, and set network options.

To skip the build, use a binary [release](https://github.com/jdpanderson/cheesecloth/releases)

There are also packages for MacOS, Linux, and Windows that have basic tray/notification area apps:
 - [cheesecloth-linux](https://github.com/jdpanderson/cheesecloth-linux) ([Releases](https://github.com/jdpanderson/cheesecloth-linux/releases))
 - [cheesecloth-macos](https://github.com/jdpanderson/cheesecloth-macos) ([Releases](https://github.com/jdpanderson/cheesecloth-macos/releases))
 - [cheesecloth-windows](https://github.com/jdpanderson/cheesecloth-windows) ([Releases](https://github.com/jdpanderson/cheesecloth-windows/releases))


## Command-Line Cheat Sheet

On a plain linux node:

```sh
# Create a new network, then invite another host
sudo cheesecloth init
sudo cheesecloth invite # emits a text token; it ages out after 30 minutes

# Join a network
sudo cheesecloth join <token> # Join a network

# Check on network status, and its peers
sudo cheesecloth status
sudo cheesecloth peers

# Manage nodes, remove a node or leave the network
sudo cheesecloth remove '<name-or-node-id-prefix>'
sudo cheesecloth leave

# Configure the network
sudo cheesecloth config get
sudo cheesecloth config set approvals_required 1

# When approvals are configured, approve actions proposed by another node
sudo cheesecloth pending
sudo cheesecloth approve '<proposal-token>'
sudo cheesecloth reject '<proposal-token>'
```

You can manage cheesecloth networks as root, or run the daemon as root and control it from a user account with correct permissions. Do what works for you. I won't judge.

## Permission & Security

Each member has three permissions, set by its invite: `admin` to invite,
remove and change settings, `vote` to take part in consensus, and `relay` to
pass control messages for others.

If you want to invite friends, consider not giving them admin rights. If your friend seems a little too sharp, consider not giving them vote or relay permission either.

You can firm up the network against node compromise with `approvals_required`, at the expense of ease of management. This will require approval from other nodes with admin rights before changes are adopted. Really though, if y'all get hacked, just whip up a new network.

See [docs/TRUST.md](docs/TRUST.md) for details.

## Development

See [development](docs/DEVELOPMENT.md) for building from source, the checks
before a pull request, and the platform tests. See [the design](docs/DESIGN.md)
for architecture, settings and recovery.
