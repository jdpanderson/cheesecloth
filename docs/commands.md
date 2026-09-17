# Commands

Every command, what it does, what it prints, and what it refuses. Every option
each one takes is in [configuration](configuration.md); this document is about
behaviour.

`cheesecloth` with no command is the agent. The rest talk to a running agent
over its control socket, except `status`, which reads the interface and the
state file, and `leave --force`, which works when no agent is running.

| Command | What it does |
|---|---|
| [`cheesecloth`](#cheesecloth) | run the agent |
| [`cheesecloth config`](#cheesecloth-config) | print the settings this node runs with, or write them to the config file |
| [`cheesecloth status`](#cheesecloth-status) | show the interface and its peers |
| [`cheesecloth invite`](#cheesecloth-invite) | mint an enrolment token for a new node |
| [`cheesecloth confirm`](#cheesecloth-confirm) | list records waiting for agreement, or agree with one |
| [`cheesecloth revoke`](#cheesecloth-revoke) | remove another node from the cluster |
| [`cheesecloth leave`](#cheesecloth-leave) | remove the node it runs on |
| [`cheesecloth service`](#cheesecloth-service) | register or remove the Windows service |

Commands that reach the agent find it by interface: `--interface` names which
one, and the socket is `/run/cheesecloth/<interface>.sock` unless
`--control-socket` says otherwise. A host running several clusters names the
config file instead, which carries the interface; see [running multiple
clusters](configuration.md#running-multiple-clusters).

## `cheesecloth`

Runs the agent. It settles its membership before configuring anything, from its
state file and what it was given:

- **Already a member** — resumes from the state file and rejoins its last known
  peers. Needs neither `--overlay-net` nor `--join-key`; a stale `--join-key`
  left on the command line is ignored. This is the usual case, and what a
  service manager starts on every boot.
- **Not a member, `--join-key` given** — enrols with one of the `--join`
  members, which tells it the cluster's overlay network.
- **Not a member, an overlay network configured** — starts a new cluster with
  itself as the only member. Configuring a network for a node that has no state
  is what founds a cluster; there is no separate flag for it.
- **Not a member, neither given** — waits. Nothing is configured and no
  interface is created, but the node's identity is generated and kept, so it is
  the same node when it is finally given something to act on. The control socket
  is opened and every command is refused with what would give the node a
  cluster, since an agent that is running should say so rather than look absent.

Waiting rather than exiting is what lets a node be installed and its service
enabled before anyone has decided what it joins, and keeps a service manager
from restarting an agent that is merely unconfigured.

Enrolling with `--join-key` blocks until the cluster agrees a membership holding
this node, since until one does, no peer would accept it. Where the cluster asks
for no confirmations that is one round of gossip, and the agent gives up after
30 seconds saying how many members had to attest. Where it asks for
confirmations it is waiting for a person, so there is no deadline: `--join`
blocks until somebody runs `cheesecloth confirm`, and Ctrl+C stops waiting. The
record stays either way, and the node joins the next time it is started after
the confirmation.

## `cheesecloth config`

Prints the settings this interface runs with, as a config file, so that what a
node runs with can be captured rather than reconstructed by hand. It prints the
effective settings — the command line, then the file, then what the cluster told
the node, then the defaults — leaving out anything that matches its default, so
the result is as short as what has to be maintained.

```
# cheesecloth config --interface wgmesh
interface: wgmesh
overlay-net: 10.42.0.0/24
```

That is the form to redirect somewhere as a whole:

```
# cheesecloth config > /etc/cheesecloth/config.yaml
```

`--init` writes the file instead of printing it, which is how a node is set up
before its agent first runs. A file that is already there is left alone rather
than written over — edit it, or print the settings and redirect them yourself,
or name another file with `--config`. Creating the file is the whole of the
write, so two of these racing need no lock: one creates it and the other is told
it is there.

## `cheesecloth status`

Shows the WireGuard interface and its peers, with the last handshake age,
traffic counters and advertised routes, naming peers from the persisted cluster
state. It does not use the control socket, so it reports even when the agent is
not running. It needs the same privileges as the agent.

```
# cheesecloth status
interface: wgcloth
address:   10.0.0.1/32
port:      51820
pubkey:    gm/3EV7bl46Z2QPUa5CppLUjwoL45BwHO1nrEgIFsFA=
identity:  KE9rn7ryXPCL+A1uHT1Or7tnBG/eheIihMPaYcN9EME=
peers:     2

NAME     IDENTITY  OVERLAY   ENDPOINT              HANDSHAKE  RX     TX     ROUTES
linode2  mFrk3G+0  10.0.0.2  178.79.147.187:51820  2s ago     348 B  404 B  -
linode3  kwvzJSL2  10.0.0.3  172.105.13.112:51820  1s ago     348 B  404 B  -
```

`--json` prints the same report as JSON.

## `cheesecloth invite`

Mints an enrolment token on the running agent and prints it. The token is a
256-bit random value kept only in the agent's memory, with its expiry and
remaining uses; nothing writes it to disk. Any member can create one.

```
# cheesecloth invite
7xk3...
valid for 10m0s, 1 use(s). On the new node:
  cheesecloth --join <this host> --join-key 7xk3...
```

The token alone goes to stdout, so a script can capture it; everything else is
on stderr. `--ttl` sets how long it stays valid (10 minutes by default) and
`--uses` how many nodes may enrol with it (one by default). A use that is
proved but cannot be admitted is given back to the token.

## `cheesecloth confirm`

Only matters where the cluster runs with `--confirmations` above zero. There, an
admission or a revocation is held and does nothing until that many members
besides its signer have agreed with it. With no argument the command lists what
is waiting:

```
# cheesecloth confirm
RECORD    WHAT        NODE   IDENTITY  SIGNED BY  CONFIRMED
9f3a1c2e  admission   web3   KE9rn7ry  mFrk3G+0   0 of 1
```

With a node name, an identity or a record id, it signs this node's agreement:

```
# cheesecloth confirm web3
confirmed the admission of web3 (KE9rn7ry); it had 0 of the 1 it needs, and now has 1
```

Read the identity before you do. The point of the second signature is that
somebody looked, and confirming without looking is the same as not asking for
confirmations at all.

A node that is already a member cannot be confirmed into the cluster twice: a
record that would change nothing is not waiting for anything and is not listed.

## `cheesecloth revoke`

Takes another node out of the cluster. The command signs the record; the node is
out once a quorum of the members has agreed a membership without it, which takes
a moment while they are reachable and does not happen at all while too few of
them are. Every peer then stops talking to the revoked node, which is not
notified.

```
# cheesecloth revoke linode2
revoked linode2 (mFrk3G+0...)
```

It takes a node name or an identity. **It cannot be undone**: the member it
takes out is out everywhere and has to enrol again.

**One record takes out one member.** The nodes a departing node admitted are
members in their own right and stay — removing several is several commands, and
there is no way to sweep them up, because a record that did would remove nodes
nobody asked to remove. What does go with the subject is a joiner it vouched for
that the cluster had not yet agreed on, since nothing else holds that joiner in.
The command says so before it returns:

```
# cheesecloth revoke linode2
revoked linode2 (mFrk3G+0...)
1 node(s) it admitted are withdrawn with it and have to enrol again:
  newnode (Dz4W1m8t...)
```

Two things are refused rather than reported afterwards, since a revocation
cannot be taken back once it is signed:

- A revocation that would take the node you are running on out with its subject,
  which happens when this node is a member only through the one being revoked.
  Run it from a node the subject did not admit.
- A revocation with no effect at all, which means this node is no longer one of
  the members the cluster has agreed on.

An identity that is already on its way out is refused too: revoking it again
would cost a record the cluster never gets back and change nothing.

Nothing is signed in any of those cases. Everything else is your judgement, and
the command says nothing about whether this node can see the cluster: the node
being revoked is usually the one that has gone, so a reachability check would
fire on almost every legitimate revocation and be learned as noise. Check with
`cheesecloth status` first.

The command returns once the revocation is signed and saved, which is the point
after which it cannot be lost — not once the cluster has agreed the membership
without its subject. Handing it to the members happens afterwards and is
best-effort; see [what happens after it
returns](operations.md#after-a-record-is-signed).

Where the cluster asks for confirmations, the revocation is held until enough
members have run `cheesecloth confirm` on it, and the subject stays a member
until then.

## `cheesecloth leave`

Takes the node it runs on out of the cluster for good. The agent revokes this
node's own identity, hands the revocation to each member it can still reach,
tears the interface down, removes its hosts entries and deletes its state file,
then stops.

```
# cheesecloth leave
left the cluster: revoked KE9rn7ryXPCL+A1uHT1Or7tnBG/eheIihMPaYcN9EME=, 2 member(s) told
the agent has stopped and its state for wgcloth is gone
```

Any node may leave this way, the node that founded the cluster included. It is a
peer like any other: taking it out leaves every node it admitted where it is,
since the cluster had agreed on them, and the mesh carries on without it and
still admits new nodes.

The agent exits, so a service that starts it at boot should be disabled as well.
Starting it again without a fresh invitation does nothing: the node is no longer
a member and has no state.

Two cases cannot tell the cluster anything and need `--force`: the agent is not
running, so nothing can sign or send a revocation, and the node is a member of
nothing, so there is nobody to tell. `--force` removes the interface, the hosts
entries and the state file only, whether the agent refused or never answered.
The command then prints the node's identity, because the cluster goes on
trusting it until a member revokes it:

```
# cheesecloth leave --force
removed this node's state for wgcloth
the cluster still trusts this node: run 'cheesecloth revoke KE9r...' on a member
```

Removing a node that cannot be reached at all is the same operation seen from
the other side: run `cheesecloth revoke` on any member.

`leave --force` is also how a node is made to start over — to found a new
cluster on a host that is already a member, or to recover one whose state file
cannot be read. The next start finds no state and roots a cluster or enrols as
its configuration says.

## `cheesecloth service`

Windows only. `cheesecloth service install` registers the agent with the Service
Control Manager so it starts at boot, taking its settings from the config file;
`cheesecloth service uninstall` removes it, and the service should be stopped
first. Both need an administrator's console. See
[Windows](operations.md#windows).

## Global options

`--config PATH` names the configuration file to read, `--log-level` sets
verbosity (`debug`, `info`, `warn` or `error`; `warn` by default) and
`--version` prints the version and exits. Every command accepts them.
