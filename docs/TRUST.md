# Trust

This covers who can do what in a network, and how safe its shared state is.

## Permissions

An invite sets the new member's permissions:

| Permission | Allows | Leave out with |
| --- | --- | --- |
| admin | invite and remove members, change settings, approve and reject | `invite --no-admin` |
| vote | vote on changes, and hold the shared state | `invite --no-vote` |
| relay | pass control messages for members behind NAT | `invite --no-relay` |

Every member can use the whole network, and can leave. Permissions never
change. To change them, remove the member and invite it again.

A typical home network gives:
- your workstation all three;
- your public servers `vote` and `relay`;
- a friend's machine none.

## Approvals

By default, any one admin can make a change alone. To make joins, removals
and setting changes wait for other admins, set `approvals_required`:

```sh
sudo cheesecloth config set approvals_required 1
```

Admins then see changes with `pending`, and use `approve` or `reject` with
the full proposal token. Check who is joining before you approve. An admin
can't approve its own change. Leaving never needs approval.

## Voters

Voters agree on every change, such as a join or a new setting. Give `vote`
only to machines you trust to hold the network's state.

| Voters | Votes needed | Mode |
| --- | --- | --- |
| 1 | 1 | relaxed |
| 2 | 2 | relaxed |
| 3 | 2 | relaxed |
| 4 | 3 | protected |
| 5 | 4 | protected |
| 6 | 4 | protected |
| 7 | 5 | protected |

- **Relaxed** mode is safe if every voter is honest. One bad voter can break
  it.
- **Protected** mode is meant to stay safe with one bad voter, but not two. It
  needs at least four voters.

Cheesecloth picks the voters and the mode as machines come and go. If too
many voters go offline at once, changes stop until they return. The network
keeps working with the members it last knew.

Two settings change this:
- `strict_security`: once protected, never fall back to relaxed mode. Set it
  with `init --strict-security` or `config set strict_security true`.
- `buffer_nodes`: how many voters may be offline while changes still work,
  from 0 to 3. A higher buffer needs more voters to reach protected mode.

`status` shows the mode, the votes needed, and which voters it can reach.

## Limits

- Protected mode stops a bad voter. It does not stop a bad admin from doing
  what admins may do.
- If voters in relaxed mode agree on two different histories, protected mode
  can't repair that later.
- With no admin left, nobody can invite, remove or change settings. With no
  voter left, nothing can change at all. The network still works for the
  members it has.
- This design has tests, but no outside audit and no formal proof.

See [consensus safety](CONSENSUS-SAFETY.md) for how the protocol works.
