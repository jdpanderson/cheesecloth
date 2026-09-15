#!/bin/bash

set -e

declare -A started_containers

cleanup() {
    if [ ${#started_containers[@]} -gt 0 ]; then
        echo "Stopping all remaining containers: ${started_containers[@]}"
        docker container rm -f ${started_containers[@]}
    fi
    echo "Removing shared networks"
    docker network rm cheesecloth_test cheesecloth_test6
}

docker build -t cheesecloth-test "$(dirname "$0")"

# The underlay must not overlap the default overlay net (10.0.0.0/8), so pick the subnet explicitly.
docker network create --subnet 172.30.0.0/24 cheesecloth_test
docker network create --ipv6 --subnet fd00:57::/64 cheesecloth_test6
trap cleanup EXIT

# network the next containers join; tests switch it for the IPv6 cases
network=cheesecloth_test

run_test_container() {
    local name=$1
    echo "Starting $name"
    shift
    local hostname=$1
    shift
    docker run -d --cap-add=NET_ADMIN --cap-add=NET_RAW --device /dev/net/tun --security-opt label=disable --name ${name} --hostname ${hostname} -v $(pwd):/app --network=${network} cheesecloth-test "$@"
    started_containers[$name]=$name
}

stop_test_container() {
    echo "Stopping $1"
    docker container rm -f $1
    unset started_containers[$1]
}

# invite <container> <uses> [cheesecloth flags...]: mint an enrolment token on a running
# member, retrying while its agent is still starting. Prints the token.
invite() {
    local container=$1 uses=$2
    shift 2
    local token
    for _ in $(seq 1 30); do
        if token=$(docker exec "$container" /app/cheesecloth invite --ttl 5m --uses "$uses" "$@" 2>/dev/null) && [ -n "$token" ]; then
            echo "$token"
            return 0
        fi
        sleep 0.5
    done
    echo "could not mint a token on $container" >&2
    docker logs "$container" >&2
    return 1
}

# wait_gone <container> <pidfile>: block until the process named in pidfile has
# exited, so a restart never races the old one's port still being bound. A
# leaving node can spend up to 10s on its graceful Leave before it releases
# anything, so a fixed sleep is not enough.
wait_gone() {
    local container=$1 pidfile=$2
    for _ in $(seq 1 60); do
        docker exec "$container" bash -c "kill -0 \$(cat $pidfile) 2>/dev/null" || return 0
        sleep 0.5
    done
    echo "process in $pidfile on $container did not exit" >&2
    dump_logs "$container"
    return 1
}

ping_ok() { # ping_ok <from-container> <to-host> [containers whose logs to dump on failure...]
    local from=$1 to=$2
    shift 2
    docker exec "$from" ping -c1 -W1 "$to" || { for c in "$from" "$@"; do dump_logs "$c"; done; false; }
}

# wait_ping <from-container> <to-host> [containers whose logs to dump on failure...]:
# ping until it answers. The mesh is up when a node can be reached over it, so
# this is how a test waits for one: it costs what convergence actually takes
# rather than a guess, and a slow machine is slow rather than broken.
wait_ping() {
    local from=$1 to=$2
    shift 2
    for _ in $(seq 1 60); do
        docker exec "$from" ping -c1 -W1 "$to" >/dev/null 2>&1 && return 0
        sleep 0.5
    done
    echo "no ping from $from to $to" >&2
    ping_ok "$from" "$to" "$@"
}

# wait_hosts_gone <container> <name> [containers whose logs to dump on failure...]:
# block until the container's hosts file no longer names the node, which is how
# a revocation or a leave shows up on a peer that was not talked to.
wait_hosts_gone() {
    local container=$1 name=$2
    shift 2
    for _ in $(seq 1 60); do
        docker exec "$container" grep -q "$name" /etc/hosts || return 0
        sleep 0.5
    done
    echo "$container still has a hosts entry for $name" >&2
    for c in "$container" "$@"; do dump_logs "$c"; done
    return 1
}

# wait_hosts <container> <name> [containers whose logs to dump on failure...]:
# block until the container's hosts file names the node, which is how a node
# another member admitted shows up on a peer that only heard the record. Pinging
# the name would not wait for it: docker resolves the container's hostname over
# the underlay whether or not the mesh has the node.
wait_hosts() {
    local container=$1 name=$2
    shift 2
    for _ in $(seq 1 60); do
        docker exec "$container" grep -q "$name" /etc/hosts && return 0
        sleep 0.5
    done
    echo "$container has no hosts entry for $name" >&2
    for c in "$container" "$@"; do dump_logs "$c"; done
    return 1
}

# wait_unreachable <container> <overlay address> [containers whose logs to dump
# on failure...]: block until the address stops answering over the mesh, which
# is what a node that has been revoked sees: the members drop it as a wireguard
# peer and its packets go nowhere. The overlay address is used rather than the
# name, since docker resolves the name over the underlay either way.
wait_unreachable() {
    local container=$1 addr=$2
    shift 2
    for _ in $(seq 1 60); do
        docker exec "$container" ping -c1 -W1 "$addr" >/dev/null 2>&1 || return 0
        sleep 0.5
    done
    echo "$container can still reach $addr over the mesh" >&2
    for c in "$container" "$@"; do dump_logs "$c"; done
    return 1
}

# dump_logs <container>: the container's output, then that of any agent started with 'docker exec'
dump_logs() {
    docker logs "$1"
    docker exec "$1" sh -c 'cat /var/log/cheesecloth-*.log 2>/dev/null' || true
}

# A node roots a new cluster when it is given an overlay network and has no
# state to go with it, so the node that starts a cluster in these tests is the
# one passed --overlay-net; a node given neither that nor --join only waits.
test_3_node_up() {
    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8
    token=$(invite test1-orig 2)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"
    run_test_container test3-orig test3 --join test1-orig --join-key "$token"

    wait_ping test1-orig test2 test2-orig
    wait_ping test1-orig test3 test3-orig
    # addresses are allocated from the bottom of the overlay net: the root takes .1
    docker exec test1-orig ip -4 addr show wgcloth | grep -q "inet 10.0.0.1/32" || { docker exec test1-orig ip addr; false; }
    docker exec test2-orig ip -4 addr show wgcloth | grep -qE "inet 10.0.0.[23]/32" || { docker exec test2-orig ip addr; false; }
    # the token is spent: a fourth node cannot use it
    run_test_container test4-orig test4 --join test1-orig --join-key "$token"
    if [ "$(docker wait test4-orig)" = 0 ]; then echo "spent token was accepted"; docker logs test4-orig; false; fi
    docker logs test4-orig 2>&1 | grep -q "join key" || { docker logs test4-orig; false; }

    stop_test_container test4-orig
    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

test_5_node_up() {
    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8
    token=$(invite test1-orig 4)
    for n in 2 3 4 5; do
        run_test_container test$n-orig test$n --join test1-orig --join-key "$token"
    done

    for n in 2 3 4 5; do wait_ping test1-orig test$n test$n-orig; done

    for n in 5 4 3 2 1; do stop_test_container test$n-orig; done
}

# a restarted node rejoins from its persisted identity; the stale --join-key on
# its command line is ignored
test_node_restart() {
    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"

    wait_ping test1-orig test2 test2-orig

    docker stop test2-orig
    docker start test2-orig

    wait_ping test1-orig test2 test2-orig
    docker logs test2-orig 2>&1 | grep -q "ignoring --join-key" || { docker logs test2-orig; false; }

    stop_test_container test2-orig
    stop_test_container test1-orig
}

# a node given neither an overlay network nor a join has nothing to act on: it
# waits instead of failing, holds nothing while it does, and roots a cluster
# once it is started with a network
test_idle_until_configured() {
    run_test_container test1-orig test1 # nothing to act on

    sleep 3

    [ "$(docker inspect -f '{{.State.Running}}' test1-orig)" = "true" ] || {
        echo "the agent did not wait to be configured"; dump_logs test1-orig; false
    }
    if docker exec test1-orig ip link show wgcloth >/dev/null 2>&1; then
        echo "the waiting agent brought up an interface"; dump_logs test1-orig; false
    fi
    # the identity is generated on the first start, so the node keeps the one it
    # waited with when it is finally configured
    docker exec test1-orig test -f /var/lib/cheesecloth/wgcloth.json || {
        echo "the waiting agent kept no identity"; dump_logs test1-orig; false
    }

    # the waiting agent holds nothing, so one started beside it with a network
    # roots a cluster that a second node can join
    docker exec -d test1-orig bash -c "/entrypoint.sh --overlay-net 10.0.0.0/8 >> /var/log/cheesecloth-root.log 2>&1"
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"

    wait_ping test1-orig test2 test2-orig

    stop_test_container test2-orig
    stop_test_container test1-orig
}

# a joiner is told which network the cluster allocates addresses in, so it
# needs no --overlay-net of its own, at enrolment or on any later start
test_overlay_net_from_cluster() {
    run_test_container test1-orig test1 --overlay-net 10.77.0.0/16
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token" # no --overlay-net

    wait_ping test1-orig 10.77.0.2 test2-orig
    wait_ping test2-orig 10.77.0.1 test1-orig

    # the network came with the welcome and is kept, so a restart needs it no more
    docker stop test2-orig
    docker start test2-orig

    wait_ping test1-orig 10.77.0.2 test2-orig
    docker exec test2-orig /app/cheesecloth status | grep -q 10.77.0.2 || {
        echo "the node did not keep the cluster's overlay network"; dump_logs test2-orig; false
    }

    stop_test_container test2-orig
    stop_test_container test1-orig
}

# nodes of one mesh may listen on different gossip ports: a peer is remembered
# with the port it was reached at, so a restart finds it without being told
test_mixed_cluster_ports() {
    idle='--interface wgidle --cluster-port 7948 --wireguard-port 51822 --overlay-net 10.13.0.0/16'
    # the mesh agent is started by hand so it can be restarted without --join;
    # the container itself runs an unrelated one-node cluster to stay alive
    mesh_agent() { # mesh_agent <extra flags...>
        docker exec -d test2-orig bash -c "echo \$\$ > /run/mesh.pid; exec /entrypoint.sh --cluster-port 7947 $* >> /var/log/cheesecloth-mesh.log 2>&1"
    }

    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8 # the defaults: wgcloth, cluster port 7946
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 $idle
    mesh_agent --join test1-orig:7946 --join-key "$token" # test1 is not on test2's port

    # the overlay addresses, not the names: the container runtime resolves those
    # over the underlay whether the mesh is up or not
    wait_ping test1-orig 10.0.0.2 test2-orig
    wait_ping test2-orig 10.0.0.1 test1-orig

    # the mesh agent restarts with nothing but its state: it must reach test1 on
    # 7946, the port it remembered, and not on its own 7947
    docker exec test2-orig bash -c 'kill $(cat /run/mesh.pid)'
    wait_gone test2-orig /run/mesh.pid
    mesh_agent

    wait_ping test1-orig 10.0.0.2 test2-orig
    wait_ping test2-orig 10.0.0.1 test1-orig
    docker exec test1-orig /app/cheesecloth status | grep -q test2 || {
        echo "the node on another port did not rejoin from its state"; dump_logs test2-orig; false
    }

    stop_test_container test2-orig
    stop_test_container test1-orig
}

# joiners started at the same time with a shared multi-use token
test_cluster_simultaneous_start() {
    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8
    token=$(invite test1-orig 2)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token" &
    run_test_container test3-orig test3 --join test1-orig --join-key "$token" &
    wait
    started_containers[test2-orig]=test2-orig
    started_containers[test3-orig]=test3-orig

    wait_ping test1-orig test2 test2-orig
    wait_ping test1-orig test3 test3-orig
    wait_ping test2-orig test3 test3-orig

    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

test_multiple_clusters_restart() {
    cluster1='--cluster-port 7946 --wireguard-port 51820 --interface wg1 --overlay-net 10.10.0.0/16'
    cluster2='--cluster-port 7947 --wireguard-port 51821 --interface wg2 --overlay-net 10.11.0.0/16'

    run_test_container test1-orig test1 $cluster1
    run_test_container test2-orig test2 $cluster2
    token1=$(invite test1-orig 1 --interface wg1)
    token2=$(invite test2-orig 1 --interface wg2)
    run_test_container test3-orig test3 --join test1-orig --join-key "$token1" $cluster1
    docker exec -d test3-orig bash -c "/entrypoint.sh --join test2-orig --join-key $token2 $cluster2 >> /var/log/cheesecloth-wg2.log 2>&1"

    wait_ping test3-orig test1 test1-orig
    wait_ping test3-orig test2 test2-orig

    docker stop test3-orig
    docker start test3-orig
    docker exec -d test3-orig bash -c "/entrypoint.sh $cluster2 >> /var/log/cheesecloth-wg2.log 2>&1" # rejoins from state, no token

    wait_ping test3-orig test1 test1-orig
    wait_ping test3-orig test2 test2-orig
    wait_ping test1-orig test3 test3-orig
    wait_ping test2-orig test3 test3-orig

    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

# wireguard runs inside the agent when asked (and wherever the kernel has none)
test_userspace_device() {
    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8 --userspace
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token" --userspace

    wait_ping test1-orig test2 test2-orig
    wait_ping test2-orig test1 test1-orig
    docker logs test1-orig 2>&1 | grep -q "device=userspace" || { echo "the device did not run in userspace"; docker logs test1-orig; false; }
    docker exec test1-orig /app/cheesecloth status | grep -q test2 || { docker exec test1-orig /app/cheesecloth status; false; }

    stop_test_container test2-orig
    stop_test_container test1-orig
}

# IPv6 underlay (gossip, enrolment and wireguard endpoints over fd00:57::/64) and IPv6 overlay
test_ipv6_cluster() {
    network=cheesecloth_test6
    local v6='--bind-addr :: --overlay-net fd00:10::/64'
    run_test_container test1-orig test1 $v6
    token=$(invite test1-orig 2)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token" $v6
    run_test_container test3-orig test3 --join test1-orig --join-key "$token" $v6
    network=cheesecloth_test

    wait_ping test1-orig test2 test2-orig
    wait_ping test3-orig test1 test1-orig
    docker exec test1-orig /app/cheesecloth status | grep -q '^address: *fd00:10:' || (docker exec test1-orig /app/cheesecloth status; false)

    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

# IPv6 overlay over the IPv4 underlay
test_ipv6_overlay() {
    run_test_container test1-orig test1 --overlay-net fd00:10::/64
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token" --overlay-net fd00:10::/64

    wait_ping test1-orig test2 test2-orig
    wait_ping test2-orig test1 test1-orig

    stop_test_container test2-orig
    stop_test_container test1-orig
}

test_node_leave() {
    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"

    wait_ping test1-orig test2 test2-orig

    docker stop test2-orig # SIGTERM: clean leave

    wait_hosts_gone test1-orig test2 test1-orig

    stop_test_container test2-orig
    stop_test_container test1-orig
}

# a revoked node is dropped by its peers and can no longer talk to them
test_revoke() {
    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8
    token=$(invite test1-orig 2)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"
    run_test_container test3-orig test3 --join test1-orig --join-key "$token"

    wait_ping test1-orig test3 test3-orig
    docker exec test1-orig /app/cheesecloth revoke test3

    wait_hosts_gone test1-orig test3 test1-orig
    docker exec test1-orig /app/cheesecloth status | grep -q test3 && { echo "revoked node still a wireguard peer"; false; }
    # the revocation also reached test2, which never talked to the operator
    wait_hosts_gone test2-orig test3 test2-orig
    wait_ping test1-orig test2 test2-orig

    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

# a member is revoked along with a node it admitted. --disown names that node,
# the agent marks the revoked node's sequence below the record that admitted it,
# and both go: on the node that signed the revocation and on a member that was
# only told. What the mark withdrew is dropped on the way to the state file and
# no peer puts it back, and the cluster carries on admitting nodes.
test_revoke_disown() {
    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"
    wait_ping test1-orig test2 test2-orig

    # test3 is admitted by test2 rather than by the root, so revoking test2
    # below that record is what takes it out. The revocation is decided from
    # what test1 holds, so it has to have the record before it signs.
    token=$(invite test2-orig 1)
    run_test_container test3-orig test3 --join test2-orig --join-key "$token"
    wait_hosts test1-orig test3 test3-orig test2-orig

    # test4 is admitted by the root, so it stays when test2 goes, and it holds
    # the records test2 signed
    token=$(invite test1-orig 1)
    run_test_container test4-orig test4 --join test1-orig --join-key "$token"
    wait_hosts test1-orig test4 test4-orig
    wait_hosts test4-orig test3 test3-orig

    out=$(docker exec test1-orig /app/cheesecloth revoke test2 --disown test3 2>&1) || {
        echo "revoke --disown failed: $out"; dump_logs test1-orig; false
    }
    echo "$out"
    echo "$out" | grep -q "withdrawn with it" || { echo "revoke --disown did not say what it withdrew"; false; }
    echo "$out" | grep -q "test3" || { echo "revoke --disown did not name test3"; false; }

    # both nodes go, on the node that signed the record and on the one told
    for c in test1-orig test4-orig; do
        wait_hosts_gone "$c" test2 "$c"
        wait_hosts_gone "$c" test3 "$c"
        docker exec "$c" /app/cheesecloth status | grep -qE "test2|test3" && {
            echo "$c still has a revoked node as a wireguard peer"; docker exec "$c" /app/cheesecloth status; false
        }
    done
    # and the disowned node is cut off: the members have dropped it as a peer,
    # so nothing it sends over the mesh is answered. It is not told, and goes on
    # believing it is a member until somebody looks; see docs/operations.md.
    wait_unreachable test3-orig 10.0.0.1 test1-orig test3-orig

    # the record that admitted test3 was withdrawn, so every node that holds
    # the revocation drops it, and the peers that still gossip do not put it back
    for c in test1-orig test4-orig; do
        docker exec "$c" grep -q '"name": "test3"' /var/lib/cheesecloth/wgcloth.json && {
            echo "$c still holds the record that admitted the disowned node"
            docker exec "$c" cat /var/lib/cheesecloth/wgcloth.json; false
        }
    done

    # the cluster still admits nodes, and the joiner is given the smaller set
    token=$(invite test1-orig 1)
    run_test_container test5-orig test5 --join test1-orig --join-key "$token"
    wait_hosts test1-orig test5 test5-orig
    # the hosts entry comes first, so the name resolves over the mesh rather
    # than over the underlay docker resolves it on
    wait_hosts test5-orig test1 test5-orig test1-orig
    wait_ping test5-orig test1 test1-orig test5-orig
    docker exec test5-orig /app/cheesecloth status | grep -qE "test2|test3" && {
        echo "a new node was given records that no longer stand"; false
    }

    stop_test_container test5-orig
    stop_test_container test4-orig
    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

# a node takes itself out of the cluster: it revokes itself, the peers drop it,
# and it keeps nothing of the cluster it left
test_leave_command() {
    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8
    token=$(invite test1-orig 2)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"
    run_test_container test3-orig test3 --join test1-orig --join-key "$token"

    wait_ping test1-orig test3 test3-orig
    docker exec test3-orig /app/cheesecloth leave 2>&1 | grep -q "left the cluster: revoked" || {
        echo "leave did not report a revocation"; dump_logs test3-orig; false
    }

    # the agent stops once it has left, and with it the container
    for _ in $(seq 1 20); do
        [ "$(docker inspect -f '{{.State.Running}}' test3-orig)" = "false" ] && break
        sleep 0.5
    done
    [ "$(docker inspect -f '{{.State.Running}}' test3-orig)" = "false" ] || {
        echo "the agent kept running after it left"; dump_logs test3-orig; false
    }
    docker cp test3-orig:/var/lib/cheesecloth/wgcloth.json - >/dev/null 2>&1 && {
        echo "the state file survived the leave"; false
    }

    # test2 was handed the revocation too, though the operator never talked to it
    wait_hosts_gone test2-orig test3 test2-orig
    for c in test1-orig test2-orig; do
        if docker exec "$c" grep -q test3 /etc/hosts; then
            echo "$c still has a hosts entry for the node that left"; dump_logs "$c"; false
        fi
        docker exec "$c" /app/cheesecloth status | grep -q test3 && {
            echo "$c still has the node that left as a wireguard peer"; false
        }
    done
    ping_ok test1-orig test2 test2-orig

    stop_test_container test3-orig
    stop_test_container test2-orig
    stop_test_container test1-orig
}

# a network advertised with --allowed-ips is routed through the advertising node
test_allowed_ips() {
    run_test_container test1-orig test1 --overlay-net 10.0.0.0/8 --allowed-ips 192.168.77.0/24
    token=$(invite test1-orig 1)
    run_test_container test2-orig test2 --join test1-orig --join-key "$token"

    wait_ping test2-orig test1 test1-orig
    docker exec test2-orig ip route show dev wgcloth | grep -q "^192.168.77.0/24" || { docker exec test2-orig ip route; docker logs test2-orig; false; }
    docker exec test2-orig wg show wgcloth allowed-ips | grep -q "192.168.77.0/24" || { docker exec test2-orig wg show wgcloth; false; }
    docker exec test2-orig /app/cheesecloth status | grep test1 | grep -q "192.168.77.0/24" || { docker exec test2-orig /app/cheesecloth status; false; }
    # a host "behind" test1 answers through the mesh
    docker exec test1-orig ip addr add 192.168.77.1/32 dev lo
    ping_ok test2-orig 192.168.77.1 test1-orig

    stop_test_container test2-orig
    stop_test_container test1-orig
}

# run the named tests, or all of them
tests=("$@")
if [ ${#tests[@]} -eq 0 ]; then
    tests=($(declare -F | grep -Eo '\<test_.*$'))
fi
for test_func in "${tests[@]}"; do
    echo "--- Running $test_func:"
    $test_func
    echo "--- OK"
done
