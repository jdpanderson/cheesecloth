package cluster

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/enrol"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testNode is a node with its own transport, for exercising the transport alone.
type testNode struct {
	id   *trust.Identity
	tr   *quicTransport
	addr string
}

func newTestNode(t *testing.T, id *trust.Identity, set *trust.Set) *testNode {
	t.Helper()
	tr, err := newQUICTransport(netip.MustParseAddr("127.0.0.1"), 0, id, set, nil)
	require.NoError(t, err)
	tr.start()
	t.Cleanup(func() { _ = tr.Shutdown() })
	return &testNode{id: id, tr: tr, addr: tr.udp.LocalAddr().String()}
}

// twoMembers builds root a and member b, each with its own copy of the records.
func twoMembers(t *testing.T) (a, b *testNode) {
	t.Helper()
	rootID, bID := testIdentity(t), testIdentity(t)
	recs := trust.Records{Admissions: []trust.Admission{
		trust.SelfAdmit(rootID, "a", time.Now()),
		trust.Admit(rootID, bID.Public(), "b", 2, 2, time.Now()),
	}}
	setA, setB := trust.NewSet(rootID.Public()), trust.NewSet(rootID.Public())
	setA.Merge(recs)
	setB.Merge(recs)
	return newTestNode(t, rootID, setA), newTestNode(t, bID, setB)
}

// sendUntilConnected sends "ping" until a connection exists to carry it; the
// first sends are dropped while the transport connects, as UDP would drop them.
func sendUntilConnected(t *testing.T, from *testNode, to string) {
	t.Helper()
	require.Eventually(t, func() bool {
		if from.tr.lookup(to) != nil {
			return true
		}
		_, _ = from.tr.WriteTo([]byte("ping"), to) // dropped, and starts the connection
		return false
	}, 5*time.Second, 20*time.Millisecond, "never connected to %s", to)
	_, err := from.tr.WriteTo([]byte("ping"), to)
	require.NoError(t, err)
}

// waitForgotten waits for n to drop its connection to addr.
func waitForgotten(t *testing.T, n *testNode, addr string) {
	t.Helper()
	assert.Eventually(t, func() bool { return n.tr.lookup(addr) == nil }, 3*time.Second, 20*time.Millisecond, "connection to %s still present", addr)
}

// streamDies checks that a stream the peer will not accept fails on first use.
func streamDies(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write([]byte("intrude"))
	_, err := conn.Read(make([]byte, 1))
	assert.Error(t, err, "peer must have closed the connection")
	_ = conn.Close()
}

func expectPacket(t *testing.T, n *testNode, want string) {
	t.Helper()
	select {
	case p := <-n.tr.PacketCh():
		assert.Equal(t, want, string(p.Buf))
	case <-time.After(3 * time.Second):
		t.Fatalf("packet %q not delivered", want)
	}
}

func Test_quicTransport_packetsAndStreams(t *testing.T) {
	a, b := twoMembers(t)

	// the first packet to an unknown address is dropped and starts a connection; packets flow once it is up
	assert.Nil(t, a.tr.lookup(b.addr))
	sendUntilConnected(t, a, b.addr)
	expectPacket(t, b, "ping")

	// the accepting side reuses the same connection in the other direction
	_, err := b.tr.WriteTo([]byte("pong"), a.addr)
	require.NoError(t, err)
	expectPacket(t, a, "pong")

	// oversized packets are refused rather than truncated
	_, err = a.tr.WriteTo(make([]byte, 65000), b.addr)
	assert.Error(t, err)

	// a stream a -> b on the same connection
	conn, err := a.tr.DialTimeout(b.addr, 2*time.Second)
	require.NoError(t, err)
	assert.Equal(t, b.addr, conn.RemoteAddr().String())
	assert.Equal(t, a.addr, conn.LocalAddr().String())
	go func() { _, _ = conn.Write([]byte("hello")); _ = conn.Close() }()
	select {
	case s := <-b.tr.StreamCh():
		buf := make([]byte, 5)
		_, err = io.ReadFull(s, buf)
		require.NoError(t, err)
		assert.Equal(t, "hello", string(buf))
		assert.Equal(t, a.addr, s.RemoteAddr().String())
		_ = s.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("stream not delivered")
	}

	// a peer that shuts down takes its connection with it; dialling it anew fails
	_ = b.tr.Shutdown()
	waitForgotten(t, a, b.addr)
	_, err = a.tr.DialTimeout(b.addr, time.Second)
	assert.Error(t, err)
	_, err = a.tr.WriteTo([]byte("lost"), b.addr)
	assert.NoError(t, err, "packets to a dead peer are dropped, not failed")
	_, err = a.tr.DialTimeout("127.0.0.1:1", time.Second)
	assert.ErrorContains(t, err, "gossip to 127.0.0.1:1")
	_, err = a.tr.DialTimeout("not an address", time.Second)
	assert.Error(t, err)
}

// A connection dropped from the table is closed, so the peer drops it too.
// Before, it lingered until the QUIC transport destroyed it silently at
// shutdown, and the peer only noticed at the idle timeout.
func Test_quicTransport_forgetClosesConnection(t *testing.T) {
	a, b := twoMembers(t)
	sendUntilConnected(t, a, b.addr)
	expectPacket(t, b, "ping")
	conn := a.tr.lookup(b.addr)
	require.NotNil(t, conn)
	require.NotNil(t, b.tr.lookup(a.addr))

	a.tr.forget(b.addr, conn)
	assert.Nil(t, a.tr.lookup(b.addr))
	assert.Error(t, conn.Context().Err(), "the dropped connection is closed")
	assert.Eventually(t, func() bool { return b.tr.lookup(a.addr) == nil }, time.Second, 10*time.Millisecond, "b was not told")
}

// Shutdown must tell peers even about a connection whose pump is stuck on a
// packet nobody has read, which is the shape that first exposed the silent
// destroy: the pump woke on done and dropped the connection before Shutdown
// reached it.
func Test_quicTransport_shutdownTellsPeers(t *testing.T) {
	a, b := twoMembers(t)
	sendUntilConnected(t, a, b.addr)
	expectPacket(t, b, "ping")
	for i := 0; i < 3; i++ { // unread: b's pump for this connection blocks on the packet channel
		_, err := a.tr.WriteTo([]byte("unread"), b.addr)
		require.NoError(t, err)
	}

	require.NoError(t, b.tr.Shutdown())
	assert.Eventually(t, func() bool { return a.tr.lookup(b.addr) == nil }, time.Second, 10*time.Millisecond,
		"a was not told that b closed")
}

func Test_quicTransport_advertiseAddr(t *testing.T) {
	a, _ := twoMembers(t)
	ip, port, err := a.tr.FinalAdvertiseAddr("", 0)
	require.NoError(t, err)
	assert.Equal(t, a.addr, hostPortOf(ip.String(), port))
	ip, port, err = a.tr.FinalAdvertiseAddr("192.0.2.1", 7946)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.1:7946", hostPortOf(ip.String(), port))
	_, port, err = a.tr.FinalAdvertiseAddr("192.0.2.1", 0)
	require.NoError(t, err)
	assert.NotZero(t, port, "the bound port fills in")
	_, _, err = a.tr.FinalAdvertiseAddr("nonsense", 0)
	assert.Error(t, err)

	wild, err := newQUICTransport(netip.IPv4Unspecified(), 0, a.id, a.tr.set, nil)
	require.NoError(t, err)
	wild.start()
	defer func() { _ = wild.Shutdown() }()
	_, _, err = wild.FinalAdvertiseAddr("", 0)
	assert.ErrorContains(t, err, "advertise address is required")
}

func hostPortOf(ip string, port int) string {
	return netip.AddrPortFrom(netip.MustParseAddr(ip), uint16(port)).String()
}

func Test_quicTransport_rejectsStrangers(t *testing.T) {
	rootID := testIdentity(t)
	set := trust.NewSet(rootID.Public())
	set.Merge(trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(rootID, "a", time.Now())}})
	member := newTestNode(t, rootID, set)

	// stranger trusts a different root (itself) and "admits" the member in its own world
	strangerID := testIdentity(t)
	strangerSet := trust.NewSet(strangerID.Public())
	strangerSet.Merge(trust.Records{Admissions: []trust.Admission{
		trust.SelfAdmit(strangerID, "s", time.Now()),
		trust.Admit(strangerID, rootID.Public(), "a", 2, 2, time.Now()),
	}})
	stranger := newTestNode(t, strangerID, strangerSet)

	// TLS 1.3 rejects a client certificate after the client's handshake has
	// completed, so the dial itself may succeed; the stream must then be dead
	// and the member must never surface it.
	if conn, err := stranger.tr.DialTimeout(member.addr, 2*time.Second); err == nil {
		streamDies(t, conn)
	}
	select {
	case s := <-member.tr.StreamCh():
		t.Fatalf("member must not surface a stream from a non-member (%s)", s.RemoteAddr())
	case p := <-member.tr.PacketCh():
		t.Fatalf("member must not surface a packet from a non-member (%q)", p.Buf)
	case <-time.After(300 * time.Millisecond):
	}
	assert.Nil(t, member.tr.lookup(stranger.addr))

	// and a member refuses to talk to a stranger posing as a server
	_, err := member.tr.DialTimeout(stranger.addr, 2*time.Second)
	assert.ErrorContains(t, err, "not a member")
}

func Test_quicTransport_revocationCutsConnection(t *testing.T) {
	a, b := twoMembers(t)
	sendUntilConnected(t, a, b.addr)
	expectPacket(t, b, "ping")

	// a revokes b; b's next packet closes the connection instead of being delivered
	_, err := a.tr.set.AddRevocation(trust.Revoke(a.id, b.id.Public(), a.tr.set.NextSeq(a.id.Public()), a.tr.set.Head(b.id.Public()), time.Now()))
	require.NoError(t, err)
	_, err = b.tr.WriteTo([]byte("still here?"), a.addr)
	require.NoError(t, err)
	select {
	case p := <-a.tr.PacketCh():
		t.Fatalf("packet from a revoked node delivered: %q", p.Buf)
	case <-time.After(300 * time.Millisecond):
	}
	waitForgotten(t, a, b.addr)
	if conn, err := b.tr.DialTimeout(a.addr, 2*time.Second); err == nil {
		streamDies(t, conn)
	}
	assert.Nil(t, a.tr.lookup(b.addr), "and b cannot come back")
}

func Test_quicTransport_oneConnectionPerPair(t *testing.T) {
	a, b := twoMembers(t)

	// both sides dial each other at once, several times over
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = a.tr.DialTimeout(b.addr, 2*time.Second) }()
		go func() { defer wg.Done(); _, _ = b.tr.DialTimeout(a.addr, 2*time.Second) }()
	}
	wg.Wait()

	preferred := preferredDialer(a.id.Public(), b.id.Public())
	recorded := func() (ca, cb peerConn) {
		a.tr.mu.Lock()
		ca = a.tr.conns[b.addr]
		a.tr.mu.Unlock()
		b.tr.mu.Lock()
		cb = b.tr.conns[a.addr]
		b.tr.mu.Unlock()
		return ca, cb
	}
	live := func(c peerConn) bool { return c.conn != nil && c.conn.Context().Err() == nil }
	// the losing connections close asynchronously; both sides end up on the one dialled by the smaller identity
	require.Eventually(t, func() bool {
		ca, cb := recorded()
		return live(ca) && live(cb) && ca.client == preferred && cb.client == preferred
	}, 3*time.Second, 20*time.Millisecond, "both sides settle on the connection dialled by the smaller identity")

	// the survivor carries traffic both ways
	_, err := a.tr.WriteTo([]byte("ping"), b.addr)
	require.NoError(t, err)
	expectPacket(t, b, "ping")
	_, err = b.tr.WriteTo([]byte("pong"), a.addr)
	require.NoError(t, err)
	expectPacket(t, a, "pong")
}

// Both sides must settle on the same connection whatever order the dials land in.
func Test_keepNew(t *testing.T) {
	a, b := testIdentity(t).Public(), testIdentity(t).Public()
	if bytes.Compare(b[:], a[:]) < 0 {
		a, b = b, a
	}
	assert.Equal(t, a, preferredDialer(a, b))
	assert.Equal(t, a, preferredDialer(b, a), "the same on both sides")

	assert.False(t, keepNew(a, b, a), "the preferred side's connection is not replaced by the other's")
	assert.True(t, keepNew(b, a, a), "the preferred side's connection replaces the other's")
	assert.True(t, keepNew(a, a, a), "a reconnect from the same side replaces the old connection")
	assert.True(t, keepNew(b, b, a))
}

func Test_quicTransport_enrolmentCap(t *testing.T) {
	rootID := testIdentity(t)
	set := trust.NewSet(rootID.Public())
	set.Merge(trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(rootID, "a", time.Now())}})
	started := make(chan net.Conn, maxEnrolments+2)
	release := make(chan struct{})
	tr, err := newQUICTransport(netip.MustParseAddr("127.0.0.1"), 0, rootID, set, func(c enrol.Conn) {
		started <- c
		<-release
		_ = c.Close()
	})
	require.NoError(t, err)
	tr.start()
	defer func() { _ = tr.Shutdown() }()
	addr := tr.udp.LocalAddr().String()

	// fill every slot with an exchange that never finishes
	joiner := testIdentity(t)
	opened := 0
	for i := 0; i < maxEnrolments; i++ {
		conn, stream := openEnrol(t, addr, joiner)
		defer func() { _ = stream.Close(); _ = conn.CloseWithError(0, "") }()
		opened++
	}
	for i := 0; i < maxEnrolments; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d of %d enrolments reached the handler", i, maxEnrolments)
		}
	}

	// one more is refused at once rather than queued
	conn, stream := openEnrol(t, addr, joiner)
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = stream.Read(make([]byte, 1))
	assert.Error(t, err, "the surplus connection is closed")
	_ = conn.CloseWithError(0, "")
	select {
	case <-started:
		t.Fatal("surplus enrolment reached the handler")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
}

// A transport with no enrolment handler turns enrolment connections away.
func Test_quicTransport_enrolmentNotOffered(t *testing.T) {
	a, _ := twoMembers(t) // nil handler
	conn, stream := openEnrol(t, a.addr, testIdentity(t))
	defer func() { _ = conn.CloseWithError(0, "") }()
	_ = stream.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := stream.Read(make([]byte, 1))
	require.Error(t, err, "the connection is closed")
	var appErr *quic.ApplicationError
	require.ErrorAs(t, err, &appErr)
	assert.Equal(t, "enrolment not offered", appErr.ErrorMessage)
}

// An enrolment connection that never opens its stream is closed after enrolWait.
func Test_quicTransport_enrolmentStreamTimeout(t *testing.T) {
	rootID := testIdentity(t)
	set := trust.NewSet(rootID.Public())
	set.Merge(trust.Records{Admissions: []trust.Admission{trust.SelfAdmit(rootID, "a", time.Now())}})
	handled := make(chan struct{}, 1)
	tr, err := newQUICTransport(netip.MustParseAddr("127.0.0.1"), 0, rootID, set, func(c enrol.Conn) { handled <- struct{}{}; _ = c.Close() })
	require.NoError(t, err)
	tr.enrolWait = 200 * time.Millisecond
	tr.start()
	defer func() { _ = tr.Shutdown() }()

	conn := dialEnrol(t, tr.udp.LocalAddr().String(), testIdentity(t))
	select {
	case <-conn.Context().Done():
	case <-time.After(3 * time.Second):
		t.Fatal("idle enrolment connection was not closed")
	}
	assert.Empty(t, handled, "the handler never ran")
	select {
	case <-tr.enrolSem:
		t.Fatal("the enrolment slot was not released")
	default:
	}
}

// dialEnrol dials addr for enrolment as id, without opening a stream.
func dialEnrol(t *testing.T, addr string, id *trust.Identity) *quic.Conn {
	t.Helper()
	cert, err := identityCertificate(id)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr, enrolClientTLSConfig(cert), &quic.Config{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	return conn
}

// openEnrol dials addr for enrolment as id and opens the stream, without running the exchange.
func openEnrol(t *testing.T, addr string, id *trust.Identity) (*quic.Conn, *quic.Stream) {
	t.Helper()
	conn := dialEnrol(t, addr, id)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	require.NoError(t, err)
	_, err = stream.Write([]byte{0}) // announces the stream to the peer
	require.NoError(t, err)
	return conn, stream
}

func Test_certIdentity(t *testing.T) {
	_, err := certIdentity(nil)
	assert.ErrorContains(t, err, "no certificate")
	_, err = certIdentity([][]byte{[]byte("not a certificate")})
	assert.Error(t, err)

	// a well-formed certificate whose key is of another kind
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
	require.NoError(t, err)
	_, err = certIdentity([][]byte{der})
	assert.ErrorContains(t, err, "not an Ed25519 identity")

	id := testIdentity(t)
	cert, err := identityCertificate(id)
	require.NoError(t, err)
	got, err := certIdentity(cert.Certificate)
	require.NoError(t, err)
	assert.Equal(t, id.Public(), got)
}

// After Shutdown, packets are dropped as UDP would and streams are refused;
// memberlist treats the first as a lost probe and the second as its own error.
func Test_quicTransport_afterShutdown(t *testing.T) {
	a, b := twoMembers(t)
	require.NoError(t, a.tr.Shutdown())
	_, err := a.tr.WriteTo([]byte("x"), b.addr)
	assert.NoError(t, err)
	_, err = a.tr.DialTimeout(b.addr, time.Second)
	assert.ErrorContains(t, err, "shut down")
	assert.NoError(t, a.tr.Shutdown(), "idempotent")
}

// A revoked peer's stream on a connection that is still up closes the connection.
func Test_quicTransport_revocationCutsStreams(t *testing.T) {
	a, b := twoMembers(t)
	sendUntilConnected(t, a, b.addr)
	expectPacket(t, b, "ping")
	require.NotNil(t, b.tr.lookup(a.addr), "b reuses the connection a dialled")

	_, err := a.tr.set.AddRevocation(trust.Revoke(a.id, b.id.Public(), a.tr.set.NextSeq(a.id.Public()), a.tr.set.Head(b.id.Public()), time.Now()))
	require.NoError(t, err)
	conn, err := b.tr.DialTimeout(a.addr, 2*time.Second)
	require.NoError(t, err, "the stream opens locally; a has not seen it yet")
	streamDies(t, conn)
	select {
	case s := <-a.tr.StreamCh():
		t.Fatalf("stream from a revoked node surfaced (%s)", s.RemoteAddr())
	case <-time.After(300 * time.Millisecond):
	}
	waitForgotten(t, a, b.addr)
}

// A stream memberlist dialled carries the dial's deadline, so a peer that
// accepts the stream and never reads it cannot hold the write open. Nothing
// takes from b's StreamCh here, so the stream is never read and the write runs
// out of flow-control window.
func Test_quicTransport_dialledStreamHasDeadline(t *testing.T) {
	a, b := twoMembers(t)
	sendUntilConnected(t, a, b.addr)
	expectPacket(t, b, "ping")

	conn, err := a.tr.DialTimeout(b.addr, 500*time.Millisecond)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	done := make(chan error, 1)
	go func() { _, werr := conn.Write(make([]byte, 8<<20)); done <- werr }()
	select {
	case werr := <-done:
		assert.ErrorIs(t, werr, os.ErrDeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("write to an unread stream never returned")
	}
}
