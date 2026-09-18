package cluster

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
	"github.com/jdpanderson/cheesecloth/internal/enrol"
	"github.com/jdpanderson/cheesecloth/internal/tally"
	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/quic-go/quic-go"
)

// The gossip transport runs memberlist over QUIC: one UDP port, one TLS 1.3
// session per pair of nodes, authenticated on both sides by self-signed
// certificates carrying the nodes' identity keys and accepted only for valid
// members. memberlist packets travel as QUIC datagrams (RFC 9221), its
// push/pull exchanges as streams. There is no cluster-wide key. The same
// listener takes enrolment connections under their own ALPN: the joiner is
// not a member yet, so its certificate is only parsed there, and the token
// exchange on the stream decides.

const (
	alpnGossip    = "cheesecloth-gossip/1"
	alpnEnrol     = "cheesecloth-enrol/1"
	identityLen   = 32
	handshakeTime = 10 * time.Second // QUIC handshake, and the whole of an outbound dial
	// enrolStreamTime is how long an enrolment connection may sit without
	// opening its stream. A joiner opens it as soon as the handshake is done,
	// so this is a round trip's work; it is short because the slot the
	// connection holds is one of maxEnrolments, and anyone who can reach the
	// port can take one before proving anything.
	enrolStreamTime = 2 * time.Second
	// keepAlive stays under the 30-second UDP conntrack timeout some routers
	// use, so a node behind such a NAT keeps its mapping; idleTimeout is long
	// enough that a few lost keep-alives do not cost a connection.
	idleTimeout = 2 * time.Minute
	keepAlive   = 25 * time.Second
	// maxDatagram bounds memberlist's packets: QUIC guarantees room for at
	// least ~1200 bytes of datagram payload on any path.
	maxDatagram = 1100
	// maxEnrolments bounds concurrent enrolment exchanges; anyone who can reach
	// the port can open one, so the rest of the transport must not starve.
	maxEnrolments = 8
)

type quicTransport struct {
	id        *trust.Identity
	set       *trust.Set
	udp       *net.UDPConn
	qt        *quic.Transport
	ln        *quic.Listener
	server    *tls.Config
	client    *tls.Config
	qconf     *quic.Config
	packets   chan *memberlist.Packet
	streams   chan net.Conn
	enrol     func(context.Context, enrol.Conn) // runs one enrolment on a stream; nil refuses enrolment
	enrolSem  chan struct{}                     // one slot per enrolment in flight
	enrolWait time.Duration                     // how long an enrolment connection may sit without opening its stream
	refused   tally.Counter                     // enrolments turned away before the exchange; counted, not logged one each
	done      chan struct{}
	wg        sync.WaitGroup
	once      sync.Once
	err       error // from Shutdown

	mu      sync.Mutex
	conns   map[string]peerConn  // by the peer's gossip address
	dialing map[string]*dialCall // dials in flight, one per address
}

// peerConn is a live connection and the identity that dialled it.
type peerConn struct {
	conn   *quic.Conn
	client trust.PublicKey
}

// dialCall is a dial in flight; later callers for the same address wait for it
// rather than opening a second connection of their own.
type dialCall struct {
	done chan struct{}
	conn *quic.Conn
	err  error
}

var _ memberlist.NodeAwareTransport = (*quicTransport)(nil)

// newQUICTransport binds bind:port for QUIC; port 0 picks a free one, see
// port. Enrolment streams go to handler once start is called.
func newQUICTransport(bind netip.Addr, port int, id *trust.Identity, set *trust.Set, handler func(context.Context, enrol.Conn)) (*quicTransport, error) {
	cert, err := identityCertificate(id)
	if err != nil {
		return nil, err
	}
	verify := func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		peer, cerr := certIdentity(rawCerts)
		if cerr != nil {
			return cerr
		}
		if !set.Valid(peer) {
			return fmt.Errorf("peer %s is not a member", peer.Short())
		}
		return nil
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: bind.AsSlice(), Port: port})
	if err != nil {
		return nil, fmt.Errorf("binding gossip transport: %w", err)
	}
	var resetKey quic.StatelessResetKey
	if _, err = rand.Read(resetKey[:]); err != nil {
		_ = udp.Close()
		return nil, err
	}
	gossipServer := &tls.Config{
		Certificates:          []tls.Certificate{cert},
		ClientAuth:            tls.RequireAnyClientCert,
		VerifyPeerCertificate: verify,
		MinVersion:            tls.VersionTLS13,
		NextProtos:            []string{alpnGossip},
	}
	enrolServer := enrolTLSConfig(cert)
	t := &quicTransport{
		id: id, set: set, udp: udp,
		qt: &quic.Transport{Conn: udp, StatelessResetKey: &resetKey},
		server: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
			NextProtos:   []string{alpnGossip, alpnEnrol},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				for _, proto := range hello.SupportedProtos {
					if proto == alpnEnrol {
						return enrolServer, nil
					}
				}
				return gossipServer, nil
			},
		},
		client: &tls.Config{
			Certificates:          []tls.Certificate{cert},
			InsecureSkipVerify:    true, // identity is checked by VerifyPeerCertificate, not by CA chain
			VerifyPeerCertificate: verify,
			MinVersion:            tls.VersionTLS13,
			NextProtos:            []string{alpnGossip},
		},
		qconf: &quic.Config{
			EnableDatagrams: true, MaxIdleTimeout: idleTimeout, KeepAlivePeriod: keepAlive,
			HandshakeIdleTimeout: handshakeTime,
		},
		packets:   make(chan *memberlist.Packet),
		streams:   make(chan net.Conn),
		enrol:     handler,
		enrolSem:  make(chan struct{}, maxEnrolments),
		enrolWait: enrolStreamTime,
		done:      make(chan struct{}),
		conns:     map[string]peerConn{},
		dialing:   map[string]*dialCall{},
	}
	t.ln, err = t.qt.Listen(t.server, t.qconf)
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("listening for gossip: %w", err)
	}
	return t, nil
}

// port is the UDP port the transport is bound to.
func (t *quicTransport) port() int { return t.udp.LocalAddr().(*net.UDPAddr).Port }

// start begins accepting member and enrolment connections.
func (t *quicTransport) start() {
	t.wg.Add(1)
	go t.accept()
}

// enrolTLSConfig accepts any identity certificate: enrolment authenticates by
// the token exchange, with the message identities bound to the certificate.
// The server side additionally requires the joiner to present one.
func enrolTLSConfig(cert tls.Certificate) *tls.Config {
	conf := enrolClientTLSConfig(cert)
	conf.ClientAuth = tls.RequireAnyClientCert
	return conf
}

// enrolClientTLSConfig is the joiner's side of the same: present our identity
// certificate, parse the member's, and let the exchange decide.
func enrolClientTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // the peer is not known to be a member; the exchange decides
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			_, err := certIdentity(rawCerts)
			return err
		},
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{alpnEnrol},
	}
}

// identityCertificate is a self-signed certificate carrying the node's Ed25519 key.
func identityCertificate(id *trust.Identity) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: id.Public().Short()},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, id.Signer().Public(), id.Signer())
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("creating identity certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: id.Signer()}, nil
}

// certIdentity is the identity in a peer's leaf certificate.
func certIdentity(rawCerts [][]byte) (trust.PublicKey, error) {
	if len(rawCerts) == 0 {
		return trust.PublicKey{}, errors.New("peer presented no certificate")
	}
	c, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return trust.PublicKey{}, err
	}
	pub, ok := c.PublicKey.(ed25519.PublicKey)
	if !ok || len(pub) != identityLen {
		return trust.PublicKey{}, errors.New("peer certificate is not an Ed25519 identity")
	}
	var peer trust.PublicKey
	copy(peer[:], pub)
	return peer, nil
}

// connIdentity is the verified identity behind an established connection.
func connIdentity(conn *quic.Conn) (trust.PublicKey, error) {
	certs := conn.ConnectionState().TLS.PeerCertificates
	if len(certs) == 0 {
		return trust.PublicKey{}, errors.New("peer presented no certificate")
	}
	return certIdentity([][]byte{certs[0].Raw})
}

// accept adopts incoming member connections until the listener closes.
func (t *quicTransport) accept() {
	defer t.wg.Done()
	for {
		conn, err := t.ln.Accept(context.Background())
		if err != nil {
			return
		}
		t.adopt(conn, true)
	}
}

// adopt takes in a connection: an enrolment connection goes to the enrolment
// handler and yields nil; a gossip connection is registered for its peer and
// served, and the connection to use for that peer is returned, which is an
// existing one when both sides dialled each other at once (see register).
func (t *quicTransport) adopt(conn *quic.Conn, accepted bool) *quic.Conn {
	peer, err := connIdentity(conn)
	if err != nil {
		_ = conn.CloseWithError(1, err.Error())
		return nil
	}
	if conn.ConnectionState().TLS.NegotiatedProtocol == alpnEnrol {
		t.adoptEnrol(conn, peer)
		return nil
	}
	client := t.id.Public()
	if accepted {
		client = peer
	}
	kept := t.register(conn, peer, client)
	if kept != conn {
		return kept
	}
	t.serve(conn, peer)
	return conn
}

// adoptEnrol hands an enrolment connection to the handler if a slot is free.
func (t *quicTransport) adoptEnrol(conn *quic.Conn, peer trust.PublicKey) {
	if t.enrol == nil {
		_ = conn.CloseWithError(1, "enrolment not offered")
		return
	}
	select {
	case t.enrolSem <- struct{}{}:
	default:
		// counted rather than logged one line each: holding the slots is what
		// makes this fire, so a line per refusal would let whoever is holding
		// them set the rate of the log
		t.refused.Note("enrolments refused because too many were already in flight; a member reports these "+
			"at its own rate, since anyone who can reach the port can make them", "from", conn.RemoteAddr())
		_ = conn.CloseWithError(1, "busy")
		return
	}
	if !t.track(1) {
		<-t.enrolSem
		_ = conn.CloseWithError(0, "shutdown")
		return
	}
	go t.serveEnrol(conn, peer)
}

// track counts n goroutines about to start, unless the transport is shutting
// down, in which case it reports false and the caller starts none. Shutdown
// closes done under the same lock before it waits, so nothing is added to the
// wait group once the wait has begun.
func (t *quicTransport) track(n int) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.done:
		return false
	default:
		t.wg.Add(n)
		return true
	}
}

// register records conn, dialled by client, as the connection to its peer and
// returns the connection to use for that peer. When both sides dialled each
// other at once the connection dialled by the smaller identity wins, so both
// sides keep the same one and close the other.
func (t *quicTransport) register(conn *quic.Conn, peer, client trust.PublicKey) *quic.Conn {
	addr := conn.RemoteAddr().String()
	t.mu.Lock()
	defer t.mu.Unlock()
	if cur, ok := t.conns[addr]; ok && cur.conn.Context().Err() == nil {
		if !keepNew(cur.client, client, preferredDialer(t.id.Public(), peer)) {
			_ = conn.CloseWithError(0, "duplicate connection")
			return cur.conn
		}
		_ = cur.conn.CloseWithError(0, "superseded")
	}
	t.conns[addr] = peerConn{conn: conn, client: client}
	slog.Debug("gossip connection", "peer", peer.Short(), "addr", addr, "dialled by", client.Short())
	return conn
}

// preferredDialer is the side whose connection both keep when a and b dial
// each other at once: the smaller identity, so both sides pick the same one.
func preferredDialer(a, b trust.PublicKey) trust.PublicKey {
	if bytes.Compare(b[:], a[:]) < 0 {
		return b
	}
	return a
}

// keepNew decides between a live connection dialled by cur and a new one
// dialled by client: the new one is turned away only when the current one was
// dialled by the preferred side and it was not.
func keepNew(cur, client, preferred trust.PublicKey) bool {
	return cur != preferred || client == preferred
}

// serve pumps a gossip connection: its datagrams become packets and its
// streams are handed to memberlist, for as long as the peer stays a member.
func (t *quicTransport) serve(conn *quic.Conn, peer trust.PublicKey) {
	addr := conn.RemoteAddr().String()
	if !t.track(2) {
		t.forget(addr, conn)
		return
	}
	go func() {
		defer t.wg.Done()
		defer t.forget(addr, conn)
		for {
			b, err := conn.ReceiveDatagram(context.Background())
			if err != nil {
				return
			}
			if !t.set.Valid(peer) {
				_ = conn.CloseWithError(1, "not a member")
				return
			}
			select {
			case t.packets <- &memberlist.Packet{Buf: b, From: conn.RemoteAddr(), Timestamp: time.Now()}:
			case <-t.done:
				return
			}
		}
	}()
	go func() {
		defer t.wg.Done()
		for {
			s, err := conn.AcceptStream(context.Background())
			if err != nil {
				return
			}
			if !t.set.Valid(peer) {
				_ = conn.CloseWithError(1, "not a member")
				return
			}
			select {
			case t.streams <- newStreamConn(conn, s, peer):
			case <-t.done:
				_ = conn.CloseWithError(0, "shutdown")
				return
			}
		}
	}()
}

// serveEnrol runs the enrolment handler on the first stream of an enrolment
// connection and then closes the connection. The exchange ends with the
// joiner's acknowledgement, so by then nothing is left in flight to cut short.
func (t *quicTransport) serveEnrol(conn *quic.Conn, peer trust.PublicKey) {
	defer t.wg.Done()
	defer func() { <-t.enrolSem }()
	defer func() { _ = conn.CloseWithError(0, "done") }()
	ctx, cancel := context.WithTimeout(context.Background(), t.enrolWait)
	defer cancel()
	s, err := conn.AcceptStream(ctx)
	if err != nil {
		slog.Debug("enrolment connection opened no stream", "from", conn.RemoteAddr(), "err", err)
		return
	}
	// The exchange waits for the cluster to agree a membership holding the
	// joiner, which where the cluster asks for confirmations is a person and
	// has no deadline. That wait is this exchange's, so it ends with it: when
	// the joiner's connection dies, and when the transport stops. Without the
	// second, Shutdown's wait for this goroutine and the handler's wait for the
	// cluster would each be waiting on the other.
	exchange, stop := context.WithCancel(conn.Context())
	defer stop()
	go func() {
		select {
		case <-t.done:
			stop()
		case <-exchange.Done():
		}
	}()
	t.enrol(exchange, newStreamConn(conn, s, peer))
}

// forget drops conn from the table if it is still the one recorded for addr,
// and closes it: a connection that is not the one for its address is of no
// further use, and closing it now tells the peer, where leaving it for
// Shutdown to destroy would not. Closing an already closed connection returns
// at once.
func (t *quicTransport) forget(addr string, conn *quic.Conn) {
	t.mu.Lock()
	if t.conns[addr].conn == conn {
		delete(t.conns, addr)
	}
	t.mu.Unlock()
	_ = conn.CloseWithError(0, "connection dropped")
}

// lookup returns the live connection to addr, if any.
func (t *quicTransport) lookup(addr string) *quic.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	if c := t.conns[addr].conn; c != nil && c.Context().Err() == nil {
		return c
	}
	return nil
}

// connect returns the connection to addr, dialling if there is none. Dials
// to one address are serialised: with at most one of our own connections to a
// peer in flight, the tie-break in adopt cannot see two of them and both
// sides settle on the same connection.
func (t *quicTransport) connect(ctx context.Context, addr string) (*quic.Conn, error) {
	if c := t.lookup(addr); c != nil {
		return c, nil
	}
	t.mu.Lock()
	if call, ok := t.dialing[addr]; ok {
		t.mu.Unlock()
		select {
		case <-call.done:
			return call.conn, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &dialCall{done: make(chan struct{})}
	t.dialing[addr] = call
	t.mu.Unlock()

	call.conn, call.err = t.dial(ctx, addr)
	t.mu.Lock()
	delete(t.dialing, addr)
	t.mu.Unlock()
	close(call.done)
	return call.conn, call.err
}

// dial connects to a peer's gossip address and adopts the connection.
func (t *quicTransport) dial(ctx context.Context, addr string) (*quic.Conn, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := t.qt.Dial(ctx, ua, t.client, t.qconf) // offers alpnGossip alone; a peer that does not speak it fails the handshake
	if err != nil {
		return nil, fmt.Errorf("gossip to %s: %w", addr, err)
	}
	if kept := t.adopt(conn, false); kept != nil {
		return kept, nil
	}
	return nil, fmt.Errorf("gossip to %s: connection not usable", addr)
}

// dialAsync starts a connection attempt to addr unless one is under way or
// the transport is shutting down. Two callers racing past the check both
// start one; connect collapses them onto a single dial.
func (t *quicTransport) dialAsync(addr string) {
	t.mu.Lock()
	_, busy := t.dialing[addr]
	t.mu.Unlock()
	if busy || !t.track(1) {
		return
	}
	go func() {
		defer t.wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), handshakeTime)
		defer cancel()
		if _, err := t.connect(ctx, addr); err != nil {
			slog.Debug("could not connect for gossip", "addr", addr, "err", err)
		}
	}()
}

// FinalAdvertiseAddr implements memberlist.Transport.
func (t *quicTransport) FinalAdvertiseAddr(ip string, port int) (net.IP, int, error) {
	if ip == "" {
		local := t.udp.LocalAddr().(*net.UDPAddr)
		if local.IP.IsUnspecified() {
			return nil, 0, errors.New("an advertise address is required when binding a wildcard")
		}
		return local.IP, local.Port, nil
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, 0, fmt.Errorf("invalid advertise address %q", ip)
	}
	if port == 0 {
		port = t.port()
	}
	return parsed, port, nil
}

// WriteTo implements memberlist.Transport.
func (t *quicTransport) WriteTo(b []byte, addr string) (time.Time, error) {
	return t.WriteToAddress(b, memberlist.Address{Addr: addr})
}

// WriteToAddress implements memberlist.NodeAwareTransport: the packet goes as
// a datagram on the connection to the peer. Without a usable connection the
// packet is silently dropped, as UDP would, and a connection attempt starts:
// memberlist treats a lost probe as a sign of failure and an error as its own
// fault, so dropping is what makes failure detection work.
func (t *quicTransport) WriteToAddress(b []byte, a memberlist.Address) (time.Time, error) {
	select {
	case <-t.done:
		return time.Now(), nil
	default:
	}
	conn := t.lookup(a.Addr)
	if conn == nil {
		t.dialAsync(a.Addr)
		return time.Now(), nil
	}
	if err := conn.SendDatagram(b); err != nil {
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			return time.Time{}, fmt.Errorf("gossip packet of %d bytes exceeds %d", len(b), tooLarge.MaxDatagramPayloadSize)
		}
		t.forget(a.Addr, conn)
		slog.Debug("gossip connection lost", "addr", a.Addr, "err", err)
	}
	return time.Now(), nil
}

// PacketCh implements memberlist.Transport.
func (t *quicTransport) PacketCh() <-chan *memberlist.Packet { return t.packets }

// DialTimeout implements memberlist.Transport.
func (t *quicTransport) DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	return t.DialAddressTimeout(memberlist.Address{Addr: addr}, timeout)
}

// DialAddressTimeout implements memberlist.NodeAwareTransport: a stream on the
// connection to the peer, connecting first if needed. A connection that no
// longer accepts streams is replaced.
func (t *quicTransport) DialAddressTimeout(a memberlist.Address, timeout time.Duration) (net.Conn, error) {
	select {
	case <-t.done:
		return nil, errors.New("gossip transport is shut down")
	default:
	}
	deadline := time.Now().Add(timeout)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	conn := t.lookup(a.Addr)
	if conn != nil {
		if s, err := conn.OpenStreamSync(ctx); err == nil {
			return dialledStream(conn, s, deadline), nil
		}
		t.forget(a.Addr, conn)
	}
	conn, err := t.connect(ctx, a.Addr)
	if err != nil {
		return nil, err
	}
	s, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("gossip to %s: %w", a.Addr, err)
	}
	return dialledStream(conn, s, deadline), nil
}

// dialledStream wraps a stream memberlist asked for, carrying the dial's own
// deadline on to the exchange. Three of the four exchanges memberlist opens a
// stream for set a deadline of their own straight away and replace this one;
// the fourth, the user message that hands a record over rather than gossiping
// it, sets none, and a peer that accepts the stream without reading it would
// otherwise block the write for as long as it cared to.
func dialledStream(conn *quic.Conn, s *quic.Stream, deadline time.Time) *streamConn {
	c := newStreamConn(conn, s, peerOf(conn))
	_ = c.SetDeadline(deadline)
	return c
}

// peerOf is the identity behind an established connection; zero if unknown.
func peerOf(conn *quic.Conn) trust.PublicKey {
	peer, _ := connIdentity(conn)
	return peer
}

// StreamCh implements memberlist.Transport.
func (t *quicTransport) StreamCh() <-chan net.Conn { return t.streams }

// Shutdown implements memberlist.Transport. Safe to call more than once.
// Every connection is closed, which waits for the close to reach the wire,
// before the QUIC transport goes: closing the transport destroys whatever is
// still open without a word to the peer, which would then only notice at the
// idle timeout.
func (t *quicTransport) Shutdown() error {
	t.once.Do(func() {
		_ = t.ln.Close()
		t.mu.Lock()
		conns := make([]*quic.Conn, 0, len(t.conns))
		for _, c := range t.conns {
			conns = append(conns, c.conn)
		}
		t.mu.Unlock()
		for _, c := range conns {
			_ = c.CloseWithError(0, "shutdown")
		}
		t.mu.Lock()
		// under mu: see track. It is closed before the wait below, so that a
		// handler waiting on it can finish and be waited for.
		close(t.done)
		t.mu.Unlock()
		t.err = t.qt.Close()
		_ = t.udp.Close()
		t.wg.Wait()
	})
	return t.err
}

// streamConn presents a QUIC stream as a net.Conn that knows its peer.
type streamConn struct {
	*quic.Stream
	local, remote net.Addr
	peer          trust.PublicKey
}

// newStreamConn wraps stream s of conn, whose peer is the given identity.
func newStreamConn(conn *quic.Conn, s *quic.Stream, peer trust.PublicKey) *streamConn {
	return &streamConn{Stream: s, local: conn.LocalAddr(), remote: conn.RemoteAddr(), peer: peer}
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }

// PeerIdentity makes a streamConn an enrol.Conn.
func (s *streamConn) PeerIdentity() trust.PublicKey { return s.peer }

// Close ends both directions: the send side cleanly, the receive side by
// telling the peer to stop.
func (s *streamConn) Close() error {
	s.CancelRead(0)
	return s.Stream.Close()
}
