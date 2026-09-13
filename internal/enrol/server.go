package enrol

import (
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// Server admits joiners who prove knowledge of a pending token.
type Server struct {
	Identity *trust.Identity
	Tokens   *TokenStore
	Root     trust.PublicKey
	// Admit signs and records an admission of the joiner (and distributes it);
	// it must return the admission and the records the joiner should start with.
	Admit func(joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error)
	// GossipAddr is this node's memberlist ip:port, handed to the joiner.
	GossipAddr string
	// Records is the membership as it stands. The server checks that a welcome
	// carrying it will fit before it admits anyone, so it is required.
	Records func() trust.Records
	// OverlayNet is the network the cluster allocates overlay addresses in,
	// so a joiner needs no setting of its own.
	OverlayNet netip.Prefix
}

// Conn is a connection whose peer identity the transport has verified (a QUIC
// stream); the exchange requires the identities in the messages to match it.
type Conn interface {
	net.Conn
	PeerIdentity() trust.PublicKey
}

// bound checks that the identity a message claims is the one on the wire.
func bound(conn Conn, claimed trust.PublicKey) error {
	if conn.PeerIdentity() != claimed {
		return errors.New("claimed identity does not match the connection's")
	}
	return nil
}

// Handle runs the member's side of one enrolment on conn and closes it.
func (s *Server) Handle(conn Conn) {
	defer func() { _ = conn.Close() }()
	if err := s.handle(conn); err != nil && !errors.Is(err, errSilent) {
		slog.Warn("enrolment failed", "from", conn.RemoteAddr(), "err", err)
	}
}

// errSilent marks failures that must not be reported to the peer, so the
// server is not an oracle for token guessing.
var errSilent = errors.New("silent")

// refuse tells a joiner why it was not admitted and reports the same reason
// for the member's log. Only a joiner that has proved the token gets one.
func refuse(conn Conn, reason string) error {
	if err := writeFrame(conn, Welcome{Error: reason}); err != nil {
		return fmt.Errorf("%s (the refusal could not be sent: %w)", reason, err)
	}
	return errors.New(reason)
}

// welcomeFits reports whether a welcome for a joiner named name still fits in
// a frame, and how large it would be. The membership only grows, so a cluster
// that has outgrown the frame must stop admitting nodes rather than sign and
// distribute an admission it cannot deliver, which would grow the records
// further with every attempt.
func (s *Server) welcomeFits(name string) (int, bool) {
	records := s.Records()
	// the joiner's own admission is added before the welcome is sent, so the
	// check leaves room for one of the largest shape
	probe := trust.Admission{
		Name: name, Host: math.MaxUint64, Seq: math.MaxUint64,
		IssuedAt: time.Now().Unix(), Signature: make([]byte, ed25519.SignatureSize),
	}
	// every kind of record the welcome carries is measured, not just the
	// admissions: revocations and prunes go out with it and stay for good
	records.Admissions = append(slices.Clone(records.Admissions), probe)
	body, err := json.Marshal(Welcome{
		Root:       s.Root,
		Records:    records,
		Admission:  probe,
		GossipAddr: s.GossipAddr,
		OverlayNet: s.OverlayNet,
	})
	if err != nil {
		return 0, true // let the write report it
	}
	return len(body), len(body) <= maxFrame
}

func (s *Server) handle(conn Conn) error {
	setDeadline(conn)
	var h hello
	if err := readFrame(conn, &h); err != nil {
		return err
	}
	if h.Version != protocolVersion || len(h.TokenID) != tokenIDLen || len(h.Nonce) != nonceLen {
		return errors.New("malformed hello")
	}
	// the name is checked before the token is looked at, so a joiner asking
	// for a name no node may hold is turned away whatever it knows
	if err := trust.CheckName(h.Name); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	if err := bound(conn, h.Identity); err != nil {
		return err
	}
	var id tokenID
	copy(id[:], h.TokenID)
	key, ok := s.Tokens.lookup(id)
	if !ok {
		slog.Debug("enrolment with unknown or expired token", "from", conn.RemoteAddr(), "name", h.Name)
		return errSilent
	}

	nM, err := randomNonce()
	if err != nil {
		return err
	}
	k := deriveKey(key, h.Nonce, nM)
	tr := transcript(h.Identity, s.Identity.Public(), h.Nonce, nM, h.Name)
	if err = writeFrame(conn, challenge{
		Identity: s.Identity.Public(), Nonce: nM, MAC: mac(k, labelMember, tr),
	}); err != nil {
		return err
	}

	var p proof
	if err = readFrame(conn, &p); err != nil {
		return err
	}
	if !hmac.Equal(p.MAC, mac(k, labelJoiner, tr)) {
		return errors.New("joiner could not prove knowledge of the token")
	}
	if !s.Tokens.consume(id) {
		return errors.New("token was spent or expired during the exchange")
	}

	// From here the joiner has proved the token, so a refusal is told to it
	// rather than left as a closed connection to interpret.
	if size, ok := s.welcomeFits(h.Name); !ok {
		s.Tokens.refund(id)
		return refuse(conn, fmt.Sprintf("this cluster's membership records no longer fit in an enrolment message (%d bytes of %d); no node can enrol until they are pruned", size, maxFrame))
	}
	adm, records, err := s.Admit(h.Identity, h.Name)
	if err != nil {
		s.Tokens.refund(id)
		return refuse(conn, err.Error())
	}
	welcome := Welcome{Root: s.Root, Records: records, Admission: adm, GossipAddr: s.GossipAddr, OverlayNet: s.OverlayNet}
	if err = writeFrame(conn, welcome); err != nil {
		return err
	}
	// the ack says the welcome arrived, so the connection can be closed
	// without cutting it short; without it the joiner is still admitted
	var a ack
	if err = readFrame(conn, &a); err != nil {
		return fmt.Errorf("joiner did not acknowledge the welcome: %w", err)
	}
	slog.Info("enrolled node", "name", h.Name, "identity", h.Identity.Short(), "from", conn.RemoteAddr())
	return nil
}

// Join enrols with the member on conn using token, proving knowledge of it and
// verifying the member's proof in return. It returns the welcome and the
// identity of the member that ran the exchange, which is the connection's
// peer. The caller owns conn.
func Join(conn Conn, token string, id *trust.Identity, name string) (*Welcome, trust.PublicKey, error) {
	if err := trust.CheckName(name); err != nil {
		return nil, trust.PublicKey{}, err
	}
	key, err := decodeToken(token)
	if err != nil {
		return nil, trust.PublicKey{}, err
	}
	setDeadline(conn)

	nJ, err := randomNonce()
	if err != nil {
		return nil, trust.PublicKey{}, err
	}
	tid := idOf(key)
	if err = writeFrame(conn, hello{
		Version: protocolVersion, TokenID: tid[:], Identity: id.Public(), Nonce: nJ, Name: name,
	}); err != nil {
		return nil, trust.PublicKey{}, err
	}

	var c challenge
	if err = readFrame(conn, &c); err != nil {
		return nil, trust.PublicKey{}, fmt.Errorf("member closed the connection (is the join key valid and unexpired?): %w", err)
	}
	if len(c.Nonce) != nonceLen {
		return nil, trust.PublicKey{}, errors.New("malformed challenge")
	}
	if err = bound(conn, c.Identity); err != nil {
		return nil, trust.PublicKey{}, err
	}
	k := deriveKey(key, nJ, c.Nonce)
	tr := transcript(id.Public(), c.Identity, nJ, c.Nonce, name)
	if !hmac.Equal(c.MAC, mac(k, labelMember, tr)) {
		return nil, trust.PublicKey{}, errors.New("member could not prove knowledge of the join key")
	}
	if err = writeFrame(conn, proof{MAC: mac(k, labelJoiner, tr)}); err != nil {
		return nil, trust.PublicKey{}, err
	}

	var w Welcome
	if err = readFrame(conn, &w); err != nil {
		return nil, trust.PublicKey{}, err
	}
	if w.Error != "" {
		return nil, trust.PublicKey{}, fmt.Errorf("the member refused to admit this node: %s", w.Error)
	}

	// Trust nothing in the welcome that the records do not prove.
	set := trust.NewSet(w.Root)
	set.Merge(w.Records)
	if !set.Valid(c.Identity) {
		return nil, trust.PublicKey{}, errors.New("member is not a valid member of the cluster it described")
	}
	if w.Admission.Identity != id.Public() || w.Admission.Admitter != c.Identity {
		return nil, trust.PublicKey{}, errors.New("welcome carries an admission for someone else")
	}
	if _, err = set.AddAdmission(w.Admission); err != nil {
		return nil, trust.PublicKey{}, err
	}
	if !set.Valid(id.Public()) {
		return nil, trust.PublicKey{}, errors.New("admission does not make us a member")
	}
	if err = writeFrame(conn, ack{}); err != nil {
		return nil, trust.PublicKey{}, err
	}
	return &w, c.Identity, nil
}
