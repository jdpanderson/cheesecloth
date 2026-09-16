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

	"github.com/jdpanderson/cheesecloth/internal/tally"
	"github.com/jdpanderson/cheesecloth/internal/trust"
)

// Server admits joiners who prove knowledge of a pending token.
type Server struct {
	Identity *trust.Identity
	Tokens   *TokenStore
	// Admit signs and records an admission of the joiner (and distributes it);
	// it must return the admission and the records the joiner should start with.
	Admit func(joiner trust.PublicKey, name string) (trust.Admission, trust.Records, error)
	// GossipAddr is this node's memberlist ip:port, handed to the joiner.
	GossipAddr string
	// Records is the membership as it stands. The server checks that a welcome
	// carrying it will fit before it admits anyone, so it is required.
	Records func() trust.Records
	// Anchor is the agreed membership a joiner starts from, if the cluster has
	// one yet; nil means it walks the records from the root instead.
	Anchor func() *trust.Checkpoint
	// OverlayNet is the network the cluster allocates overlay addresses in,
	// so a joiner needs no setting of its own.
	OverlayNet netip.Prefix

	// unproven counts what peers that proved nothing sent, so the log says so
	// at its own rate rather than theirs.
	unproven tally.Counter
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
	err := s.handle(conn)
	switch {
	case err == nil:
	case errors.Is(err, errUnproven):
		s.unproven.Note(unprovenMsg, "recent", err, "from", conn.RemoteAddr())
	default:
		slog.Warn("enrolment failed", "from", conn.RemoteAddr(), "err", err)
	}
}

// errUnproven marks a failure by a peer that has not proved the token. Such a
// peer is told nothing, so that the server is not an oracle for token guessing,
// and it is not logged one line per attempt either: anyone who can reach the
// port can produce these, and a line each would let them decide how much a
// member writes to disk. They are counted instead.
//
// Everything after the proof is a peer that held a valid invitation, so it is
// bounded by the uses the token had and is logged as it happens.
var errUnproven = errors.New("unproven")

// unproven wraps a failure by a peer that has proved nothing.
func unproven(err error) error { return fmt.Errorf("%w: %w", errUnproven, err) }

// unprovenMsg is what the counted report says. The transport writes its own for
// the enrolments it turns away before this package sees them.
const unprovenMsg = "enrolment attempts by peers that proved nothing; a member reports these at its own rate, " +
	"since anyone who can reach the port can make them"

// shortName is a name as it may be logged before anything has checked it. The
// name in a hello is whatever the peer sent, up to the size of the message, and
// a peer that has proved nothing must not decide how much a member writes; what
// is kept is enough to recognise the name the joiner asked for. The handler
// quotes control characters, so only the length is this function's business.
func shortName(name string) string {
	if len(name) <= trust.NameMax {
		return name
	}
	return name[:trust.NameMax] + "... (truncated)"
}

// refuse tells a joiner why it was not admitted and reports the same reason
// for the member's log. Only a joiner that has proved the token gets one.
func refuse(conn Conn, reason string) error {
	if err := writeFrame(conn, Welcome{Error: reason}); err != nil {
		return fmt.Errorf("%s (the refusal could not be sent: %w)", reason, err)
	}
	return errors.New(reason)
}

// welcomeFits reports whether a welcome for a joiner named name still fits in
// a frame, and how large it would be. A cluster that has outgrown the frame
// must stop admitting nodes rather than sign and distribute an admission it
// cannot deliver, which would grow the records further with every attempt.
//
// What fills the frame is the membership itself: one entry per member, and one
// per identity removed in the last Keep agreements. The records a membership
// accounts for are trimmed and cost nothing, and there is no history behind it
// to send.
func (s *Server) welcomeFits(name string) (int, bool) {
	records := s.Records()
	// the joiner's own admission is added before the welcome is sent, so the
	// check leaves room for one of the largest shape
	probe := trust.Admission{Name: name, Host: math.MaxUint64, Signature: make([]byte, ed25519.SignatureSize)}
	// every kind of record the welcome carries is measured, not just the
	// admissions: the checkpoint chain is most of it
	records.Admissions = append(slices.Clone(records.Admissions), probe)
	body, err := json.Marshal(Welcome{
		Anchor:     s.anchor(),
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

// anchor is the agreed membership to hand a joiner, where the server was given
// a way to ask for one.
func (s *Server) anchor() *trust.Checkpoint {
	if s.Anchor == nil {
		return nil
	}
	return s.Anchor()
}

func (s *Server) handle(conn Conn) error {
	setDeadline(conn)
	var h hello
	if err := readFrame(conn, &h, maxShortFrame); err != nil {
		return unproven(err)
	}
	if h.Version != protocolVersion || len(h.TokenID) != tokenIDLen || len(h.Nonce) != nonceLen {
		return unproven(errors.New("malformed hello"))
	}
	if err := bound(conn, h.Identity); err != nil {
		return unproven(err)
	}
	var id tokenID
	copy(id[:], h.TokenID)
	key, ok := s.Tokens.lookup(id)
	if !ok {
		slog.Debug("enrolment with unknown or expired token", "from", conn.RemoteAddr(), "name", shortName(h.Name))
		return unproven(errors.New("unknown or expired token"))
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
		return unproven(err)
	}

	var p proof
	if err = readFrame(conn, &p, maxShortFrame); err != nil {
		return unproven(err)
	}
	if !hmac.Equal(p.MAC, mac(k, labelJoiner, tr)) {
		return unproven(errors.New("joiner could not prove knowledge of the token"))
	}

	// From here the joiner has proved the token, so a refusal is told to it
	// rather than left as a closed connection to interpret.
	//
	// The name is checked here rather than at the hello. A peer that has proved
	// nothing is told nothing, so checking it earlier turned a bad name into a
	// closed connection the joiner would read as a wrong token. Nothing is
	// signed from an unchecked name either way: admit checks it again before it
	// signs, and the hosts file checks what it writes for itself.
	if nameErr := trust.CheckName(h.Name); nameErr != nil {
		return refuse(conn, nameErr.Error())
	}
	if !s.Tokens.consume(id) {
		return errors.New("token was spent or expired during the exchange")
	}
	// The joiner is not a member until the cluster has agreed a membership
	// holding it, and Admit waits for that, so the rest of the exchange is
	// bounded by the agreement rather than by a round trip.
	setAgreeDeadline(conn)
	if size, ok := s.welcomeFits(h.Name); !ok {
		s.Tokens.refund(id)
		return refuse(conn, fmt.Sprintf("this cluster's membership records no longer fit in an enrolment message (%d bytes of %d); no node can enrol until the cluster is smaller", size, maxFrame))
	}
	adm, records, err := s.Admit(h.Identity, h.Name)
	if err != nil {
		s.Tokens.refund(id)
		return refuse(conn, err.Error())
	}
	welcome := Welcome{Anchor: s.anchor(), Records: records, Admission: adm, GossipAddr: s.GossipAddr, OverlayNet: s.OverlayNet}
	if err = writeFrame(conn, welcome); err != nil {
		return err
	}
	// the ack says the welcome arrived, so the connection can be closed
	// without cutting it short; without it the joiner is still admitted
	var a ack
	if err = readFrame(conn, &a, maxShortFrame); err != nil {
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
	if err = readFrame(conn, &c, maxShortFrame); err != nil {
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
	// the member now waits for the cluster to agree a membership holding this
	// node, which is what makes it a member; both sides allow for it
	setAgreeDeadline(conn)

	var w Welcome
	if err = readFrame(conn, &w, maxFrame); err != nil {
		return nil, trust.PublicKey{}, err
	}
	if w.Error != "" {
		return nil, trust.PublicKey{}, fmt.Errorf("the member refused to admit this node: %s", w.Error)
	}

	// The token exchange is what established that this member speaks for the
	// cluster, so the membership it hands over is taken as given: a joiner has
	// no history to check it against and needs none. Everything else in the
	// welcome still has to be proved by the records.
	set := trust.NewSet()
	if w.Anchor != nil {
		if err = set.Adopt(*w.Anchor); err != nil {
			return nil, trust.PublicKey{}, fmt.Errorf("the welcome's membership is unusable: %w", err)
		}
	}
	set.Merge(w.Records)
	if !set.Valid(c.Identity) {
		return nil, trust.PublicKey{}, errors.New("member is not a valid member of the cluster it described")
	}
	if w.Admission.Identity != id.Public() || w.Admission.Admitter != c.Identity {
		return nil, trust.PublicKey{}, errors.New("welcome carries an admission for someone else")
	}
	// The admission is the member's assertion of the name and slot it gave this
	// node; the agreed membership is what makes the node a member. Once the
	// cluster has agreed one, the admission has done its work and the set may
	// well have trimmed it away, which is not a failure.
	if _, err = set.AddAdmission(w.Admission); err != nil && !errors.Is(err, trust.ErrSuperseded) {
		return nil, trust.PublicKey{}, err
	}
	if !set.Valid(id.Public()) {
		return nil, trust.PublicKey{}, errors.New("the membership the member handed over does not hold this node")
	}
	if !w.OverlayNet.IsValid() {
		return nil, trust.PublicKey{}, errors.New("the welcome names no overlay network")
	}
	if err = writeFrame(conn, ack{}); err != nil {
		return nil, trust.PublicKey{}, err
	}
	return &w, c.Identity, nil
}
