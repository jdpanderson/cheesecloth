package trust

import (
	"encoding/json"
	"testing"
)

// FuzzRecords is the push/pull path: a peer's whole record set arrives as
// bytes, is decoded and merged, and every answer the cluster asks of a set
// must still come back without a panic. Records that fail verification are
// skipped rather than fatal, so anything at all may arrive here.
func FuzzRecords(f *testing.F) {
	root, err := NewIdentity()
	if err != nil {
		f.Fatal(err)
	}
	a, err := NewIdentity()
	if err != nil {
		f.Fatal(err)
	}
	rs := Records{Admissions: []Admission{
		SelfAdmit(root, "root", t0),
		Admit(root, a.Public(), "a", 2, 2, t0),
	}}
	rs.Revocations = append(rs.Revocations, Revoke(root, a.Public(), 3, nil, t0))
	rs.Prunes = append(rs.Prunes, SignPrune(root, []PublicKey{a.Public()}, 4, t0))
	seed, err := json.Marshal(rs)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"admissions":[{}],"revocations":[{}],"prunes":[{}]}`))
	f.Add([]byte(`{"admissions":null,"revocations":null,"prunes":null}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, b []byte) {
		var got Records
		if err := json.Unmarshal(b, &got); err != nil {
			return // not our problem: the caller drops what it cannot decode
		}
		s := NewSet(root.Public())
		s.Merge(got)
		s.Valid(a.Public())
		s.Lookup(a.Public())
		s.ByName("a")
		s.NameTaken("a", root.Public())
		s.Prunable()
		s.SignedBy(root.Public())
		s.NextSeq(root.Public())
		s.LastSigned(root.Public())
		s.Conflicts()
		_, _ = s.FreeHost(255)
		s.Records()
	})
}
