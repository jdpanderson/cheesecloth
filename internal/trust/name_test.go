package trust

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_CheckName(t *testing.T) {
	for _, name := range []string{"a", "n1", "web-01", "x" + strings.Repeat("y", NameMax-1)} {
		assert.NoError(t, CheckName(name), "%q is an ordinary node name", name)
	}

	for _, tt := range []struct {
		name string
		want string
	}{
		{"", "empty"},
		{strings.Repeat("a", NameMax+1), "64 characters"},
		{"Web1", "not a hostname"},
		{"web1.example.com", "not a hostname"},
		{"my_host", "not a hostname"},
		{"-web1", "not a hostname"},
		{"web1-", "not a hostname"},
		{"web 1", "not a hostname"},
		{"web1\n192.0.2.66\tbank.example.com", "not a hostname"},
		{"héllo", "not a hostname"},
		{"192", "all digits"},
	} {
		assert.ErrorContains(t, CheckName(tt.name), tt.want, "name %q", tt.name)
	}
}

// A name that could not be written to a hosts file or shown to an operator is
// never in a record, wherever the record came from.
func Test_Admission_Validate_name(t *testing.T) {
	id := newID(t)
	adm := SelfAdmit(id, "root", t0)
	require.NoError(t, adm.Validate())

	for _, name := range []string{"", "Root", "root.example.com", "root\n10.0.0.9 other"} {
		bad := Admit(id, id.Public(), name, rootHost, rootSeq, t0)
		assert.ErrorContains(t, bad.Validate(), "admission:", "name %q", name)
	}

	// the check is on the signed name, so it cannot be dodged by editing the record
	adm.Name = "root\n10.0.0.9 other"
	assert.ErrorContains(t, adm.Validate(), "admission:")
}

// The set is one of the places a record arrives from outside.
func Test_Set_AddAdmission_refusesABadName(t *testing.T) {
	root, a, _, _, set := cluster(t)
	ok, err := set.AddAdmission(Admit(root, newID(t).Public(), "not a name", 4, 3, t0))
	assert.ErrorContains(t, err, "not a hostname")
	assert.False(t, ok)

	n := set.Merge(Records{Admissions: []Admission{Admit(a, newID(t).Public(), "BAD", 5, 2, t0)}})
	assert.Zero(t, n, "a merged record is checked like any other")
}
