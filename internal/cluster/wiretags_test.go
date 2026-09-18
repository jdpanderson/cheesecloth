package cluster

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jdpanderson/cheesecloth/internal/trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The codec tags are short because every byte of them travels with every
// record. Two fields of one struct sharing a tag is not an error the codec
// reports: it writes both under the one key and hands back the last, leaving
// the other field zero. What that costs is a record whose signature no longer
// covers what it says, which surfaces as "does not verify" somewhere else
// entirely. So the tags are checked here instead, over every type reachable
// from what goes on the wire, so that a field added later is checked too.
func Test_wireTags_areUniqueWithinEachStruct(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type, string)
	walk = func(rt reflect.Type, path string) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Array || rt.Kind() == reflect.Map {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		tags := map[string]string{}
		for i := range rt.NumField() {
			f := rt.Field(i)
			tag, ok := f.Tag.Lookup("codec")
			require.True(t, ok, "%s.%s travels on the wire and needs a codec tag", rt.Name(), f.Name)
			name := strings.Split(tag, ",")[0]
			require.NotEmpty(t, name, "%s.%s has an empty codec tag", rt.Name(), f.Name)
			if was, dup := tags[name]; dup {
				t.Fatalf("%s.%s and %s.%s both use codec tag %q; one would overwrite the other",
					rt.Name(), was, rt.Name(), f.Name, name)
			}
			tags[name] = f.Name

			// a codec tag does not inherit omitempty from the json tag: without
			// its own, the field goes out even when there is nothing in it
			jsonTag := f.Tag.Get("json")
			if strings.Contains(jsonTag, ",omit") {
				assert.Contains(t, tag, ",omitempty",
					"%s.%s is omitted from the state file but not from the wire", rt.Name(), f.Name)
			}
			walk(f.Type, path+"."+f.Name)
		}
	}
	walk(reflect.TypeOf(recordMsg{}), "recordMsg")
	walk(reflect.TypeOf(syncState{}), "syncState")
	assert.Greater(t, len(seen), 8, "the walk reached the record types, not just the wrappers")
}

// The wire got short names so that the state file could keep long ones. It is
// written once per change and read by people, which is worth more there than
// the bytes are.
func Test_stateFile_keepsReadableNames(t *testing.T) {
	id := testIdentity(t)
	cp := trust.Found(id, "a", trust.QuorumMajority, 0)
	b, err := json.MarshalIndent(&state{Seed: id.Seed(), Anchor: &cp, Records: trust.Records{
		Admissions: []trust.Admission{trust.Admit(id, testIdentity(t).Public(), "b", 2)},
	}}, "", "  ")
	require.NoError(t, err)
	for _, want := range []string{
		`"seed"`, `"anchor"`, `"records"`, `"admissions"`, `"identity"`, `"admitter"`,
		`"signature"`, `"depth"`, `"quorum"`, `"members"`, `"attestations"`, `"signer"`, `"name"`, `"host"`,
	} {
		assert.Contains(t, string(b), want, "the state file spells its fields out")
	}
}
