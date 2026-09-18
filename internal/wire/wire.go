// Package wire holds the two byte encodings this project shares: what gets
// signed, and what travels.
//
// Canonical is the first, and it is fixed for good. Every digest and every
// signature is computed over it, so changing it would invalidate every record
// a cluster holds.
//
// Marshal and Unmarshal are the second: how a record travels from one node to
// another. Nothing but transport depends on them, so the format is free to
// change. Never sign what Marshal produces -- sign what Canonical produces,
// which is why the two live here together and are named apart.
package wire

import (
	"bytes"
	"encoding/binary"

	"github.com/hashicorp/go-msgpack/v2/codec"
)

// Canonical encodes fields under domain: the domain string terminated by a
// zero byte, then each field as a 4-byte big-endian length and its bytes, so
// that records of different kinds can never have the same bytes and no field
// boundary is ambiguous.
func Canonical(domain string, fields ...[]byte) []byte {
	out := append([]byte(domain), 0)
	for _, f := range fields {
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

// handle is the messagepack configuration every message uses. A codec handle
// is a configuration object and is safe to share; the encoders and decoders
// made from it are not, so one of those is made per message.
var handle codec.MsgpackHandle

// Marshal encodes v as messagepack. It reads a field's `codec` tag in
// preference to its `json` one, which is what lets a record travel under
// one-letter names while the state file spells the same fields out: the names
// go with every copy of every record, and the file is written once and read by
// people. What it saves besides is the base64 -- an identity travels as its 32
// bytes and a signature as its 64, rather than as a third again in text.
//
// A `codec` tag does not inherit `omitempty` from the `json` tag beside it, and
// two fields of one struct sharing a tag is not an error it reports. Both are
// checked by Test_wireTags_areUniqueWithinEachStruct rather than here.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := codec.NewEncoder(&buf, &handle).Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unmarshal decodes a messagepack message into v.
func Unmarshal(b []byte, v any) error {
	return codec.NewDecoder(bytes.NewReader(b), &handle).Decode(v)
}
