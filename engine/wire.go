package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// A deliberately tiny DNS wire codec, mirroring src/dnstune/dnswire.py.
// Every read is bounds-checked; compression pointers may only point
// backwards, so loops are impossible.

const (
	qtypeA          = 1
	qtypeCNAME      = 5
	qtypeOPT        = 41
	classIN         = 1
	maxLabel        = 63
	maxWireName     = 255
	maxPointerJumps = 16
	maxAddresses    = 64
	ednsPayload     = 1232
	headerLen       = 12
)

var errFormat = errors.New("malformed DNS packet")

func formatErr(msg string) error {
	return fmt.Errorf("%w: %s", errFormat, msg)
}

func validLabel(label string) bool {
	n := len(label)
	if n == 0 || n > maxLabel {
		return false
	}
	for i := 0; i < n; i++ {
		c := label[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			continue
		}
		if c == '-' && i != 0 && i != n-1 {
			continue
		}
		return false
	}
	return true
}

// validHostname returns the lower-cased name without a trailing dot.
func validHostname(name string) (string, error) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || len(name) > 253 {
		return "", fmt.Errorf("invalid hostname length")
	}
	for _, label := range strings.Split(name, ".") {
		if !validLabel(label) {
			return "", fmt.Errorf("invalid hostname label %q", label)
		}
	}
	return name, nil
}

func encodeName(name string) ([]byte, error) {
	norm, err := validHostname(name)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(norm)+2)
	for _, label := range strings.Split(norm, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	if len(out) > maxWireName {
		return nil, fmt.Errorf("hostname too long")
	}
	return out, nil
}

// buildQuery builds a recursive query with an EDNS0 OPT record.
func buildQuery(name string, qtype uint16, id uint16) ([]byte, error) {
	encoded, err := encodeName(name)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, headerLen, headerLen+len(encoded)+4+11)
	binary.BigEndian.PutUint16(buf[0:], id)
	binary.BigEndian.PutUint16(buf[2:], 0x0100) // RD
	binary.BigEndian.PutUint16(buf[4:], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(buf[10:], 1)     // ARCOUNT (OPT)
	buf = append(buf, encoded...)
	buf = binary.BigEndian.AppendUint16(buf, qtype)
	buf = binary.BigEndian.AppendUint16(buf, classIN)
	buf = append(buf, 0) // OPT owner: root
	buf = binary.BigEndian.AppendUint16(buf, qtypeOPT)
	buf = binary.BigEndian.AppendUint16(buf, ednsPayload)
	buf = binary.BigEndian.AppendUint32(buf, 0)
	buf = binary.BigEndian.AppendUint16(buf, 0)
	return buf, nil
}

func lowerASCII(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}

// readName decodes a possibly compressed name and returns the offset just
// after it in the original (non-jumped) position.
func readName(data []byte, offset int) (string, int, error) {
	labels := []string{}
	pos := offset
	end := -1
	jumps := 0
	total := 0
	for {
		if pos >= len(data) {
			return "", 0, formatErr("name runs past end of packet")
		}
		length := int(data[pos])
		if length == 0 {
			if end < 0 {
				end = pos + 1
			}
			break
		}
		switch length & 0xC0 {
		case 0xC0:
			if pos+1 >= len(data) {
				return "", 0, formatErr("truncated compression pointer")
			}
			target := (length&0x3F)<<8 | int(data[pos+1])
			if end < 0 {
				end = pos + 2
			}
			jumps++
			if jumps > maxPointerJumps {
				return "", 0, formatErr("too many compression jumps")
			}
			if target >= pos {
				return "", 0, formatErr("compression pointer does not point backwards")
			}
			pos = target
			continue
		case 0x00:
			// ordinary label, handled below
		default:
			return "", 0, formatErr("reserved label type")
		}
		pos++
		if pos+length > len(data) {
			return "", 0, formatErr("label runs past end of packet")
		}
		total += length + 1
		if total > maxWireName {
			return "", 0, formatErr("name too long")
		}
		labels = append(labels, lowerASCII(data[pos:pos+length]))
		pos += length
	}
	return strings.Join(labels, "."), end, nil
}

type response struct {
	rcode     int
	truncated bool
	addresses []string
}

// parseResponse validates a reply to our query and extracts the A records.
func parseResponse(data []byte, id uint16, name string, qtype uint16) (*response, error) {
	if len(data) < headerLen {
		return nil, formatErr("packet shorter than DNS header")
	}
	rid := binary.BigEndian.Uint16(data[0:2])
	flags := binary.BigEndian.Uint16(data[2:4])
	qdcount := binary.BigEndian.Uint16(data[4:6])
	ancount := int(binary.BigEndian.Uint16(data[6:8]))
	if rid != id {
		return nil, formatErr("transaction id mismatch")
	}
	if flags&0x8000 == 0 {
		return nil, formatErr("not a response")
	}
	if (flags>>11)&0xF != 0 {
		return nil, formatErr("unexpected opcode")
	}
	if qdcount != 1 {
		return nil, formatErr("unexpected question count")
	}

	qname, offset, err := readName(data, headerLen)
	if err != nil {
		return nil, err
	}
	if offset+4 > len(data) {
		return nil, formatErr("truncated question")
	}
	gotType := binary.BigEndian.Uint16(data[offset:])
	gotClass := binary.BigEndian.Uint16(data[offset+2:])
	offset += 4
	want := strings.ToLower(strings.TrimSuffix(name, "."))
	if qname != want || gotType != qtype || gotClass != classIN {
		return nil, formatErr("question does not match query")
	}

	wanted := map[string]struct{}{qname: {}}
	addrs := make([]string, 0, 4)
	for i := 0; i < ancount; i++ {
		owner, next, err := readName(data, offset)
		if err != nil {
			return nil, err
		}
		offset = next
		if offset+10 > len(data) {
			return nil, formatErr("truncated resource record header")
		}
		rtype := binary.BigEndian.Uint16(data[offset:])
		rclass := binary.BigEndian.Uint16(data[offset+2:])
		rdlen := int(binary.BigEndian.Uint16(data[offset+8:]))
		offset += 10
		if offset+rdlen > len(data) {
			return nil, formatErr("resource record data runs past end of packet")
		}
		start := offset
		offset += rdlen
		if rclass != classIN {
			continue
		}
		if _, ok := wanted[owner]; !ok {
			continue
		}
		switch {
		case rtype == qtypeCNAME:
			target, _, err := readName(data, start)
			if err != nil {
				return nil, err
			}
			wanted[target] = struct{}{}
		case rtype == qtype:
			if qtype != qtypeA || rdlen != 4 {
				return nil, formatErr("address record has wrong length")
			}
			var raw [4]byte
			copy(raw[:], data[start:start+4])
			if len(addrs) < maxAddresses {
				addrs = append(addrs, netip.AddrFrom4(raw).String())
			}
		}
	}
	return &response{
		rcode:     int(flags & 0xF),
		truncated: flags&0x0200 != 0,
		addresses: addrs,
	}, nil
}
