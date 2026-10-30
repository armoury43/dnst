package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"
)

const testID = 0x1234

// questionEnd returns the offset just after the question of an uncompressed query.
func questionEnd(q []byte) int {
	pos := headerLen
	for q[pos] != 0 {
		pos += 1 + int(q[pos])
	}
	return pos + 1 + 4
}

// mkResponse builds a reply with encoding/binary only, independent of parseResponse.
func mkResponse(query []byte, id uint16, rcode uint16, tc bool, addrs ...[4]byte) []byte {
	flags := uint16(0x8180) | rcode
	if tc {
		flags |= 0x0200
	}
	buf := make([]byte, headerLen)
	binary.BigEndian.PutUint16(buf[0:], id)
	binary.BigEndian.PutUint16(buf[2:], flags)
	binary.BigEndian.PutUint16(buf[4:], 1)
	binary.BigEndian.PutUint16(buf[6:], uint16(len(addrs)))
	buf = append(buf, query[headerLen:questionEnd(query)]...)
	for _, a := range addrs {
		buf = append(buf, 0xC0, 0x0C)
		buf = binary.BigEndian.AppendUint16(buf, 1)
		buf = binary.BigEndian.AppendUint16(buf, 1)
		buf = binary.BigEndian.AppendUint32(buf, 60)
		buf = binary.BigEndian.AppendUint16(buf, 4)
		buf = append(buf, a[:]...)
	}
	return buf
}

func mustQuery(t *testing.T, name string) []byte {
	t.Helper()
	q, err := buildQuery(name, qtypeA, testID)
	if err != nil {
		t.Fatalf("buildQuery(%q): %v", name, err)
	}
	return q
}

func TestValidHostname(t *testing.T) {
	good := map[string]string{"Example.COM.": "example.com", "a-b_c.d1.org": "a-b_c.d1.org"}
	for in, want := range good {
		got, err := validHostname(in)
		if err != nil || got != want {
			t.Errorf("validHostname(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{"", ".", "a..b", "-a.com", "a-.com", "a b.com", "é.com", "a/b.com", "example.com\n"}
	for _, in := range bad {
		if _, err := validHostname(in); err == nil {
			t.Errorf("validHostname(%q) accepted invalid input", in)
		}
	}
	long := bytes.Repeat([]byte("a"), 64)
	if _, err := validHostname(string(long) + ".com"); err == nil {
		t.Error("accepted a 64-byte label")
	}
}

func TestBuildQueryLayout(t *testing.T) {
	q := mustQuery(t, "a.example.com")
	want := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		1, 'a', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
		0x00, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	if !bytes.Equal(q, want) {
		t.Fatalf("query mismatch:\n got %x\nwant %x", q, want)
	}
}

func TestParseResponseAnswers(t *testing.T) {
	q := mustQuery(t, "example.com")
	resp, err := parseResponse(mkResponse(q, testID, 0, false, [4]byte{93, 184, 216, 34}, [4]byte{1, 2, 3, 4}), testID, "example.com", qtypeA)
	if err != nil {
		t.Fatal(err)
	}
	if resp.rcode != 0 || resp.truncated || len(resp.addresses) != 2 || resp.addresses[0] != "93.184.216.34" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	nx, err := parseResponse(mkResponse(q, testID, 3, true), testID, "example.com", qtypeA)
	if err != nil || nx.rcode != 3 || !nx.truncated || len(nx.addresses) != 0 {
		t.Fatalf("unexpected NXDOMAIN parse: %+v %v", nx, err)
	}
}

func TestParseResponseRejects(t *testing.T) {
	q := mustQuery(t, "example.com")
	good := mkResponse(q, testID, 0, false, [4]byte{1, 2, 3, 4})

	cases := map[string][]byte{
		"wrong id":        mkResponse(q, testID+1, 0, false, [4]byte{1, 2, 3, 4}),
		"query not reply": q,
		"other question":  mkResponse(mustQuery(t, "other.com"), testID, 0, false, [4]byte{1, 2, 3, 4}),
		"empty":           {},
	}
	noQuestions := append([]byte(nil), good...)
	noQuestions[4], noQuestions[5] = 0, 0
	cases["zero questions"] = noQuestions

	badLen := append([]byte(nil), good[:len(good)-6]...)
	badLen = append(badLen, 0, 5, 1, 2, 3, 4, 5)
	cases["bad address length"] = badLen

	for name, pkt := range cases {
		if _, err := parseResponse(pkt, testID, "example.com", qtypeA); !errors.Is(err, errFormat) {
			t.Errorf("%s: expected format error, got %v", name, err)
		}
	}
}

func TestCompressionPointersAreSafe(t *testing.T) {
	header := make([]byte, headerLen)
	binary.BigEndian.PutUint16(header[0:], testID)
	binary.BigEndian.PutUint16(header[2:], 0x8180)
	binary.BigEndian.PutUint16(header[4:], 1)

	self := append(append([]byte(nil), header...), 0xC0, 0x0C, 0, 1, 0, 1)
	forward := append(append([]byte(nil), header...), 0xC0, 0x20)
	forward = append(forward, make([]byte, 40)...)
	reserved := append(append([]byte(nil), header...), 0x40, 'a', 'b', 'c', 0, 0, 1, 0, 1)

	for name, pkt := range map[string][]byte{"self": self, "forward": forward, "reserved": reserved} {
		if _, err := parseResponse(pkt, testID, "example.com", qtypeA); !errors.Is(err, errFormat) {
			t.Errorf("%s pointer: expected format error, got %v", name, err)
		}
	}
}

func TestEveryTruncationIsClean(t *testing.T) {
	q := mustQuery(t, "example.com")
	pkt := mkResponse(q, testID, 0, false, [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8})
	for cut := 0; cut < len(pkt); cut++ {
		// Must return an error or a result, never panic.
		_, _ = parseResponse(pkt[:cut], testID, "example.com", qtypeA)
	}
}

func TestRandomMutationsNeverPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(20260921))
	q := mustQuery(t, "example.com")
	base := mkResponse(q, testID, 0, false, [4]byte{1, 2, 3, 4}, [4]byte{5, 6, 7, 8})
	for i := 0; i < 20000; i++ {
		data := append([]byte(nil), base...)
		for k := rng.Intn(6) + 1; k > 0; k-- {
			data[rng.Intn(len(data))] = byte(rng.Intn(256))
		}
		if rng.Float64() < 0.2 {
			data = data[:rng.Intn(len(data))]
		}
		_, _ = parseResponse(data, testID, "example.com", qtypeA)
	}
	for i := 0; i < 5000; i++ {
		blob := make([]byte, rng.Intn(80))
		rng.Read(blob)
		_, _ = parseResponse(blob, testID, "example.com", qtypeA)
	}
}
