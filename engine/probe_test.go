package main

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

// startFake runs a UDP DNS server on localhost driven by a plain function.
func startFake(t *testing.T, handler func(query []byte) [][]byte) (host, port string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, peer, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			query := append([]byte(nil), buf[:n]...)
			for _, reply := range handler(query) {
				_, _ = pc.WriteTo(reply, peer)
			}
		}
	}()
	host, port, err = net.SplitHostPort(pc.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func queryID(q []byte) uint16 { return uint16(q[0])<<8 | uint16(q[1]) }

func normalHandler(q []byte) [][]byte {
	id := queryID(q)
	if bytes.Contains(q, []byte("\x07invalid\x00")) {
		return [][]byte{mkResponse(q, id, 3, false)}
	}
	return [][]byte{mkResponse(q, id, 0, false, [4]byte{93, 184, 216, 34})}
}

func TestProbeOnceSuccess(t *testing.T) {
	host, port := startFake(t, normalHandler)
	obs := probeOnce(net.JoinHostPort(host, port), "example.com", kindPopular, time.Second)
	if obs.Error != "" || obs.Rcode == nil || *obs.Rcode != 0 || obs.LatencyMs == nil {
		t.Fatalf("unexpected observation: %+v", obs)
	}
	if len(obs.Addresses) != 1 || obs.Addresses[0] != "93.184.216.34" {
		t.Fatalf("unexpected addresses: %v", obs.Addresses)
	}
}

func TestProbeOnceTimeout(t *testing.T) {
	host, port := startFake(t, func([]byte) [][]byte { return nil })
	obs := probeOnce(net.JoinHostPort(host, port), "example.com", kindPopular, 200*time.Millisecond)
	if obs.Error != "timeout" || obs.Rcode != nil || obs.LatencyMs != nil {
		t.Fatalf("unexpected observation: %+v", obs)
	}
}

func TestProbeOnceIgnoresSpoofedPackets(t *testing.T) {
	host, port := startFake(t, func(q []byte) [][]byte {
		id := queryID(q)
		return [][]byte{
			[]byte("garbage"),
			mkResponse(q, id+1, 0, false, [4]byte{6, 6, 6, 6}),
			mkResponse(q, id, 0, false, [4]byte{1, 2, 3, 4}),
		}
	})
	obs := probeOnce(net.JoinHostPort(host, port), "example.com", kindPopular, time.Second)
	if len(obs.Addresses) != 1 || obs.Addresses[0] != "1.2.3.4" {
		t.Fatalf("spoofed packet was not ignored: %+v", obs)
	}
}

func TestProbeOnceOnlyGarbage(t *testing.T) {
	host, port := startFake(t, func([]byte) [][]byte { return [][]byte{{0, 0, 0, 0, 0}} })
	obs := probeOnce(net.JoinHostPort(host, port), "example.com", kindPopular, 300*time.Millisecond)
	if obs.Error != "malformed" {
		t.Fatalf("expected malformed, got %+v", obs)
	}
}

func TestProbeOnceInvalidName(t *testing.T) {
	obs := probeOnce("127.0.0.1:1", "bad name.com", kindPopular, 100*time.Millisecond)
	if obs.Error != "invalid-name" {
		t.Fatalf("expected invalid-name, got %+v", obs)
	}
}

func TestRunJobShapeAndOrder(t *testing.T) {
	hostA, portA := startFake(t, normalHandler)
	j := &job{
		Protocol: protocol, Servers: []string{hostA, hostA}, Domains: []string{"example.com", "python.org"},
		Queries: 3, TimeoutMs: 500, Workers: 4,
	}
	results := runJob(j, portA)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	obs := results[0].Observations
	if len(obs) != 4 || obs[0].Kind != kindNX || obs[1].Kind != kindPopular {
		t.Fatalf("unexpected plan shape: %+v", obs)
	}
	if !strings.HasSuffix(obs[0].Domain, ".invalid") || obs[0].Rcode == nil || *obs[0].Rcode != 3 {
		t.Fatalf("NX probe wrong: %+v", obs[0])
	}
	if obs[1].Domain != "example.com" || obs[2].Domain != "python.org" || obs[3].Domain != "example.com" {
		t.Fatalf("domains not rotated: %+v", obs)
	}
}

func TestJSONShapeMatchesPythonContract(t *testing.T) {
	obs := observation{Kind: kindPopular, Domain: "example.com", Addresses: []string{}, Error: "timeout"}
	raw, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{`"rcode":null`, `"latency_ms":null`, `"addresses":[]`, `"error":"timeout"`} {
		if !strings.Contains(text, want) {
			t.Errorf("JSON %s is missing %s", text, want)
		}
	}
}

func TestJobValidation(t *testing.T) {
	valid := func() job {
		return job{Protocol: protocol, Servers: []string{"1.1.1.1"}, Domains: []string{"example.com"}, Queries: 3, TimeoutMs: 1500, Workers: 8}
	}
	ok := valid()
	if err := ok.validate(); err != nil {
		t.Fatalf("valid job rejected: %v", err)
	}
	mutations := map[string]func(*job){
		"protocol":     func(j *job) { j.Protocol = 2 },
		"no servers":   func(j *job) { j.Servers = nil },
		"bad server":   func(j *job) { j.Servers = []string{"example.com"} },
		"zone server":  func(j *job) { j.Servers = []string{"fe80::1%eth0"} },
		"no domains":   func(j *job) { j.Domains = nil },
		"bad domain":   func(j *job) { j.Domains = []string{"bad name"} },
		"queries low":  func(j *job) { j.Queries = 0 },
		"queries high": func(j *job) { j.Queries = 1000 },
		"timeout low":  func(j *job) { j.TimeoutMs = 1 },
		"timeout high": func(j *job) { j.TimeoutMs = 999999 },
		"workers":      func(j *job) { j.Workers = 0 },
	}
	for name, mutate := range mutations {
		j := valid()
		mutate(&j)
		if err := j.validate(); err == nil {
			t.Errorf("%s: invalid job accepted", name)
		}
	}
}

func TestRunCommandLine(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, strings.NewReader(""), &out, &errOut); code != 0 {
		t.Fatalf("--version exited %d", code)
	}
	if got := strings.TrimSpace(out.String()); got != "dnstune-probe "+version+" protocol=1" {
		t.Fatalf("unexpected version line %q", got)
	}
	out.Reset()
	if code := run([]string{"run"}, strings.NewReader(`{"protocol":1,"bogus":true}`), &out, &errOut); code != 2 {
		t.Fatalf("unknown fields must be rejected, exit %d", code)
	}
	if code := run([]string{"run"}, strings.NewReader(`not json`), &out, &errOut); code != 2 {
		t.Fatalf("invalid JSON must be rejected, exit %d", code)
	}
	if code := run([]string{"nope"}, strings.NewReader(""), &out, &errOut); code != 2 {
		t.Fatalf("unknown command must exit 2, got %d", code)
	}
}
