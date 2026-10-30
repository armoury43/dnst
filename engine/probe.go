package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"
)

const (
	kindPopular = "popular"
	kindNX      = "nxprobe"

	maxServers = 1024
	maxDomains = 64
	maxQueries = 100
)

type job struct {
	Protocol  int      `json:"protocol"`
	Servers   []string `json:"servers"`
	Domains   []string `json:"domains"`
	Queries   int      `json:"queries"`
	TimeoutMs int      `json:"timeout_ms"`
	Workers   int      `json:"workers"`
}

type observation struct {
	Kind      string   `json:"kind"`
	Domain    string   `json:"domain"`
	Rcode     *int     `json:"rcode"`
	LatencyMs *float64 `json:"latency_ms"`
	Addresses []string `json:"addresses"`
	Error     string   `json:"error"`
}

type serverResult struct {
	Server       string        `json:"server"`
	Observations []observation `json:"observations"`
}

type output struct {
	Protocol int            `json:"protocol"`
	Results  []serverResult `json:"results"`
}

// validate treats the job as untrusted input, like every other boundary.
func (j *job) validate() error {
	if j.Protocol != protocol {
		return fmt.Errorf("unsupported protocol %d", j.Protocol)
	}
	if n := len(j.Servers); n < 1 || n > maxServers {
		return fmt.Errorf("servers must contain 1-%d entries", maxServers)
	}
	for _, s := range j.Servers {
		addr, err := netip.ParseAddr(s)
		if err != nil || addr.Zone() != "" {
			return fmt.Errorf("invalid server address %q", s)
		}
	}
	if n := len(j.Domains); n < 1 || n > maxDomains {
		return fmt.Errorf("domains must contain 1-%d entries", maxDomains)
	}
	for _, d := range j.Domains {
		if _, err := validHostname(d); err != nil {
			return fmt.Errorf("invalid domain %q: %v", d, err)
		}
	}
	if j.Queries < 1 || j.Queries > maxQueries {
		return fmt.Errorf("queries must be 1-%d", maxQueries)
	}
	if j.TimeoutMs < 100 || j.TimeoutMs > 30000 {
		return fmt.Errorf("timeout_ms must be 100-30000")
	}
	if j.Workers < 1 || j.Workers > 256 {
		return fmt.Errorf("workers must be 1-256")
	}
	return nil
}

func randomUint16() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func randomNXName() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "dnstune-fallback.invalid"
	}
	return "dnstune-" + hex.EncodeToString(b[:]) + ".invalid"
}

func classifyErr(err error) string {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "refused"
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return "network:" + errno.Error()
	}
	return "network:error"
}

func roundMs(d time.Duration) float64 {
	return math.Round(float64(d.Microseconds())/10) / 100
}

// probeOnce sends one A query over a fresh connected UDP socket (new random
// source port and transaction id every time) and reports what happened.
func probeOnce(target, domain, kind string, timeout time.Duration) observation {
	obs := observation{Kind: kind, Domain: domain, Addresses: []string{}}

	id, err := randomUint16()
	if err != nil {
		obs.Error = "internal:rand"
		return obs
	}
	query, err := buildQuery(domain, qtypeA, id)
	if err != nil {
		obs.Error = "invalid-name"
		return obs
	}
	conn, err := net.Dial("udp", target)
	if err != nil {
		obs.Error = classifyErr(err)
		return obs
	}
	defer conn.Close()

	start := time.Now()
	if err := conn.SetDeadline(start.Add(timeout)); err != nil {
		obs.Error = classifyErr(err)
		return obs
	}
	if _, err := conn.Write(query); err != nil {
		obs.Error = classifyErr(err)
		return obs
	}

	buf := make([]byte, 4096)
	lastErr := "timeout"
	for {
		n, err := conn.Read(buf)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				obs.Error = lastErr
			} else {
				obs.Error = classifyErr(err)
			}
			return obs
		}
		elapsed := time.Since(start)
		resp, perr := parseResponse(buf[:n], id, domain, qtypeA)
		if perr != nil {
			lastErr = "malformed" // ignore spoofed or corrupt packets until the deadline
			continue
		}
		rcode := resp.rcode
		latency := roundMs(elapsed)
		obs.Rcode = &rcode
		obs.LatencyMs = &latency
		obs.Addresses = resp.addresses
		if resp.truncated && len(resp.addresses) == 0 {
			obs.Error = "truncated"
		}
		return obs
	}
}

// probeServer runs the whole plan against one server, sequentially.
func probeServer(host, port string, j *job) serverResult {
	target := net.JoinHostPort(host, port)
	timeout := time.Duration(j.TimeoutMs) * time.Millisecond
	res := serverResult{Server: host, Observations: make([]observation, 0, j.Queries+1)}
	res.Observations = append(res.Observations, probeOnce(target, randomNXName(), kindNX, timeout))
	for i := 0; i < j.Queries; i++ {
		domain := j.Domains[i%len(j.Domains)]
		res.Observations = append(res.Observations, probeOnce(target, domain, kindPopular, timeout))
	}
	return res
}

// runJob probes all servers with bounded parallelism, preserving input order.
func runJob(j *job, port string) []serverResult {
	results := make([]serverResult, len(j.Servers))
	sem := make(chan struct{}, j.Workers)
	var wg sync.WaitGroup
	for i, host := range j.Servers {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = probeServer(host, port, j)
		}(i, host)
	}
	wg.Wait()
	return results
}
