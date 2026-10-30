// Command dnstune-probe is the optional measurement engine for dnstune.
//
// It only measures: it sends DNS queries and prints raw observations as JSON.
// All judgement (scoring, integrity flags, selection) lives in the Python
// package, so a bug here can never change which servers are trusted.
//
//	dnstune-probe --version     prints "dnstune-probe <version> protocol=<n>"
//	dnstune-probe run           reads a job (JSON) on stdin, writes results on stdout
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	version  = "0.1.0"
	protocol = 1

	maxJobBytes = 1 << 20
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintf(stdout, "dnstune-probe %s protocol=%d\n", version, protocol)
		return 0
	}
	if len(args) == 1 && args[0] == "run" {
		return runCommand(stdin, stdout, stderr)
	}
	fmt.Fprintln(stderr, "usage: dnstune-probe --version | run   (job JSON on stdin)")
	return 2
}

func runCommand(stdin io.Reader, stdout, stderr io.Writer) int {
	raw, err := io.ReadAll(io.LimitReader(stdin, maxJobBytes))
	if err != nil {
		fmt.Fprintf(stderr, "cannot read job: %v\n", err)
		return 2
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var j job
	if err := decoder.Decode(&j); err != nil {
		fmt.Fprintf(stderr, "invalid job: %v\n", err)
		return 2
	}
	if err := j.validate(); err != nil {
		fmt.Fprintf(stderr, "invalid job: %v\n", err)
		return 2
	}
	out := output{Protocol: protocol, Results: runJob(&j, "53")}
	if err := json.NewEncoder(stdout).Encode(out); err != nil {
		fmt.Fprintf(stderr, "cannot write results: %v\n", err)
		return 1
	}
	return 0
}
