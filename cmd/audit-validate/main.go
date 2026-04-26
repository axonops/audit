// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	// Blank-import the outputs convenience package to register all
	// built-in output factories (stdout, file, loki, syslog, webhook).
	// Without this, every -outputs YAML using a built-in type would
	// fail with `unknown output type "stdout"` at semantic-check time.
	_ "github.com/axonops/audit/outputs"
)

// version is set by GoReleaser via -ldflags "-X main.version=…".
// "dev" identifies a hand-built binary so bug reports remain
// traceable to a specific build.
var version = "dev"

// Exit codes — see package godoc.
const (
	exitValid    = 0
	exitParse    = 1
	exitSchema   = 2
	exitSemantic = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is the testable entry point. Returns the process exit code.
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, code := parseFlags(args, stderr)
	if code != 0 {
		return code
	}
	if cfg.helpRequested {
		// Usage already printed by flag.FlagSet on -h/-help.
		return exitValid
	}
	if cfg.showVersion {
		_, _ = fmt.Fprintf(stdout, "audit-validate %s\n", version)
		return exitValid
	}

	taxonomyData, err := readSource(cfg.taxonomyPath, stdin, "taxonomy")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "audit-validate: %v\n", err)
		return exitParse
	}
	outputsData, err := readSource(cfg.outputsPath, stdin, "outputs")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "audit-validate: %v\n", err)
		return exitParse
	}

	res := validate(taxonomyData, outputsData, cfg.resolveSecrets)
	if cfg.quiet {
		return res.exitCode
	}

	switch cfg.format {
	case "json":
		writeJSON(stdout, res)
	default:
		writeText(stdout, stderr, res)
	}
	return res.exitCode
}

// cliConfig holds parsed CLI flags.
type cliConfig struct {
	taxonomyPath   string
	outputsPath    string
	format         string
	quiet          bool
	resolveSecrets bool
	showVersion    bool
	helpRequested  bool // true when -h/-help short-circuits parseFlags
}

// parseFlags parses argv. Returns the config and an exit code.
// A non-zero exitCode means the caller should exit immediately
// (usage error, -h/-help, -version, or stdin double-use).
// `-h`/`-help` returns exitValid (0) so scripts can probe without
// triggering CI failure.
func parseFlags(args []string, stderr io.Writer) (cfg cliConfig, exitCode int) {
	fs := flag.NewFlagSet("audit-validate", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&cfg.taxonomyPath, "taxonomy", "", `Path to taxonomy YAML, or "-" for stdin (required).`)
	fs.StringVar(&cfg.outputsPath, "outputs", "", `Path to outputs YAML, or "-" for stdin (required).`)
	fs.StringVar(&cfg.format, "format", "text", `Output format: "text" or "json".`)
	fs.BoolVar(&cfg.quiet, "quiet", false, "Suppress all output; rely on exit code.")
	fs.BoolVar(&cfg.resolveSecrets, "resolve-secrets", false, "Reserved. Default builds reject ref+ strings as semantic errors.")
	fs.BoolVar(&cfg.showVersion, "version", false, "Print the audit-validate version and exit.")

	fs.Usage = func() {
		_, _ = fmt.Fprintln(stderr, "Usage: audit-validate -taxonomy <file|-> -outputs <file|-> [flags]")
		_, _ = fmt.Fprintln(stderr)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			cfg.helpRequested = true
			return cfg, exitValid
		}
		// ContinueOnError returns the parse error. Exit 2 (Go
		// convention for usage errs).
		return cfg, exitSchema
	}

	if cfg.showVersion {
		// Banner is printed by the caller (run); parseFlags returns
		// success with cfg.showVersion=true so `run` short-circuits.
		return cfg, 0
	}

	if cfg.taxonomyPath == "" || cfg.outputsPath == "" {
		_, _ = fmt.Fprintln(stderr, "audit-validate: both -taxonomy and -outputs are required")
		fs.Usage()
		return cfg, exitSchema
	}
	if cfg.taxonomyPath == "-" && cfg.outputsPath == "-" {
		_, _ = fmt.Fprintln(stderr, `audit-validate: only one of -taxonomy or -outputs may be "-" (stdin can be read once)`)
		return cfg, exitSchema
	}
	if cfg.format != "text" && cfg.format != "json" {
		_, _ = fmt.Fprintf(stderr, "audit-validate: unknown -format %q (allowed: text, json)\n", cfg.format)
		return cfg, exitSchema
	}
	return cfg, 0
}

// readSource reads YAML from a file path, or from stdin if path == "-".
func readSource(path string, stdin io.Reader, label string) ([]byte, error) {
	if path == "-" {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, fmt.Errorf("read %s from stdin: %w", label, err)
		}
		return data, nil
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied CLI argument
	if err != nil {
		return nil, fmt.Errorf("read %s file: %w", label, err)
	}
	return data, nil
}
