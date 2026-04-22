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

package outputconfig

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/axonops/audit"
)

// New is the convenience facade that creates a ready-to-use
// [audit.Auditor] from embedded taxonomy YAML and a filesystem path
// to the outputs configuration. It combines [audit.ParseTaxonomyYAML],
// [Load], and [audit.New] into a single call — the 80 % case.
//
// When outputsConfigPath is empty, New creates a stdout-only
// development auditor with app_name derived from [os.Args] and host
// from [os.Hostname]. Useful for local development and quick
// evaluation.
//
// opts are applied after the options produced by [Load], so they
// take precedence (last wins). Use this to add [audit.WithMetrics],
// [audit.WithDisabled], or other overrides.
//
// For advanced cases that need [LoadOption] values — secret
// providers, per-output metrics factories, custom output factory
// registrations — use [NewWithLoad] instead.
//
// Non-stdout output types require blank imports to register their
// factories:
//
//	import _ "github.com/axonops/audit/file"    // file output
//	import _ "github.com/axonops/audit/syslog"  // syslog output
//	import _ "github.com/axonops/audit/webhook" // webhook output
//	import _ "github.com/axonops/audit/loki"    // loki output
//
// — or the convenience umbrella package:
//
//	import _ "github.com/axonops/audit/outputs" // all output types
func New(ctx context.Context, taxonomyYAML []byte, outputsConfigPath string, opts ...audit.Option) (*audit.Auditor, error) {
	return NewWithLoad(ctx, taxonomyYAML, outputsConfigPath, nil, opts...)
}

// NewWithLoad is like [New] but forwards loadOpts to [Load]. Use
// when you need one of [WithSecretProvider], [WithCoreMetrics],
// [WithOutputMetrics], [WithFactory], [WithSecretTimeout], or
// [WithDiagnosticLogger]. For the common no-LoadOption case, prefer
// [New].
func NewWithLoad(ctx context.Context, taxonomyYAML []byte, outputsConfigPath string, loadOpts []LoadOption, opts ...audit.Option) (*audit.Auditor, error) {
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		return nil, fmt.Errorf("outputconfig: parse taxonomy: %w", err)
	}

	var auditorOpts []audit.Option
	auditorOpts = append(auditorOpts, audit.WithTaxonomy(tax))

	var devStdout audit.Output // retained for error-path cleanup
	if outputsConfigPath == "" {
		devOpts, stdout, devErr := devModeOptions()
		if devErr != nil {
			return nil, fmt.Errorf("outputconfig: dev mode: %w", devErr)
		}
		devStdout = stdout
		auditorOpts = append(auditorOpts, devOpts...)
	} else {
		data, readErr := readConfigFile(outputsConfigPath)
		if readErr != nil {
			return nil, readErr
		}
		loaded, loadErr := Load(ctx, data, tax, loadOpts...)
		if loadErr != nil {
			return nil, fmt.Errorf("outputconfig: load: %w", loadErr)
		}
		auditorOpts = append(auditorOpts, loaded.Options()...)

		// User options applied last — highest precedence.
		auditorOpts = append(auditorOpts, opts...)

		auditor, auditorErr := audit.New(auditorOpts...)
		if auditorErr != nil {
			// Clean up outputs that Load constructed.
			_ = loaded.Close()
			return nil, fmt.Errorf("outputconfig: create auditor: %w", auditorErr)
		}
		return auditor, nil
	}

	// Dev mode: user options applied after dev defaults.
	auditorOpts = append(auditorOpts, opts...)

	auditor, auditorErr := audit.New(auditorOpts...)
	if auditorErr != nil {
		// Clean up the stdout output constructed by devModeOptions —
		// Auditor.Close cannot run because construction failed. For
		// os.Stdout this is a no-op today, but makes the path resilient
		// to future dev-mode outputs with real resources.
		if devStdout != nil {
			_ = devStdout.Close()
		}
		return nil, fmt.Errorf("outputconfig: create auditor: %w", auditorErr)
	}
	return auditor, nil
}

// devModeOptions returns options for a stdout-only development auditor
// with auto-detected app_name and host, along with the constructed
// stdout output so callers can Close it on [audit.New] failure.
func devModeOptions() ([]audit.Option, audit.Output, error) {
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	if err != nil {
		return nil, nil, fmt.Errorf("create stdout output: %w", err)
	}

	appName := "audit"
	if len(os.Args) > 0 {
		appName = filepath.Base(os.Args[0])
	}

	host, _ := os.Hostname() // best-effort; empty string is acceptable
	if host == "" {
		host = "localhost"
	}

	return []audit.Option{
		audit.WithAppName(appName),
		audit.WithHost(host),
		audit.WithOutputs(stdout),
	}, stdout, nil
}

// readConfigFile reads a configuration file with security hardening:
// regular-file check, size bounding via io.LimitReader, and TOCTOU
// defense via double size check (stat + post-read).
func readConfigFile(path string) ([]byte, error) {
	path = filepath.Clean(path)

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("outputconfig: open %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("outputconfig: stat %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("outputconfig: %q is not a regular file", path)
	}
	if info.Size() > int64(MaxOutputConfigSize) {
		return nil, fmt.Errorf("%w: %q size %d exceeds maximum %d",
			ErrOutputConfigInvalid, path, info.Size(), MaxOutputConfigSize)
	}

	// LimitReader defends against TOCTOU where the file grows between
	// stat and read.
	data, err := io.ReadAll(io.LimitReader(f, int64(MaxOutputConfigSize)+1))
	if err != nil {
		return nil, fmt.Errorf("outputconfig: read %q: %w", path, err)
	}
	if len(data) > MaxOutputConfigSize {
		return nil, fmt.Errorf("%w: %q exceeds maximum size %d after read",
			ErrOutputConfigInvalid, path, MaxOutputConfigSize)
	}

	return data, nil
}
