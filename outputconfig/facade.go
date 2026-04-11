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

	audit "github.com/axonops/go-audit"
)

// NewLogger is a convenience facade that creates a ready-to-use
// [audit.Logger] from embedded taxonomy YAML and a filesystem path
// to the outputs configuration. It combines [audit.ParseTaxonomyYAML],
// [Load], and [audit.NewLogger] into a single call.
//
// When outputsConfigPath is empty, NewLogger creates a stdout-only
// development logger with app_name derived from [os.Args] and host
// from [os.Hostname]. This is useful for local development and
// quick evaluation.
//
// Additional opts are applied after the options produced by [Load],
// so they take precedence (last wins). Use this to add
// [audit.WithMetrics], [audit.WithDisabled], or other overrides.
//
// Non-stdout output types require blank imports to register their
// factories:
//
//	import _ "github.com/axonops/go-audit/file"    // file output
//	import _ "github.com/axonops/go-audit/syslog"  // syslog output
//	import _ "github.com/axonops/go-audit/webhook" // webhook output
//	import _ "github.com/axonops/go-audit/loki"    // loki output
//
// For advanced scenarios requiring secret providers, custom
// LoadOptions, or fine-grained control, use the manual
// [Load] + [audit.NewLogger] path instead.
func NewLogger(ctx context.Context, taxonomyYAML []byte, outputsConfigPath string, opts ...audit.Option) (*audit.Logger, error) {
	tax, err := audit.ParseTaxonomyYAML(taxonomyYAML)
	if err != nil {
		return nil, fmt.Errorf("outputconfig: parse taxonomy: %w", err)
	}

	var loggerOpts []audit.Option
	loggerOpts = append(loggerOpts, audit.WithTaxonomy(tax))

	if outputsConfigPath == "" {
		devOpts, devErr := devModeOptions()
		if devErr != nil {
			return nil, fmt.Errorf("outputconfig: dev mode: %w", devErr)
		}
		loggerOpts = append(loggerOpts, devOpts...)
	} else {
		data, readErr := readConfigFile(outputsConfigPath)
		if readErr != nil {
			return nil, readErr
		}
		result, loadErr := Load(ctx, data, tax)
		if loadErr != nil {
			return nil, fmt.Errorf("outputconfig: load: %w", loadErr)
		}
		loggerOpts = append(loggerOpts, result.Options...)

		// User options applied last — highest precedence.
		loggerOpts = append(loggerOpts, opts...)

		logger, err := audit.NewLogger(loggerOpts...)
		if err != nil {
			// Clean up outputs that Load constructed.
			for _, o := range result.Outputs {
				_ = o.Output.Close()
			}
			return nil, fmt.Errorf("outputconfig: create logger: %w", err)
		}
		return logger, nil
	}

	// Dev mode: user options applied after dev defaults.
	loggerOpts = append(loggerOpts, opts...)

	logger, err := audit.NewLogger(loggerOpts...)
	if err != nil {
		return nil, fmt.Errorf("outputconfig: create logger: %w", err)
	}
	return logger, nil
}

// devModeOptions returns options for a stdout-only development logger
// with auto-detected app_name and host.
func devModeOptions() ([]audit.Option, error) {
	stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
	if err != nil {
		return nil, fmt.Errorf("create stdout output: %w", err)
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
	}, nil
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
