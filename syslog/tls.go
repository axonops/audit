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

package syslog

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
)

// buildSyslogTLSConfig constructs a TLS config from the syslog config.
// Warnings emitted by [audit.TLSPolicy.Apply] are routed through the
// given logger (pass [slog.Default] for caller-default behaviour).
func buildSyslogTLSConfig(cfg *Config, logger *slog.Logger) (*tls.Config, error) {
	tlsCfg, warnings := cfg.TLSPolicy.Apply(nil)
	for _, w := range warnings {
		logger.Warn(w, "output", "syslog", "address", cfg.Address)
	}

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("audit: syslog tls: load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	if cfg.TLSCA != "" {
		caCert, err := os.ReadFile(cfg.TLSCA)
		if err != nil {
			return nil, fmt.Errorf("audit: syslog tls: read ca certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("audit: syslog tls: parse ca certificate: invalid pem block")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

// syslogFacilities maps facility name strings to srslog.Priority values.
