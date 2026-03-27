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

package syslog_test

import (
	"fmt"

	"github.com/axonops/go-audit/syslog"
)

func ExampleConfig_tcp() {
	// Plain TCP syslog — the simplest configuration.
	cfg := &syslog.Config{
		Network:  "tcp",
		Address:  "syslog.example.com:514",
		Facility: "local0",
		AppName:  "myapp",
	}
	fmt.Printf("network=%s address=%s facility=%s app=%s\n",
		cfg.Network, cfg.Address, cfg.Facility, cfg.AppName)
	// Output: network=tcp address=syslog.example.com:514 facility=local0 app=myapp
}

func ExampleConfig_tls() {
	// TLS syslog with CA verification.
	cfg := &syslog.Config{
		Network: "tcp+tls",
		Address: "syslog.example.com:6514",
		TLSCA:   "/etc/audit/ca.pem",
	}
	fmt.Printf("network=%s address=%s ca=%s\n", cfg.Network, cfg.Address, cfg.TLSCA)
	// Output: network=tcp+tls address=syslog.example.com:6514 ca=/etc/audit/ca.pem
}

func ExampleConfig_mtls() {
	// mTLS syslog with client certificate authentication.
	cfg := &syslog.Config{
		Network: "tcp+tls",
		Address: "syslog.example.com:6514",
		TLSCert: "/etc/audit/client-cert.pem",
		TLSKey:  "/etc/audit/client-key.pem",
		TLSCA:   "/etc/audit/ca.pem",
	}
	fmt.Printf("network=%s address=%s cert=%s key=%s ca=%s\n",
		cfg.Network, cfg.Address, cfg.TLSCert, cfg.TLSKey, cfg.TLSCA)
	// Output: network=tcp+tls address=syslog.example.com:6514 cert=/etc/audit/client-cert.pem key=/etc/audit/client-key.pem ca=/etc/audit/ca.pem
}
