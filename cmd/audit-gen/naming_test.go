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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToPascalCase(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"simple two words", "schema_register", "SchemaRegister"},
		{"id suffix", "actor_id", "ActorID"},
		{"ip suffix", "source_ip", "SourceIP"},
		{"url suffix", "callback_url", "CallbackURL"},
		{"tls suffix", "server_tls", "ServerTLS"},
		{"http prefix", "http_method", "HTTPMethod"},
		{"ms suffix", "uptime_ms", "UptimeMS"},
		{"db suffix", "target_db", "TargetDB"},
		{"single word", "outcome", "Outcome"},
		{"single acronym", "id", "ID"},
		{"three segments", "app_config_id", "AppConfigID"},
		{"multi acronym", "http_url", "HTTPURL"},
		{"empty string", "", ""},
		{"leading underscore", "_actor_id", "ActorID"},
		{"trailing underscore", "actor_id_", "ActorID"},
		{"consecutive underscores", "actor__id", "ActorID"},
		{"all underscores", "___", ""},
		{"mixed case input", "Actor_Id", "ActorID"},
		{"uppercase input", "OUTCOME", "Outcome"},
		{"single char", "x", "X"},
		{"api prefix", "api_key", "APIKey"},
		{"tcp prefix", "tcp_port", "TCPPort"},
		{"tls_ca", "tls_ca", "TLSCA"},
		{"sql_db", "sql_db", "SQLDB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := toPascalCase(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
