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

package loki_test

import (
	"fmt"
	"time"

	audit "github.com/axonops/go-audit"
	"github.com/axonops/go-audit/loki"
)

// ExampleNew demonstrates creating a Loki output with stream labels
// and gzip compression.
func ExampleNew() {
	cfg := &loki.Config{
		URL:                "http://localhost:3100/loki/api/v1/push",
		AllowInsecureHTTP:  true, // local dev only
		AllowPrivateRanges: true, // local dev only
		BatchSize:          100,
		FlushInterval:      5 * time.Second,
		Timeout:            10 * time.Second,
		MaxRetries:         3,
		BufferSize:         10000,
		Compress:           true,
		Labels: loki.LabelConfig{
			Static: map[string]string{
				"job":         "audit",
				"environment": "development",
			},
		},
	}

	out, err := loki.New(cfg, nil, nil)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		return
	}
	defer func() { _ = out.Close() }()

	fmt.Println(out.Name())
	fmt.Println(out.ReportsDelivery())
	// Output:
	// loki:localhost:3100
	// true
}

// ExampleNewFactory demonstrates registering a Loki output factory
// with custom Loki-specific metrics.
func ExampleNewFactory() {
	// Create a factory with custom metrics (pass nil to disable).
	factory := loki.NewFactory(nil)

	// The factory can be registered with the audit output registry:
	audit.RegisterOutputFactory("loki-custom", factory)

	fmt.Println("factory registered")
	// Output:
	// factory registered
}
