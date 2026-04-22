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

package outputconfig_test

import (
	"context"
	"fmt"
	"os"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
)

// writeTempYAML writes content to a temp file and returns its path.
// Only used by the runnable examples — production consumers use
// `go:embed` + a real filesystem path.
func writeTempYAML(content []byte) string {
	f, err := os.CreateTemp("", "outputs-*.yaml")
	if err != nil {
		panic(err)
	}
	if _, wErr := f.Write(content); wErr != nil {
		panic(wErr)
	}
	_ = f.Close()
	return f.Name()
}

func removeFile(path string) { _ = os.Remove(path) }

var exampleTaxonomyYAML = []byte(`
version: 1
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
`)

var exampleOutputsYAML = []byte(`
version: 1
app_name: example-app
host: example-host
outputs:
  console:
    type: stdout
`)

// ExampleLoad shows how to parse an outputs YAML configuration into
// a [*Loaded] and feed its options into [audit.New] directly — useful
// when the consumer needs the parsed outputs for inspection before
// constructing the auditor, or wants to mix in additional
// [audit.Option] values that are not expressible as [LoadOption].
func ExampleLoad() {
	tax, err := audit.ParseTaxonomyYAML(exampleTaxonomyYAML)
	if err != nil {
		fmt.Println("parse taxonomy:", err)
		return
	}

	loaded, err := outputconfig.Load(context.Background(), exampleOutputsYAML, tax)
	if err != nil {
		fmt.Println("load:", err)
		return
	}

	opts := append([]audit.Option{audit.WithTaxonomy(tax)}, loaded.Options()...)
	auditor, err := audit.New(opts...)
	if err != nil {
		_ = loaded.Close() // clean up outputs the auditor would have owned
		fmt.Println("new auditor:", err)
		return
	}
	defer func() { _ = auditor.Close() }()

	fmt.Println("outputs:", len(loaded.OutputMetadata()))
	fmt.Println("app_name:", loaded.AppName())
	// Output:
	// outputs: 1
	// app_name: example-app
}

// ExampleNew shows the simplest consumer flow: embed the taxonomy,
// point [New] at a filesystem path for the outputs YAML, get back a
// ready-to-use [*audit.Auditor]. Additional [audit.Option] values
// override the Load-derived ones (last wins).
func ExampleNew() {
	// In a real program you would load a separate YAML file from disk:
	//   auditor, err := outputconfig.New(ctx, taxonomyYAML, "outputs.yaml")
	//
	// This runnable example writes the YAML to a temp file so it can
	// run under `go test`.
	tmp := writeTempYAML(exampleOutputsYAML)
	defer removeFile(tmp)

	auditor, err := outputconfig.New(context.Background(), exampleTaxonomyYAML, tmp,
		audit.WithDisabled(), // last-wins override — keeps the example silent
	)
	if err != nil {
		fmt.Println("new:", err)
		return
	}
	defer func() { _ = auditor.Close() }()

	fmt.Println("disabled:", auditor.IsDisabled())
	// Output:
	// disabled: true
}

// ExampleNewWithLoad shows the advanced form that accepts
// [LoadOption] values — used when the consumer needs a custom secret
// provider, a core-metrics recorder, or per-output metrics factory.
// For the simple no-LoadOption case use [New].
func ExampleNewWithLoad() {
	tmp := writeTempYAML(exampleOutputsYAML)
	defer removeFile(tmp)

	auditor, err := outputconfig.NewWithLoad(context.Background(),
		exampleTaxonomyYAML, tmp,
		[]outputconfig.LoadOption{
			outputconfig.WithCoreMetrics(nil), // nil metrics = no-op, illustrates threading
		},
		audit.WithDisabled(),
	)
	if err != nil {
		fmt.Println("new:", err)
		return
	}
	defer func() { _ = auditor.Close() }()

	fmt.Println("disabled:", auditor.IsDisabled())
	// Output:
	// disabled: true
}
