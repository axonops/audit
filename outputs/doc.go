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

// Package outputs registers all go-audit output factories with a
// single blank import:
//
//	import _ "github.com/axonops/go-audit/outputs"
//
// This is a convenience package following the [image/all] pattern.
// It blank-imports [github.com/axonops/go-audit/file],
// [github.com/axonops/go-audit/syslog],
// [github.com/axonops/go-audit/webhook], and
// [github.com/axonops/go-audit/loki], causing their init() functions
// to register output factories with the core registry.
//
// Production deployments SHOULD import only the output packages they
// use to minimise binary size and dependency surface. This package
// pulls in all output dependencies including HTTP clients, syslog
// libraries, and compression codecs.
//
// Double registration is safe — [audit.RegisterOutputFactory] overwrites
// silently by design.
package outputs
