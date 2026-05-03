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

//go:build !integration

package steps

import "github.com/cucumber/godog"

// registerSchemaArtifactsStepsIfBuilt is a no-op outside the
// `integration` build tag so the non-integration build of this
// package does not pull in `github.com/santhosh-tekuri/jsonschema/v5`
// (#548). The integration-tagged sibling file installs the real
// step registration via [registerSchemaArtifactsSteps].
func registerSchemaArtifactsStepsIfBuilt(_ *godog.ScenarioContext, _ *AuditTestContext) {}
