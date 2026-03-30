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

package audit

// SaveAndResetRegistryForTest saves the current registry state, clears
// it, and returns a restore function. Call the restore function in
// t.Cleanup to restore the original init()-registered factories.
func SaveAndResetRegistryForTest() (restore func()) {
	registryMu.Lock()
	saved := registry
	registry = make(map[string]OutputFactory)
	registryMu.Unlock()
	return func() {
		registryMu.Lock()
		registry = saved
		registryMu.Unlock()
	}
}
