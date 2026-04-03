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

import "testing"

func TestComputeHMACFast_EquivalentToComputeHMAC(t *testing.T) {
	t.Parallel()
	salt := []byte("test-salt-value-32-bytes-long!!!")
	payload := []byte(`{"event_type":"test","outcome":"success"}`)

	for _, alg := range SupportedHMACAlgorithms() {
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			cfg := &HMACConfig{
				Enabled:     true,
				SaltVersion: "v1",
				SaltValue:   salt,
				Algorithm:   alg,
			}
			state := newHMACState(cfg)
			if state == nil {
				t.Fatalf("newHMACState returned nil for algorithm %q", alg)
			}

			fast := string(state.computeHMACFast(payload))
			slow, err := ComputeHMAC(payload, salt, alg)
			if err != nil {
				t.Fatalf("ComputeHMAC error: %v", err)
			}
			if fast != slow {
				t.Errorf("fast %q != slow %q for algorithm %s", fast, slow, alg)
			}

			// Verify Reset works: repeated call produces identical result.
			fast2 := string(state.computeHMACFast(payload))
			if fast != fast2 {
				t.Errorf("repeated call differs: %q != %q", fast, fast2)
			}
		})
	}
}
