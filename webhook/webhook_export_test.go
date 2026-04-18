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

package webhook

// WebhookBackoff is exported for testing only.
var WebhookBackoff = webhookBackoff

// BuildNDJSON is exported for testing only.
var BuildNDJSON = buildNDJSON

// SanitiseClientError is exported for testing only — exercises the
// error-URL redaction path used in the retry loop's log sites (#475).
var SanitiseClientError = sanitiseClientError

// ResponseHeaderTimeout is exported for testing only — exercises the
// minimum-floor computation used for the HTTP transport (#485).
var ResponseHeaderTimeout = responseHeaderTimeout

// MinResponseHeaderTimeout is exported for testing only — lets tests
// assert that the floor constant matches the documented value (#485).
const MinResponseHeaderTimeout = minResponseHeaderTimeout
