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

package audittest_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/axonops/audit"
	"github.com/axonops/audit/audittest"
)

var testTaxonomyYAML = []byte(`
version: 1
categories:
  write:
    - user_create
    - user_delete
  security:
    severity: 8
    events:
      - auth_failure
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email: {}
  user_delete:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
  auth_failure:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
`)

func TestNew(t *testing.T) {
	t.Parallel()
	auditor, events, metrics := audittest.New(t, testTaxonomyYAML)

	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	require.Equal(t, 1, events.Count())
	assert.Equal(t, "user_create", events.Events()[0].EventType)
	assert.Equal(t, 1, metrics.EventDeliveries("recorder", "success"))
}

func TestNewQuick(t *testing.T) {
	t.Parallel()
	auditor, events, _ := audittest.NewQuick(t, "user_create", "user_delete")

	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":   "success",
		"any_field": "any_value",
		"extra":     42,
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	require.Equal(t, 1, events.Count())
	assert.Equal(t, "user_create", events.Events()[0].EventType)
}

func TestNew_ValidationError(t *testing.T) {
	t.Parallel()
	auditor, events, metrics := audittest.New(t, testTaxonomyYAML)

	// Missing required field "actor_id".
	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome": "success",
	}))
	require.Error(t, err)
	assert.ErrorIs(t, err, audit.ErrMissingRequiredField)
	assert.Contains(t, err.Error(), "missing required")
	require.NoError(t, auditor.Close())

	assert.Equal(t, 0, events.Count())
	assert.Equal(t, 1, metrics.ValidationErrors("user_create"))
}

func TestNew_WithDisabled(t *testing.T) {
	t.Parallel()
	auditor, events, _ := audittest.New(t, testTaxonomyYAML,
		audittest.WithDisabled(),
	)

	// Disabled auditor accepts events without error but does not deliver.
	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)
	require.NoError(t, auditor.Close())

	assert.Equal(t, 0, events.Count())
}

func TestNew_TableDriven_WithReset(t *testing.T) {
	// Not parallel — subtests share an auditor and use Reset.
	auditor, events, _ := audittest.New(t, testTaxonomyYAML)

	tests := []struct {
		fields    audit.Fields
		name      string
		eventType string
	}{
		{name: "create", eventType: "user_create", fields: audit.Fields{"outcome": "success", "actor_id": "alice"}},
		{name: "failure", eventType: "auth_failure", fields: audit.Fields{"outcome": "failure", "actor_id": "unknown", "reason": "bad password"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			events.Reset()
			err := auditor.AuditEvent(audit.NewEvent(tc.eventType, tc.fields))
			require.NoError(t, err)
			// Synchronous delivery — events available immediately.
			require.Equal(t, 1, events.Count())
			assert.Equal(t, tc.eventType, events.Events()[0].EventType)
		})
	}
}

func TestQuickTaxonomy(t *testing.T) {
	t.Parallel()
	tax := audittest.QuickTaxonomy("user_create", "user_delete")
	assert.Equal(t, 1, tax.Version)
	assert.Contains(t, tax.Events, "user_create")
	assert.Contains(t, tax.Events, "user_delete")
	assert.Contains(t, tax.Categories, "test")
}

func TestNew_WithQueueSize(t *testing.T) {
	// #579: audit.Config + audit.WithConfig removed. Consumers compose
	// individual audit.Option values via audittest.WithAuditOption.
	t.Parallel()
	auditor, events, _ := audittest.New(t, testTaxonomyYAML,
		audittest.WithAuditOption(audit.WithQueueSize(50)),
	)

	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)

	require.Equal(t, 1, events.Count())
	assert.Equal(t, "user_create", events.Events()[0].EventType)
}

func TestNew_WithAsync(t *testing.T) {
	t.Parallel()
	auditor, events, _ := audittest.New(t, testTaxonomyYAML,
		audittest.WithAsync(),
	)

	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)

	// Async delivery — must Close before assertions.
	require.NoError(t, auditor.Close())

	require.Equal(t, 1, events.Count())
	assert.Equal(t, "user_create", events.Events()[0].EventType)
}

func TestNew_WithAuditOption(t *testing.T) {
	t.Parallel()
	auditor, events, _ := audittest.New(t, testTaxonomyYAML,
		audittest.WithAuditOption(audit.WithAppName("test-app")),
	)

	err := auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "alice",
	}))
	require.NoError(t, err)

	require.Equal(t, 1, events.Count())
	evt := events.Events()[0]
	assert.Equal(t, "user_create", evt.EventType)
	assert.Equal(t, "test-app", evt.StringField("app_name"))
}

// ---------------------------------------------------------------------------
// WithExcludeLabels (#566)
// ---------------------------------------------------------------------------

// sensitivityTaxonomyYAML defines a taxonomy with two sensitivity
// labels ("pii", "financial") for WithExcludeLabels tests.
var sensitivityTaxonomyYAML = []byte(`
version: 1
sensitivity:
  labels:
    pii:
      fields: [email, phone]
    financial:
      fields: [credit_card, bank_account]
categories:
  write:
    - user_create
events:
  user_create:
    fields:
      outcome: {required: true}
      actor_id: {required: true}
      email: {}
      phone: {}
      credit_card: {}
      bank_account: {}
      locale: {}
`)

func TestWithExcludeLabels_StripsLabelledFields(t *testing.T) {
	t.Parallel()
	auditor, events, _ := audittest.New(t, sensitivityTaxonomyYAML,
		audittest.WithExcludeLabels("recorder", "pii"),
	)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":     "success",
		"actor_id":    "alice",
		"email":       "alice@example.com",
		"phone":       "555-1234",
		"credit_card": "4111-1111-1111-1111",
		"locale":      "en-GB",
	})))

	require.Equal(t, 1, events.Count())
	evt := events.Events()[0]

	// pii-labelled fields stripped.
	assert.Nil(t, evt.Field("email"), "email (pii) must be stripped")
	assert.Nil(t, evt.Field("phone"), "phone (pii) must be stripped")
	// Non-pii fields preserved.
	assert.Equal(t, "alice", evt.StringField("actor_id"))
	assert.Equal(t, "success", evt.StringField("outcome"))
	assert.Equal(t, "4111-1111-1111-1111", evt.StringField("credit_card"),
		"financial fields must survive when only pii is excluded")
	assert.Equal(t, "en-GB", evt.StringField("locale"))
}

func TestWithExcludeLabels_PreservesOtherFields(t *testing.T) {
	t.Parallel()
	auditor, events, _ := audittest.New(t, sensitivityTaxonomyYAML,
		audittest.WithExcludeLabels("recorder", "pii"),
	)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":  "success",
		"actor_id": "bob",
		"locale":   "fr-FR",
	})))

	require.Equal(t, 1, events.Count())
	evt := events.Events()[0]
	// No pii fields present, so stripping is a no-op — all fields survive.
	assert.Equal(t, "bob", evt.StringField("actor_id"))
	assert.Equal(t, "success", evt.StringField("outcome"))
	assert.Equal(t, "fr-FR", evt.StringField("locale"))
	// Framework fields also survive (never stripped).
	assert.NotEmpty(t, evt.StringField("event_category"))
}

func TestWithExcludeLabels_MultipleLabels(t *testing.T) {
	t.Parallel()
	auditor, events, _ := audittest.New(t, sensitivityTaxonomyYAML,
		audittest.WithExcludeLabels("recorder", "pii", "financial"),
	)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":      "success",
		"actor_id":     "carol",
		"email":        "carol@example.com",
		"credit_card":  "4111-1111-1111-1111",
		"bank_account": "ACCT-42",
		"locale":       "de-DE",
	})))

	require.Equal(t, 1, events.Count())
	evt := events.Events()[0]
	// All labelled fields stripped.
	assert.Nil(t, evt.Field("email"), "pii")
	assert.Nil(t, evt.Field("credit_card"), "financial")
	assert.Nil(t, evt.Field("bank_account"), "financial")
	// Non-labelled fields preserved.
	assert.Equal(t, "carol", evt.StringField("actor_id"))
	assert.Equal(t, "de-DE", evt.StringField("locale"))
}

func TestWithExcludeLabels_AccumulatesAcrossCalls(t *testing.T) {
	t.Parallel()
	// Two separate calls must accumulate label lists (not replace).
	auditor, events, _ := audittest.New(t, sensitivityTaxonomyYAML,
		audittest.WithExcludeLabels("recorder", "pii"),
		audittest.WithExcludeLabels("recorder", "financial"),
	)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":     "success",
		"actor_id":    "dave",
		"email":       "dave@example.com",
		"credit_card": "4111-1111-1111-1111",
	})))

	require.Equal(t, 1, events.Count())
	evt := events.Events()[0]
	assert.Nil(t, evt.Field("email"), "pii stripped by first call")
	assert.Nil(t, evt.Field("credit_card"), "financial stripped by second call")
}

func TestWithExcludeLabels_EmptyVariadic(t *testing.T) {
	t.Parallel()
	// WithExcludeLabels("recorder") with zero labels engages the
	// per-output-options plumbing branch (switch to WithNamedOutput)
	// but the audit-level strip is a no-op. All fields should survive.
	auditor, events, _ := audittest.New(t, sensitivityTaxonomyYAML,
		audittest.WithExcludeLabels("recorder"),
	)

	require.NoError(t, auditor.AuditEvent(audit.NewEvent("user_create", audit.Fields{
		"outcome":     "success",
		"actor_id":    "eve",
		"email":       "eve@example.com",
		"credit_card": "4111-1111-1111-1111",
	})))

	require.Equal(t, 1, events.Count())
	evt := events.Events()[0]
	// No labels supplied → no stripping.
	assert.Equal(t, "eve@example.com", evt.StringField("email"))
	assert.Equal(t, "4111-1111-1111-1111", evt.StringField("credit_card"))
}

func TestWithExcludeLabels_UnknownLabel(t *testing.T) {
	t.Parallel()
	// Unknown label — not defined in the taxonomy sensitivity section.
	// audit.New returns an error; audittest surfaces it via tb.Fatalf.
	// Use a captor *testing.T to verify the failure path without
	// aborting the parent test.
	captor := &fatalCaptor{}
	func() {
		defer captor.recoverFatal()
		_, _, _ = audittest.New(captor, sensitivityTaxonomyYAML,
			audittest.WithExcludeLabels("recorder", "not-a-label"),
		)
	}()
	assert.True(t, captor.fatalCalled, "tb.Fatalf expected for unknown label")
	assert.Contains(t, captor.fatalMsg, "not-a-label",
		"fatal message should name the offending label")
}

func TestWithExcludeLabels_OutputNameMismatch(t *testing.T) {
	t.Parallel()
	// WithExcludeLabels("not-recorder", ...) targets an output that
	// does not exist in the test logger — tb.Fatalf is expected.
	captor := &fatalCaptor{}
	func() {
		defer captor.recoverFatal()
		_, _, _ = audittest.New(captor, sensitivityTaxonomyYAML,
			audittest.WithExcludeLabels("wrong-name", "pii"),
		)
	}()
	assert.True(t, captor.fatalCalled, "tb.Fatalf expected for outputName mismatch")
	assert.Contains(t, captor.fatalMsg, "wrong-name")
	assert.Contains(t, captor.fatalMsg, "recorder")
}

// fatalCaptor is a testing.TB that turns Fatalf into a recorded
// message + runtime.Goexit-equivalent. audittest.New calls tb.Fatalf
// when audit.New returns an error; the caller must wrap the call in
// a func/defer to scope the Goexit.
type fatalCaptor struct {
	testing.TB
	fatalMsg    string
	fatalCalled bool
}

func (f *fatalCaptor) Helper()        {}
func (f *fatalCaptor) Cleanup(func()) {}
func (f *fatalCaptor) Fatalf(format string, args ...any) {
	f.fatalCalled = true
	f.fatalMsg = fmt.Sprintf(format, args...)
	panic(sentinelFatalPanic{})
}

type sentinelFatalPanic struct{}

func (f *fatalCaptor) recoverFatal() {
	if r := recover(); r != nil {
		if _, ok := r.(sentinelFatalPanic); !ok {
			panic(r)
		}
	}
}
