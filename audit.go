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

// Architecture: async buffer -> single drain goroutine -> serialise -> fan-out
//
// AuditEvent() validates the event against the registered taxonomy, checks
// the global filter, then enqueues the event to a buffered channel. A
// single drain goroutine reads from the channel, serialises the event
// to JSON (or the configured format), and writes to all enabled
// outputs. If the buffer is full the event is dropped and metrics are
// recorded.
//
// Close() cancels the drain goroutine's context, waits up to
// ShutdownTimeout for pending events to flush, then closes all outputs in
// sequence. Close is idempotent via sync.Once.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// dropWarnInterval is the minimum interval between slog.Warn calls
// for buffer-full drop events.
const dropWarnInterval = 10 * time.Second

// auditEntryPool caches auditEntry instances to avoid per-Audit heap
// allocation. Entries are retrieved in AuditEvent(), sent through the
// channel, processed by the drain goroutine, and returned to the pool
// at the end of processEntry(). Fields are nilled before return to
// prevent stale references from keeping caller data alive in the pool.
var auditEntryPool = sync.Pool{
	New: func() any { return new(auditEntry) },
}

// fieldsPool caches Fields maps to avoid per-event heap allocation in
// copyFieldsWithDefaults. Maps are retrieved in auditInternal (caller
// goroutine), populated with copied fields, sent through the channel,
// and returned to the pool after processEntry completes (drain goroutine).
// Maps are cleared before return to prevent stale references.
var fieldsPool = sync.Pool{
	New: func() any { return make(Fields, 8) },
}

// Auditor is the core type. It validates events against a
// registered [Taxonomy], filters by category and per-event overrides,
// and delivers events asynchronously to configured [Output]
// destinations.
//
// The library uses [log/slog] for internal diagnostics (buffer drops,
// serialisation failures, output write errors). Consumers can configure
// the slog default handler to control this output.
//
// An Auditor is safe for concurrent use by multiple goroutines.
//
//nolint:govet // field order: logical grouping over alignment optimisation
type Auditor struct {
	closeErr  error
	filter    *filterState
	metrics   Metrics
	formatter Formatter
	ch        chan *auditEntry
	taxonomy  *Taxonomy
	cancel    context.CancelFunc
	drainDone chan struct{}
	// entries and outputsByName are immutable after construction.
	entries       []*outputEntry
	outputsByName map[string]*outputEntry
	cfg           Config
	closeOnce     sync.Once
	closed        atomic.Bool
	// destKeys tracks destination keys during construction to detect
	// duplicate output destinations. Only used by WithNamedOutput;
	// WithOutputs uses a local map.
	destKeys map[string]string
	// usedWithOutputs is set during construction when WithOutputs is
	// applied; prevents mixing WithOutputs and WithNamedOutput.
	usedWithOutputs bool
	// disabled is set by WithDisabled to create a no-op auditor that
	// discards all events without validation or delivery. Replaces
	// the former Config.Enabled field (inverted: disabled=true means
	// the auditor does nothing).
	disabled bool
	// synchronous is set by WithSynchronousDelivery to deliver events
	// inline within AuditEvent instead of via the async channel. No
	// drain goroutine is started. Useful for testing and CLIs.
	synchronous bool
	// syncMu guards processEntry calls in synchronous delivery mode.
	// processEntry reuses per-output state (formatOpts, HMAC) that is
	// only safe under single-goroutine access.
	syncMu sync.Mutex
	// Framework fields set via WithAppName, WithHost, WithTimezone.
	// PID is captured once at construction via os.Getpid().
	appName  string
	host     string
	timezone string
	pid      int
	// standardFieldDefaults holds deployment-wide default values for
	// reserved standard fields. Set once via WithStandardFieldDefaults;
	// read-only after construction. Applied in auditInternal before
	// validation so that defaults satisfy required: true constraints.
	standardFieldDefaults map[string]string
	logger                *slog.Logger // library diagnostics logger
	drops                 dropLimiter  // rate-limits buffer-full warnings
	drainCount            uint64       // events processed by drain loop; for sampling RecordQueueDepth
}

// New creates a new [Auditor] from the given options.
// A taxonomy MUST be provided via [WithTaxonomy] unless [WithDisabled]
// is applied; New returns an error if none is supplied.
//
// The zero-value [Config] is valid: buffer=10,000, shutdown=5s,
// validation=strict. Pass tuning options like [WithQueueSize] or
// [WithShutdownTimeout] to override defaults, or [WithConfig] to apply
// a struct.
//
// When [WithDisabled] is applied, New returns a valid no-op
// auditor without requiring a taxonomy. All [Auditor.AuditEvent] calls
// return nil immediately without validation or delivery. Methods
// that require a taxonomy ([Auditor.EnableCategory], etc.) return
// [ErrDisabled].
func New(opts ...Option) (*Auditor, error) {
	a := &Auditor{}

	for _, opt := range opts {
		if err := opt(a); err != nil {
			return nil, err
		}
	}

	// validateConfig calls applyDefaults internally, then validates.
	// migrateConfig runs after defaults so version is always set.
	if err := validateConfig(&a.cfg); err != nil {
		return nil, err
	}
	if err := migrateConfig(&a.cfg); err != nil {
		return nil, err
	}

	// Release construction-only state.
	a.destKeys = nil

	if a.logger == nil {
		a.logger = slog.Default()
	}

	if a.disabled {
		a.applyConstructionDefaults()
		return a, nil
	}

	if a.taxonomy == nil {
		return nil, fmt.Errorf("audit: taxonomy is required: use WithTaxonomy")
	}

	a.applyDevTaxonomyOverrides()

	if err := a.validateOutputRoutes(); err != nil {
		return nil, err
	}

	a.prepareOutputEntries()

	a.applyConstructionDefaults()

	if !a.synchronous {
		ctx, cancel := context.WithCancel(context.Background())
		a.cancel = cancel
		a.ch = make(chan *auditEntry, a.cfg.QueueSize)
		a.drainDone = make(chan struct{})
		go a.drainLoop(ctx)
	}

	a.logger.Info("audit: auditor created",
		"queue_size", a.cfg.QueueSize,
		"shutdown_timeout", a.cfg.ShutdownTimeout,
		"validation_mode", string(a.cfg.ValidationMode),
		"outputs", len(a.entries),
		"synchronous", a.synchronous,
	)

	return a, nil
}

// applyDevTaxonomyOverrides warns about DevTaxonomy and forces permissive
// validation mode when a dev taxonomy is used.
func (a *Auditor) applyDevTaxonomyOverrides() {
	if a.taxonomy == nil || !a.taxonomy.dev {
		return
	}
	a.logger.Warn("audit: using DevTaxonomy — not suitable for production; all event types accepted without schema enforcement")
	if a.cfg.ValidationMode == ValidationStrict {
		a.cfg.ValidationMode = ValidationPermissive
	}
}

// applyConstructionDefaults sets formatter, PID, timezone, and propagates
// framework fields. Called once during New after all options are applied.
func (a *Auditor) applyConstructionDefaults() {
	if a.formatter == nil {
		a.formatter = &JSONFormatter{OmitEmpty: a.cfg.OmitEmpty}
	}
	a.pid = os.Getpid()
	if a.timezone == "" {
		a.timezone = time.Now().Location().String()
	}
	a.propagateFrameworkFields()
	a.propagateLogger()
}

// propagateLogger forwards the library's slog.Logger to outputs that
// implement [DiagnosticLoggerReceiver].
func (a *Auditor) propagateLogger() {
	for _, oe := range a.entries {
		if recv, ok := oe.output.(DiagnosticLoggerReceiver); ok {
			recv.SetDiagnosticLogger(a.logger)
		}
	}
}

// AuditEvent validates and enqueues a typed audit event. Use
// generated event builders from audit-gen for compile-time field
// safety, or [NewEvent] for dynamic event construction.
//
// AuditEvent returns [ErrQueueFull] if the async buffer is at
// capacity (the event is dropped), [ErrClosed] if the auditor has
// been closed, or a descriptive error for validation failures.
// If the event's category is globally disabled (and no per-event
// override enables it), the event is silently discarded without error.
func (a *Auditor) AuditEvent(evt Event) error {
	if evt == nil {
		return fmt.Errorf("audit: event must not be nil")
	}
	// Fast-path detection: generated builders from cmd/audit-gen emit
	// the unexported donateFields() sentinel to opt into the zero-extra-
	// alloc path. The auditor takes ownership of the donated Fields map
	// (no defensive copy) and merges standard-field defaults in place.
	// Consumer-defined Event types and NewEvent stay on the slow path.
	// See docs/adr/0001-fields-ownership-contract.md (#497).
	_, donated := evt.(FieldsDonor)
	return a.auditInternalDonated(evt.EventType(), evt.Fields(), donated)
}

// auditInternal is the shared validation-and-enqueue path used by
// both [Auditor.AuditEvent] and internal callers. Always treats the
// caller's Fields map as untrusted and defensively copies it.
func (a *Auditor) auditInternal(eventType string, fields Fields) error {
	return a.auditInternalDonated(eventType, fields, false)
}

// auditInternalDonated is the unified internal path that branches
// between the donor fast-path and the defensive-copy slow-path based
// on the donated flag. When donated is true, the caller's Fields map
// is taken as-is (no clone); standard-field defaults are merged in
// place via [mergeDefaultsInPlace].
func (a *Auditor) auditInternalDonated(eventType string, fields Fields, donated bool) error {
	if a.disabled {
		return nil
	}
	if a.closed.Load() {
		return ErrClosed
	}

	if a.metrics != nil {
		a.metrics.RecordSubmitted()
	}

	_, copied, err := a.validateEvent(eventType, fields, donated)
	if err != nil {
		return err
	}

	if !a.filter.isEnabled(eventType, a.taxonomy) {
		if a.metrics != nil {
			a.metrics.RecordFiltered(eventType)
		}
		return nil
	}

	entry, ok := auditEntryPool.Get().(*auditEntry)
	if !ok {
		entry = new(auditEntry)
	}
	entry.eventType = eventType
	entry.fields = copied
	entry.donated = donated

	if a.synchronous {
		a.deliverSync(entry)
		return nil
	}
	return a.enqueue(entry)
}

// validateEvent checks the event type exists, merges standard-field
// defaults (in place for donated, via copy for the slow path), and
// validates field constraints. Returns the definition and the fields
// the drain pipeline will see.
func (a *Auditor) validateEvent(eventType string, fields Fields, donated bool) (*EventDef, Fields, error) {
	def, ok := a.taxonomy.Events[eventType]
	if !ok {
		if a.metrics != nil {
			a.metrics.RecordValidationError(eventType)
		}
		return nil, nil, newValidationError(ErrUnknownEventType, "audit: unknown event type %q", eventType)
	}

	var merged Fields
	if donated {
		// Donor contract: caller guarantees no mutation / no retention
		// after AuditEvent returns. We mutate in place, no clone.
		a.mergeDefaultsInPlace(fields)
		merged = fields
	} else {
		merged = a.copyFieldsWithDefaults(fields)
	}

	if err := a.validateFields(eventType, def, merged); err != nil {
		if a.metrics != nil {
			a.metrics.RecordValidationError(eventType)
		}
		return nil, nil, err
	}

	return def, merged, nil
}

// mergeDefaultsInPlace writes standard-field defaults into fields iff
// the key is not already present. Used only on the donor fast path
// (see [FieldsDonor]); the defensive-copy slow path uses
// [Auditor.copyFieldsWithDefaults] which allocates a fresh map.
func (a *Auditor) mergeDefaultsInPlace(fields Fields) {
	if len(a.standardFieldDefaults) == 0 {
		return
	}
	for k, v := range a.standardFieldDefaults {
		if _, ok := fields[k]; !ok {
			fields[k] = v
		}
	}
}

// deliverSync processes an event inline within AuditEvent for
// synchronous delivery mode. It reuses the same processEntry logic
// as the drain goroutine, including panic recovery and pool return.
// A mutex serialises calls because processEntry reuses per-output
// state (formatOpts, HMAC) that is only safe under single-goroutine
// access.
func (a *Auditor) deliverSync(entry *auditEntry) {
	a.syncMu.Lock()
	defer a.syncMu.Unlock()
	a.processEntry(entry)
}

// enqueue attempts a non-blocking send to the async channel. On
// buffer-full, the entry is returned to the pool to avoid leaking
// pooled objects.
func (a *Auditor) enqueue(entry *auditEntry) error {
	select {
	case a.ch <- entry:
		return nil
	default:
		a.drops.record(dropWarnInterval, func(dropped int64) {
			a.logger.Warn("audit: buffer full, events dropped",
				"dropped", dropped,
				"queue_size", cap(a.ch))
		})
		if a.metrics != nil {
			a.metrics.RecordBufferDrop()
		}
		// Return dropped entry and fields map to pools. Skip pool-
		// return when fields was donated by a [FieldsDonor] — the
		// map belongs to the caller, not our fieldsPool (#497).
		if !entry.donated {
			returnFieldsToPool(entry.fields)
		}
		entry.eventType = ""
		entry.fields = nil
		entry.donated = false
		auditEntryPool.Put(entry)
		return ErrQueueFull
	}
}

// Close shuts down the auditor gracefully. Close MUST be called when the
// auditor is no longer needed; failing to call Close leaks the drain
// goroutine and loses all buffered events.
//
// Close signals the drain goroutine to stop, waits up to
// [Config.ShutdownTimeout] for pending events to flush, then closes all
// outputs in parallel.
//
// Close is idempotent -- subsequent calls return nil (or the same
// error if an output failed to close on the first call).
func (a *Auditor) Close() error {
	a.closeOnce.Do(func() {
		a.closed.Store(true)

		if a.disabled {
			return
		}

		shutdownStart := time.Now()
		a.logger.Info("audit: shutdown started")

		if !a.synchronous {
			a.cancel()
			a.waitForDrain()
		}

		a.closeErr = a.closeOutputs()

		a.logger.Info("audit: shutdown complete",
			"duration", time.Since(shutdownStart))
	})
	return a.closeErr
}

// closeOutputs closes all outputs in parallel. Each output's Close
// runs in its own goroutine. An overall timeout prevents a single
// misbehaving output from blocking shutdown indefinitely.
func (a *Auditor) closeOutputs() error {
	if len(a.entries) == 0 {
		return nil
	}

	type closeResult struct { //nolint:govet // fieldalignment: readability preferred
		name string
		err  error
	}

	results := make(chan closeResult, len(a.entries))
	for _, oe := range a.entries {
		go func(oe *outputEntry) {
			results <- closeResult{
				name: oe.output.Name(),
				err:  oe.output.Close(),
			}
		}(oe)
	}

	// Overall close timeout: drain timeout covers the per-output buffer
	// drain. If any output hangs beyond this, we log and move on.
	closeTimeout := a.cfg.ShutdownTimeout + 5*time.Second
	deadlineTimer := time.NewTimer(closeTimeout)
	defer deadlineTimer.Stop()

	var closeErrs []error
	collected := 0
	for range len(a.entries) {
		select {
		case r := <-results:
			collected++
			if r.err != nil {
				a.logger.Error("audit: output close failed",
					"output", r.name,
					"error", r.err)
				closeErrs = append(closeErrs, fmt.Errorf("audit: output %q: %w", r.name, r.err))
			}
		case <-deadlineTimer.C:
			remaining := len(a.entries) - collected
			a.logger.Error("audit: output close timed out",
				"timeout", closeTimeout,
				"remaining_outputs", remaining)
			closeErrs = append(closeErrs, fmt.Errorf(
				"audit: %d output(s) did not close within %s", remaining, closeTimeout))
			return errors.Join(closeErrs...)
		}
	}

	return errors.Join(closeErrs...)
}

// waitForDrain waits for the drain goroutine to finish, with a
// timeout. No extra goroutine is spawned; we select on the drainDone
// channel that drainLoop closes when it exits.
func (a *Auditor) waitForDrain() {
	timer := time.NewTimer(a.cfg.ShutdownTimeout)
	defer timer.Stop()

	select {
	case <-a.drainDone:
	case <-timer.C:
		a.logger.Warn("audit: drain timed out, some events may be lost",
			"shutdown_timeout", a.cfg.ShutdownTimeout,
			"buffer_remaining", len(a.ch))
	}
}

// validateOutputRoutes checks all per-output event routes and
// sensitivity exclusion labels against the taxonomy.
func (a *Auditor) validateOutputRoutes() error {
	for _, oe := range a.entries {
		route := oe.route.Load()
		if route != nil {
			if err := ValidateEventRoute(route, a.taxonomy); err != nil {
				return fmt.Errorf("audit: output %q: %w", oe.output.Name(), err)
			}
		}
		if err := a.validateExcludeLabels(oe); err != nil {
			return err
		}
	}
	return nil
}

// validateExcludeLabels checks that all exclude_labels on an output
// reference labels defined in the taxonomy's sensitivity config.
func (a *Auditor) validateExcludeLabels(oe *outputEntry) error {
	if len(oe.excludedLabels) == 0 {
		return nil
	}
	if a.taxonomy == nil || a.taxonomy.Sensitivity == nil {
		return fmt.Errorf("audit: output %q has exclude_labels but taxonomy has no sensitivity config",
			oe.output.Name())
	}
	for label := range oe.excludedLabels {
		if _, ok := a.taxonomy.Sensitivity.Labels[label]; !ok {
			return fmt.Errorf("audit: output %q exclude_labels references undefined sensitivity label %q",
				oe.output.Name(), label)
		}
	}
	return nil
}

// EnableCategory enables all events in the named category. The
// category MUST exist in the registered taxonomy. Per-event overrides
// via [Auditor.DisableEvent] take precedence over category state.
func (a *Auditor) EnableCategory(category string) error {
	if a.disabled {
		return fmt.Errorf("audit: cannot enable category on disabled auditor: %w", ErrDisabled)
	}
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := a.taxonomy.Categories[category]; !ok {
		return fmt.Errorf("audit: unknown category %q", category)
	}
	a.filter.enabledCategories.Store(category, true)
	a.logger.Info("audit: category enabled", "category", category)
	return nil
}

// DisableCategory disables all events in the named category. The
// category MUST exist in the registered taxonomy. Per-event overrides
// via [Auditor.EnableEvent] take precedence over category state.
func (a *Auditor) DisableCategory(category string) error {
	if a.disabled {
		return fmt.Errorf("audit: cannot disable category on disabled auditor: %w", ErrDisabled)
	}
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := a.taxonomy.Categories[category]; !ok {
		return fmt.Errorf("audit: unknown category %q", category)
	}
	a.filter.enabledCategories.Store(category, false)
	a.logger.Info("audit: category disabled", "category", category)
	return nil
}

// EnableEvent enables a specific event type regardless of its
// category's state. The event type MUST exist in the registered
// taxonomy. Per-event overrides take precedence over category state.
func (a *Auditor) EnableEvent(eventType string) error {
	if a.disabled {
		return fmt.Errorf("audit: cannot enable event on disabled auditor: %w", ErrDisabled)
	}
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := a.taxonomy.Events[eventType]; !ok {
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}
	a.filter.eventOverrides.Store(eventType, true)
	a.filter.hasEventOverrides.Store(true)
	a.logger.Info("audit: event enabled", "event_type", eventType)
	return nil
}

// DisableEvent disables a specific event type regardless of its
// category's state. The event type MUST exist in the registered
// taxonomy. Per-event overrides take precedence over category state.
func (a *Auditor) DisableEvent(eventType string) error {
	if a.disabled {
		return fmt.Errorf("audit: cannot disable event on disabled auditor: %w", ErrDisabled)
	}
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := a.taxonomy.Events[eventType]; !ok {
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}
	a.filter.eventOverrides.Store(eventType, false)
	a.filter.hasEventOverrides.Store(true)
	a.logger.Info("audit: event disabled", "event_type", eventType)
	return nil
}

// SetOutputRoute sets the per-output event route for the named output.
// The route is validated against the taxonomy; unknown categories or
// event types return an error. Mixed include/exclude routes return an
// error. An unknown output name returns an error.
//
// SetOutputRoute is safe for concurrent use with event delivery.
func (a *Auditor) SetOutputRoute(outputName string, route *EventRoute) error {
	if a.disabled {
		return fmt.Errorf("audit: cannot set output route on disabled auditor: %w", ErrDisabled)
	}
	oe, ok := a.outputsByName[outputName]
	if !ok {
		return fmt.Errorf("audit: unknown output %q", outputName)
	}
	if err := ValidateEventRoute(route, a.taxonomy); err != nil {
		return err
	}
	oe.setRoute(route)
	a.logger.Info("audit: output route set", "output", outputName)
	return nil
}

// ClearOutputRoute removes the per-output event route for the named
// output, causing it to receive all globally-enabled events.
//
// ClearOutputRoute is safe for concurrent use with event delivery.
func (a *Auditor) ClearOutputRoute(outputName string) error {
	oe, ok := a.outputsByName[outputName]
	if !ok {
		return fmt.Errorf("audit: unknown output %q", outputName)
	}
	oe.setRoute(&EventRoute{})
	a.logger.Info("audit: output route cleared", "output", outputName)
	return nil
}

// OutputRoute returns a copy of the current per-output event route
// for the named output. An unknown output name returns an error.
func (a *Auditor) OutputRoute(outputName string) (EventRoute, error) {
	oe, ok := a.outputsByName[outputName]
	if !ok {
		return EventRoute{}, fmt.Errorf("audit: unknown output %q", outputName)
	}
	return oe.getRoute(), nil
}

// Handle returns an [EventHandle] for the named event type. Call
// once at startup (for example during DI wiring), cache the returned
// handle, and emit via [EventHandle.Audit] per event — this avoids
// the per-call basicEvent allocation that [NewEvent] incurs via
// interface escape. Returns [ErrHandleNotFound] if the event type is
// not registered. For event types known at compile time, prefer
// generated typed builders from audit-gen.
func (a *Auditor) Handle(eventType string) (*EventHandle, error) {
	if a.disabled {
		return &EventHandle{name: eventType, auditor: a}, nil
	}
	if _, ok := a.taxonomy.Events[eventType]; !ok {
		return nil, fmt.Errorf("audit: unknown event type %q: %w", eventType, ErrHandleNotFound)
	}
	return &EventHandle{name: eventType, auditor: a}, nil
}

// MustHandle returns an [EventHandle] for the named event type.
// It panics with an error wrapping [ErrHandleNotFound] if the event
// type is not registered. Use [Auditor.Handle] to receive the error
// instead of panicking.
func (a *Auditor) MustHandle(eventType string) *EventHandle {
	h, err := a.Handle(eventType)
	if err != nil {
		panic(err)
	}
	return h
}

// returnFieldsToPool clears a Fields map and returns it to the pool.
// Safe to call with nil (no-op).
func returnFieldsToPool(fields Fields) {
	if fields != nil {
		clear(fields)
		fieldsPool.Put(fields)
	}
}

// copyFieldsWithDefaults creates a merged copy of fields + standard field
// defaults. Standard field defaults have lower precedence (key existence,
// not zero value). This avoids the double allocation that would result
// from separate copy + merge steps.
func (a *Auditor) copyFieldsWithDefaults(fields Fields) Fields {
	size := len(fields) + len(a.standardFieldDefaults)
	if size == 0 {
		return nil
	}
	cp := fieldsPool.Get().(Fields) //nolint:forcetypeassert // pool New always returns Fields
	clear(cp)
	for k, v := range fields {
		cp[k] = v
	}
	for k, v := range a.standardFieldDefaults {
		if _, exists := cp[k]; !exists {
			cp[k] = v
		}
	}
	return cp
}
