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
// DrainTimeout for pending events to flush, then closes all outputs in
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

// Logger is the core audit logger. It validates events against a
// registered [Taxonomy], filters by category and per-event overrides,
// and delivers events asynchronously to configured [Output]
// destinations.
//
// The library uses [log/slog] for internal diagnostics (buffer drops,
// serialisation failures, output write errors). Consumers can configure
// the slog default handler to control this output.
//
// A Logger is safe for concurrent use by multiple goroutines.
//
//nolint:govet // field order: logical grouping over alignment optimisation
type Logger struct {
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
	// disabled is set by WithDisabled to create a no-op logger that
	// discards all events without validation or delivery. Replaces
	// the former Config.Enabled field (inverted: disabled=true means
	// the logger does nothing).
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
}

// NewLogger creates a new audit [Logger] from the given options.
// A taxonomy MUST be provided via [WithTaxonomy]; NewLogger returns
// an error if none is supplied.
//
// The zero-value [Config] is valid: buffer=10,000, drain=5s,
// validation=strict. Pass tuning options like [WithBufferSize] or
// [WithDrainTimeout] to override defaults, or [WithConfig] to apply
// a struct.
//
// When [WithDisabled] is applied, NewLogger returns a valid no-op
// logger. All [Logger.AuditEvent] calls return nil immediately without
// validation or delivery.
func NewLogger(opts ...Option) (*Logger, error) {
	l := &Logger{}

	for _, opt := range opts {
		if err := opt(l); err != nil {
			return nil, err
		}
	}

	// validateConfig calls applyDefaults internally, then validates.
	// migrateConfig runs after defaults so version is always set.
	if err := validateConfig(&l.cfg); err != nil {
		return nil, err
	}
	if err := migrateConfig(&l.cfg); err != nil {
		return nil, err
	}

	// Release construction-only state.
	l.destKeys = nil

	if l.logger == nil {
		l.logger = slog.Default()
	}

	if l.taxonomy == nil {
		return nil, fmt.Errorf("audit: taxonomy is required: use WithTaxonomy")
	}

	l.applyDevTaxonomyOverrides()

	if err := l.validateOutputRoutes(); err != nil {
		return nil, err
	}

	l.prepareOutputEntries()

	l.applyConstructionDefaults()

	if l.disabled {
		return l, nil
	}

	if !l.synchronous {
		ctx, cancel := context.WithCancel(context.Background())
		l.cancel = cancel
		l.ch = make(chan *auditEntry, l.cfg.BufferSize)
		l.drainDone = make(chan struct{})
		go l.drainLoop(ctx)
	}

	l.logger.Info("audit: logger created",
		"buffer_size", l.cfg.BufferSize,
		"drain_timeout", l.cfg.DrainTimeout,
		"validation_mode", string(l.cfg.ValidationMode),
		"outputs", len(l.entries),
		"synchronous", l.synchronous,
	)

	return l, nil
}

// applyDevTaxonomyOverrides warns about DevTaxonomy and forces permissive
// validation mode when a dev taxonomy is used.
func (l *Logger) applyDevTaxonomyOverrides() {
	if l.taxonomy == nil || !l.taxonomy.dev {
		return
	}
	l.logger.Warn("audit: using DevTaxonomy — not suitable for production; all event types accepted without schema enforcement")
	if l.cfg.ValidationMode == ValidationStrict {
		l.cfg.ValidationMode = ValidationPermissive
	}
}

// applyConstructionDefaults sets formatter, PID, timezone, and propagates
// framework fields. Called once during NewLogger after all options are applied.
func (l *Logger) applyConstructionDefaults() {
	if l.formatter == nil {
		l.formatter = &JSONFormatter{OmitEmpty: l.cfg.OmitEmpty}
	}
	l.pid = os.Getpid()
	if l.timezone == "" {
		l.timezone = time.Now().Location().String()
	}
	l.propagateFrameworkFields()
}

// AuditEvent validates and enqueues a typed audit event. Use
// generated event builders from audit-gen for compile-time field
// safety, or [NewEvent] for dynamic event construction.
//
// AuditEvent returns [ErrBufferFull] if the async buffer is at
// capacity (the event is dropped), [ErrClosed] if the logger has
// been closed, or a descriptive error for validation failures.
// If the event's category is globally disabled (and no per-event
// override enables it), the event is silently discarded without error.
func (l *Logger) AuditEvent(evt Event) error {
	if evt == nil {
		return fmt.Errorf("audit: event must not be nil")
	}
	return l.auditInternal(evt.EventType(), evt.Fields())
}

// auditInternal is the shared validation-and-enqueue path used by
// both [Logger.AuditEvent] and internal callers.
func (l *Logger) auditInternal(eventType string, fields Fields) error {
	if l.disabled {
		return nil
	}
	if l.closed.Load() {
		return ErrClosed
	}

	_, copied, err := l.validateEvent(eventType, fields)
	if err != nil {
		return err
	}

	if !l.filter.isEnabled(eventType, l.taxonomy) {
		if l.metrics != nil {
			l.metrics.RecordFiltered(eventType)
		}
		return nil
	}

	entry, ok := auditEntryPool.Get().(*auditEntry)
	if !ok {
		entry = new(auditEntry)
	}
	entry.eventType = eventType
	entry.fields = copied

	if l.synchronous {
		l.deliverSync(entry)
		return nil
	}
	return l.enqueue(entry)
}

// validateEvent checks the event type exists, copies fields with defaults,
// and validates field constraints. Returns the definition and copied fields.
func (l *Logger) validateEvent(eventType string, fields Fields) (*EventDef, Fields, error) {
	def, ok := l.taxonomy.Events[eventType]
	if !ok {
		if l.metrics != nil {
			l.metrics.RecordValidationError(eventType)
		}
		return nil, nil, newValidationError(ErrUnknownEventType, "audit: unknown event type %q", eventType)
	}

	copied := l.copyFieldsWithDefaults(fields)

	if err := l.validateFields(eventType, def, copied); err != nil {
		if l.metrics != nil {
			l.metrics.RecordValidationError(eventType)
		}
		return nil, nil, err
	}

	return def, copied, nil
}

// deliverSync processes an event inline within AuditEvent for
// synchronous delivery mode. It reuses the same processEntry logic
// as the drain goroutine, including panic recovery and pool return.
// A mutex serialises calls because processEntry reuses per-output
// state (formatOpts, HMAC) that is only safe under single-goroutine
// access.
func (l *Logger) deliverSync(entry *auditEntry) {
	l.syncMu.Lock()
	defer l.syncMu.Unlock()
	l.processEntry(entry)
}

// enqueue attempts a non-blocking send to the async channel. On
// buffer-full, the entry is returned to the pool to avoid leaking
// pooled objects.
func (l *Logger) enqueue(entry *auditEntry) error {
	select {
	case l.ch <- entry:
		return nil
	default:
		l.drops.record(dropWarnInterval, func(dropped int64) {
			l.logger.Warn("audit: buffer full, events dropped",
				"dropped", dropped,
				"buffer_size", cap(l.ch))
		})
		if l.metrics != nil {
			l.metrics.RecordBufferDrop()
		}
		// Return dropped entry to pool.
		entry.eventType = ""
		entry.fields = nil
		auditEntryPool.Put(entry)
		return ErrBufferFull
	}
}

// Close shuts down the logger gracefully. Close MUST be called when the
// logger is no longer needed; failing to call Close leaks the drain
// goroutine and loses all buffered events.
//
// Close signals the drain goroutine to stop, waits up to
// [Config.DrainTimeout] for pending events to flush, then closes all
// outputs in sequence.
//
// Close is idempotent -- subsequent calls return nil (or the same
// error if an output failed to close on the first call).
func (l *Logger) Close() error {
	l.closeOnce.Do(func() {
		l.closed.Store(true)

		if l.disabled {
			return
		}

		shutdownStart := time.Now()
		l.logger.Info("audit: shutdown started")

		if !l.synchronous {
			l.cancel()
			l.waitForDrain()
		}

		var closeErrs []error
		for _, oe := range l.entries {
			if err := oe.output.Close(); err != nil {
				l.logger.Error("audit: output close failed",
					"output", oe.output.Name(),
					"error", err)
				closeErrs = append(closeErrs, fmt.Errorf("audit: output %q: %w", oe.output.Name(), err))
			}
		}
		l.closeErr = errors.Join(closeErrs...)

		l.logger.Info("audit: shutdown complete",
			"duration", time.Since(shutdownStart))
	})
	return l.closeErr
}

// waitForDrain waits for the drain goroutine to finish, with a
// timeout. No extra goroutine is spawned; we select on the drainDone
// channel that drainLoop closes when it exits.
func (l *Logger) waitForDrain() {
	select {
	case <-l.drainDone:
	case <-time.After(l.cfg.DrainTimeout):
		l.logger.Warn("audit: drain timed out, some events may be lost",
			"drain_timeout", l.cfg.DrainTimeout,
			"buffer_remaining", len(l.ch))
	}
}

// validateOutputRoutes checks all per-output event routes and
// sensitivity exclusion labels against the taxonomy.
func (l *Logger) validateOutputRoutes() error {
	for _, oe := range l.entries {
		route := oe.route.Load()
		if route != nil {
			if err := ValidateEventRoute(route, l.taxonomy); err != nil {
				return fmt.Errorf("audit: output %q: %w", oe.output.Name(), err)
			}
		}
		if err := l.validateExcludeLabels(oe); err != nil {
			return err
		}
	}
	return nil
}

// validateExcludeLabels checks that all exclude_labels on an output
// reference labels defined in the taxonomy's sensitivity config.
func (l *Logger) validateExcludeLabels(oe *outputEntry) error {
	if len(oe.excludedLabels) == 0 {
		return nil
	}
	if l.taxonomy == nil || l.taxonomy.Sensitivity == nil {
		return fmt.Errorf("audit: output %q has exclude_labels but taxonomy has no sensitivity config",
			oe.output.Name())
	}
	for label := range oe.excludedLabels {
		if _, ok := l.taxonomy.Sensitivity.Labels[label]; !ok {
			return fmt.Errorf("audit: output %q exclude_labels references undefined sensitivity label %q",
				oe.output.Name(), label)
		}
	}
	return nil
}

// EnableCategory enables all events in the named category. The
// category MUST exist in the registered taxonomy. Per-event overrides
// via [Logger.DisableEvent] take precedence over category state.
func (l *Logger) EnableCategory(category string) error {
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := l.taxonomy.Categories[category]; !ok {
		return fmt.Errorf("audit: unknown category %q", category)
	}
	l.filter.enabledCategories.Store(category, true)
	l.logger.Info("audit: category enabled", "category", category)
	return nil
}

// DisableCategory disables all events in the named category. The
// category MUST exist in the registered taxonomy. Per-event overrides
// via [Logger.EnableEvent] take precedence over category state.
func (l *Logger) DisableCategory(category string) error {
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := l.taxonomy.Categories[category]; !ok {
		return fmt.Errorf("audit: unknown category %q", category)
	}
	l.filter.enabledCategories.Store(category, false)
	l.logger.Info("audit: category disabled", "category", category)
	return nil
}

// EnableEvent enables a specific event type regardless of its
// category's state. The event type MUST exist in the registered
// taxonomy. Per-event overrides take precedence over category state.
func (l *Logger) EnableEvent(eventType string) error {
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := l.taxonomy.Events[eventType]; !ok {
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}
	l.filter.eventOverrides.Store(eventType, true)
	l.filter.hasEventOverrides.Store(true)
	l.logger.Info("audit: event enabled", "event_type", eventType)
	return nil
}

// DisableEvent disables a specific event type regardless of its
// category's state. The event type MUST exist in the registered
// taxonomy. Per-event overrides take precedence over category state.
func (l *Logger) DisableEvent(eventType string) error {
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := l.taxonomy.Events[eventType]; !ok {
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}
	l.filter.eventOverrides.Store(eventType, false)
	l.filter.hasEventOverrides.Store(true)
	l.logger.Info("audit: event disabled", "event_type", eventType)
	return nil
}

// SetOutputRoute sets the per-output event route for the named output.
// The route is validated against the taxonomy; unknown categories or
// event types return an error. Mixed include/exclude routes return an
// error. An unknown output name returns an error.
//
// SetOutputRoute is safe for concurrent use with event delivery.
func (l *Logger) SetOutputRoute(outputName string, route *EventRoute) error {
	oe, ok := l.outputsByName[outputName]
	if !ok {
		return fmt.Errorf("audit: unknown output %q", outputName)
	}
	if err := ValidateEventRoute(route, l.taxonomy); err != nil {
		return err
	}
	oe.setRoute(route)
	l.logger.Info("audit: output route set", "output", outputName)
	return nil
}

// ClearOutputRoute removes the per-output event route for the named
// output, causing it to receive all globally-enabled events.
//
// ClearOutputRoute is safe for concurrent use with event delivery.
func (l *Logger) ClearOutputRoute(outputName string) error {
	oe, ok := l.outputsByName[outputName]
	if !ok {
		return fmt.Errorf("audit: unknown output %q", outputName)
	}
	oe.setRoute(&EventRoute{})
	l.logger.Info("audit: output route cleared", "output", outputName)
	return nil
}

// OutputRoute returns a copy of the current per-output event route
// for the named output. An unknown output name returns an error.
func (l *Logger) OutputRoute(outputName string) (EventRoute, error) {
	oe, ok := l.outputsByName[outputName]
	if !ok {
		return EventRoute{}, fmt.Errorf("audit: unknown output %q", outputName)
	}
	return oe.getRoute(), nil
}

// Handle returns an [EventHandle] for the named event type. The
// handle enables zero-allocation audit calls. Returns
// [ErrHandleNotFound] if the event type is not registered.
func (l *Logger) Handle(eventType string) (*EventHandle, error) {
	if _, ok := l.taxonomy.Events[eventType]; !ok {
		return nil, fmt.Errorf("audit: unknown event type %q: %w", eventType, ErrHandleNotFound)
	}
	return &EventHandle{name: eventType, logger: l}, nil
}

// MustHandle returns an [EventHandle] for the named event type.
// It panics with an error wrapping [ErrHandleNotFound] if the event
// type is not registered. Use [Logger.Handle] to receive the error
// instead of panicking.
func (l *Logger) MustHandle(eventType string) *EventHandle {
	h, err := l.Handle(eventType)
	if err != nil {
		panic(err)
	}
	return h
}

// copyFieldsWithDefaults creates a merged copy of fields + standard field
// defaults. Standard field defaults have lower precedence (key existence,
// not zero value). This avoids the double allocation that would result
// from separate copy + merge steps.
func (l *Logger) copyFieldsWithDefaults(fields Fields) Fields {
	size := len(fields) + len(l.standardFieldDefaults)
	if size == 0 {
		return nil
	}
	cp := make(Fields, size)
	for k, v := range fields {
		cp[k] = v
	}
	for k, v := range l.standardFieldDefaults {
		if _, exists := cp[k]; !exists {
			cp[k] = v
		}
	}
	return cp
}
