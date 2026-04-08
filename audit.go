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
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"strings"
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
	drops                 dropLimiter // rate-limits buffer-full slog.Warn
}

// NewLogger creates a new audit [Logger] with the given configuration
// and options. A taxonomy MUST be provided via [WithTaxonomy];
// NewLogger returns an error if none is supplied.
//
// When [Config.Enabled] is false, NewLogger returns a valid no-op
// logger. All [Logger.AuditEvent] calls return nil immediately without
// validation or delivery.
//
// NewLogger MUST NOT return a non-nil *Logger when cfg or the taxonomy
// is invalid. Config version migration runs before validation; a zero
// [Config.Version] returns an error wrapping [ErrConfigInvalid].
func NewLogger(cfg Config, opts ...Option) (*Logger, error) {
	if err := migrateConfig(&cfg); err != nil {
		return nil, err
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	l := &Logger{cfg: cfg}

	for _, opt := range opts {
		if err := opt(l); err != nil {
			return nil, err
		}
	}

	// Release construction-only state.
	l.destKeys = nil

	if l.taxonomy == nil {
		return nil, fmt.Errorf("audit: taxonomy is required: use WithTaxonomy")
	}

	if err := l.validateOutputRoutes(); err != nil {
		return nil, err
	}

	l.prepareOutputEntries()

	// Default formatter if WithFormatter was not called.
	if l.formatter == nil {
		l.formatter = &JSONFormatter{OmitEmpty: cfg.OmitEmpty}
	}

	// Capture PID and timezone once at construction.
	l.pid = os.Getpid()
	if l.timezone == "" {
		l.timezone = time.Now().Location().String()
	}

	// Propagate framework fields to all formatters that support them.
	l.propagateFrameworkFields()

	if !cfg.Enabled {
		return l, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	l.ch = make(chan *auditEntry, cfg.BufferSize)
	l.drainDone = make(chan struct{})
	go l.drainLoop(ctx)

	slog.Info("audit: logger created",
		"buffer_size", cfg.BufferSize,
		"drain_timeout", cfg.DrainTimeout,
		"validation_mode", string(cfg.ValidationMode),
		"outputs", len(l.entries),
	)

	return l, nil
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
	if !l.cfg.Enabled {
		return nil
	}
	if l.closed.Load() {
		return ErrClosed
	}

	def, ok := l.taxonomy.Events[eventType]
	if !ok {
		if l.metrics != nil {
			l.metrics.RecordValidationError(eventType)
		}
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}

	// Copy fields and merge defaults in one pass to avoid double
	// allocation. The copy isolates the caller's map from the drain
	// goroutine; defaults are applied into the copy so that they
	// satisfy required: true validation without mutating the original.
	copied := l.copyFieldsWithDefaults(fields)

	if err := l.validateFields(eventType, def, copied); err != nil {
		if l.metrics != nil {
			l.metrics.RecordValidationError(eventType)
		}
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
	return l.enqueue(entry)
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
			slog.Warn("audit: buffer full, events dropped",
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

		if !l.cfg.Enabled {
			return
		}

		shutdownStart := time.Now()
		slog.Info("audit: shutdown started")

		l.cancel()
		l.waitForDrain()

		var closeErrs []error
		for _, oe := range l.entries {
			if err := oe.output.Close(); err != nil {
				slog.Error("audit: output close failed",
					"output", oe.output.Name(),
					"error", err)
				closeErrs = append(closeErrs, fmt.Errorf("audit: output %q: %w", oe.output.Name(), err))
			}
		}
		l.closeErr = errors.Join(closeErrs...)

		slog.Info("audit: shutdown complete",
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
		slog.Warn("audit: drain timed out, some events may be lost",
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
	slog.Info("audit: category enabled", "category", category)
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
	slog.Info("audit: category disabled", "category", category)
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
	slog.Info("audit: event enabled", "event_type", eventType)
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
	slog.Info("audit: event disabled", "event_type", eventType)
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
	slog.Info("audit: output route set", "output", outputName)
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
	slog.Info("audit: output route cleared", "output", outputName)
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

// Handle returns an [EventType] handle for the named event type. The
// handle enables zero-allocation audit calls. Returns
// [ErrHandleNotFound] if the event type is not registered.
func (l *Logger) Handle(eventType string) (*EventType, error) {
	if _, ok := l.taxonomy.Events[eventType]; !ok {
		return nil, fmt.Errorf("audit: unknown event type %q: %w", eventType, ErrHandleNotFound)
	}
	return &EventType{name: eventType, logger: l}, nil
}

// MustHandle returns an [EventType] handle for the named event type.
// It panics with an error wrapping [ErrHandleNotFound] if the event
// type is not registered. Use [Logger.Handle] to receive the error
// instead of panicking.
func (l *Logger) MustHandle(eventType string) *EventType {
	h, err := l.Handle(eventType)
	if err != nil {
		panic(err)
	}
	return h
}

// drainLoop is the single goroutine that reads events from the async
// channel, serialises them, and fans out to all outputs.
func (l *Logger) drainLoop(ctx context.Context) {
	defer close(l.drainDone)
	defer slog.Debug("audit: drain loop exiting")
	slog.Debug("audit: drain loop started")
	for {
		select {
		case entry := <-l.ch:
			if entry != nil {
				l.processEntry(entry)
			}
		case <-ctx.Done():
			l.drainRemaining()
			return
		}
	}
}

// drainRemaining flushes any events left in the channel after the
// context is cancelled.
func (l *Logger) drainRemaining() {
	for {
		select {
		case entry := <-l.ch:
			if entry != nil {
				l.processEntry(entry)
			}
		default:
			return
		}
	}
}

// processEntry fans out an audit entry to all matching outputs. Events
// are serialised once per unique Formatter; per-output routes are
// checked before delivery. Output failures are isolated.
func (l *Logger) processEntry(entry *auditEntry) {
	// Defers execute LIFO. The pool return must happen after the
	// panic recovery, so it is declared first (executes last).
	defer func() {
		entry.eventType = ""
		entry.fields = nil
		auditEntryPool.Put(entry)
	}()
	defer func() {
		if r := recover(); r != nil {
			slog.Error("audit: panic in processEntry",
				"event_type", entry.eventType,
				"panic", r)
			if l.metrics != nil {
				l.metrics.RecordSerializationError(entry.eventType)
			}
		}
	}()

	ts := time.Now()
	def := l.taxonomy.Events[entry.eventType]

	if len(def.Categories) == 0 {
		// Uncategorised event: single pass, no category context.
		var fc formatCache
		l.deliverToOutputs(entry, "", ts, def, &fc)
		return
	}

	// Categorised event: deliver once per enabled category.
	// If EnableEvent was called, iterate ALL categories.
	// The atomic flag guards the sync.Map lookup on the hot path.
	eventForceEnabled := false
	if l.filter.hasEventOverrides.Load() {
		if override, ok := l.filter.eventOverrides.Load(entry.eventType); ok && override {
			eventForceEnabled = true
		}
	}

	// Format cache shared across category passes — the formatted
	// output is identical because ResolvedSeverity is a single
	// value per event, not per category.
	var fc formatCache

	for _, category := range def.Categories {
		if !eventForceEnabled && !l.filter.isCategoryEnabled(category) {
			continue
		}
		l.deliverToOutputs(entry, category, ts, def, &fc)
	}
}

// deliverToOutputs fans out a single event to all matching outputs
// for a given category. An empty category means the event is
// uncategorised.
func (l *Logger) deliverToOutputs(entry *auditEntry, category string, ts time.Time, def *EventDef, fc *formatCache) {
	severity := def.ResolvedSeverity()
	meta := EventMetadata{
		EventType: entry.eventType,
		Severity:  severity,
		Category:  category,
		Timestamp: ts,
	}

	for _, oe := range l.entries {
		l.deliverToOutput(oe, entry, category, ts, def, fc, meta)
	}
}

// deliverToOutput handles delivery to a single output with per-output
// panic recovery. A panic in one output's Write (or format/HMAC path)
// does not prevent delivery to subsequent outputs. This is critical
// for the fan-out guarantee: a buggy output must not take down the
// entire delivery pipeline.
func (l *Logger) deliverToOutput(oe *outputEntry, entry *auditEntry, category string, ts time.Time, def *EventDef, fc *formatCache, meta EventMetadata) { //nolint:gocyclo,gocognit,cyclop // per-output delivery with panic recovery
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			slog.Error("audit: panic in output write",
				"output", oe.output.Name(),
				"event_type", entry.eventType,
				"panic", r,
				"stack", string(buf[:n]))
			// Always record the panic in core metrics, even for
			// DeliveryReporter outputs — the output clearly did not
			// self-report if it panicked.
			if l.metrics != nil {
				l.metrics.RecordOutputError(oe.output.Name())
			}
		}
	}()

	if !oe.matchesEvent(entry.eventType, category, meta.Severity) {
		if l.metrics != nil {
			l.metrics.RecordOutputFiltered(oe.output.Name())
		}
		return
	}

	var data []byte
	if oe.formatOpts != nil && def.FieldLabels != nil {
		data = l.formatWithExclusion(oe, entry, ts, def)
	} else {
		data = l.formatCached(oe, entry, ts, def, fc)
	}
	if data == nil {
		return
	}

	// Append event_category if enabled and the event has a category.
	if category != "" && l.taxonomy.EmitEventCategory {
		data = appendEventCategory(data, oe.effectiveFormatter(l.formatter), category)
	}

	// Compute and append HMAC if configured for this output.
	// HMAC is computed over the complete payload at this point
	// (after field stripping + event_category).
	if oe.hmac != nil {
		hmacHex := oe.hmac.computeHMACFast(data)
		data = AppendPostFields(data, oe.effectiveFormatter(l.formatter), []PostField{
			{JSONKey: "_hmac", CEFKey: "_hmac", Value: string(hmacHex)},
			{JSONKey: "_hmac_v", CEFKey: "_hmacVersion", Value: oe.hmacConfig.SaltVersion},
		})
	}

	var writeErr error
	if oe.metadataWriter != nil {
		writeErr = oe.metadataWriter.WriteWithMetadata(data, meta)
	} else {
		writeErr = oe.output.Write(data)
	}
	l.recordWrite(oe.output.Name(), entry.eventType, oe.selfReports, writeErr)
}

// PostField represents a field appended to serialised bytes after
// format caching. Used for delivery-specific context (category) and
// future features (e.g., HMAC checksum).
type PostField struct {
	// JSONKey is the JSON object key used when appending to JSON output.
	JSONKey string
	// CEFKey is the extension key used when appending to CEF output.
	CEFKey string
	// Value is the string value to emit for this field. Values are
	// escaped automatically (JSON via [WriteJSONString], CEF via cefEscapeExtValue).
	Value string
}

// appendEventCategory appends the event_category field to serialised
// bytes based on the formatter type. Returns the original data
// unchanged for unknown formatter types.
func appendEventCategory(data []byte, formatter Formatter, category string) []byte {
	return AppendPostFields(data, formatter, []PostField{
		{JSONKey: "event_category", CEFKey: "cat", Value: category},
	})
}

// AppendPostFields appends one or more post-serialisation fields to
// cached bytes. The formatter type determines the syntax:
// JSON: ,"key":"val" inserted before }\n
// CEF: key=val inserted before the newline.
func AppendPostFields(data []byte, formatter Formatter, fields []PostField) []byte {
	if len(fields) == 0 || len(data) < 2 {
		return data
	}

	switch formatter.(type) {
	case *JSONFormatter:
		return appendPostFieldsJSON(data, fields)
	case *CEFFormatter:
		return appendPostFieldsCEF(data, fields)
	default:
		return data // unknown formatter — skip silently
	}
}

func appendPostFieldsJSON(data []byte, fields []PostField) []byte {
	// JSON ends with }\n — insert before the closing brace.
	braceIdx := len(data) - 2 // data[len-1] is \n, data[len-2] is }
	if braceIdx < 0 || data[braceIdx] != '}' {
		return data // unexpected format — return unchanged
	}

	// Build the complete output in a pooled buffer using WriteJSONString
	// instead of json.Marshal to avoid per-field allocations.
	buf, ok := jsonBufPool.Get().(*bytes.Buffer)
	if !ok {
		buf = new(bytes.Buffer)
	}
	buf.Reset()
	buf.Write(data[:braceIdx])
	for _, f := range fields {
		buf.WriteByte(',')
		WriteJSONString(buf, f.JSONKey)
		buf.WriteByte(':')
		WriteJSONString(buf, f.Value)
	}
	buf.Write(data[braceIdx:]) // }\n

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	jsonBufPool.Put(buf)
	return result
}

func appendPostFieldsCEF(data []byte, fields []PostField) []byte {
	// CEF ends with \n — insert before the newline.
	nlIdx := len(data) - 1
	if nlIdx < 0 || data[nlIdx] != '\n' {
		return data // unexpected format — return unchanged
	}

	// Build suffix with proper CEF escaping for values.
	var buf bytes.Buffer
	for _, f := range fields {
		buf.WriteByte(' ')
		buf.WriteString(f.CEFKey)
		buf.WriteByte('=')
		buf.WriteString(cefEscapeExtValue(f.Value))
	}
	suffix := buf.Bytes()

	result := make([]byte, 0, len(data)+len(suffix))
	result = append(result, data[:nlIdx]...)
	result = append(result, suffix...)
	result = append(result, '\n')
	return result
}

// prepareOutputEntries initialises derived state on each outputEntry
// after all options are applied: format options, HMAC state, and
// MetadataWriter assertion caching.
func (l *Logger) prepareOutputEntries() {
	for _, oe := range l.entries {
		if mw, ok := oe.output.(MetadataWriter); ok {
			oe.metadataWriter = mw
		}
		if dr, ok := oe.output.(DeliveryReporter); ok {
			oe.selfReports = dr.ReportsDelivery()
		}
		if oe.excludedLabels != nil {
			oe.formatOpts = &FormatOptions{
				ExcludedLabels: oe.excludedLabels,
			}
		}
		if oe.hmacConfig != nil && oe.hmacConfig.Enabled {
			oe.hmac = newHMACState(oe.hmacConfig)
		}
	}
}

// propagateFrameworkFields propagates logger-wide framework
// metadata to all formatters that implement [FrameworkFieldSetter]
// and all outputs that implement [FrameworkFieldReceiver].
func (l *Logger) propagateFrameworkFields() {
	set := func(f Formatter) {
		if setter, ok := f.(FrameworkFieldSetter); ok {
			setter.SetFrameworkFields(l.appName, l.host, l.timezone, l.pid)
		}
	}
	set(l.formatter)
	for _, oe := range l.entries {
		if oe.formatter != nil {
			set(oe.formatter)
		}
		if recv, ok := oe.output.(FrameworkFieldReceiver); ok {
			recv.SetFrameworkFields(l.appName, l.host, l.timezone, l.pid)
		}
	}
}

// formatWithExclusion serialises an event with sensitivity-labelled
// fields excluded. It bypasses the format cache because different
// outputs may exclude different label sets.
func (l *Logger) formatWithExclusion(oe *outputEntry, entry *auditEntry, ts time.Time, def *EventDef) []byte {
	// Safe: drain loop is single-goroutine. FieldLabels is read-only
	// after taxonomy registration; we assign the pointer per-event
	// to avoid allocating a new FormatOptions on every call.
	oe.formatOpts.FieldLabels = def.FieldLabels
	f := oe.effectiveFormatter(l.formatter)
	data, err := f.Format(ts, entry.eventType, entry.fields, def, oe.formatOpts)
	if err != nil {
		slog.Error("audit: format error (filtered)", "event", entry.eventType, "output", oe.output.Name(), "error", err)
		if l.metrics != nil {
			l.metrics.RecordSerializationError(entry.eventType)
		}
		return nil
	}
	return data
}

// formatCacheSize is the number of unique formatters cached on the
// stack before falling back to a heap-allocated map.
const formatCacheSize = 4

// formatCacheEntry pairs a formatter with its serialised output.
type formatCacheEntry struct {
	f    Formatter
	data []byte
}

// formatCache caches serialised output per unique formatter. For
// deployments with <= 4 unique formatters (the vast majority), the
// array is stack-allocated. Falls back to a heap map for larger counts.
type formatCache struct {
	m   map[Formatter][]byte // overflow; nil until needed
	arr [formatCacheSize]formatCacheEntry
	n   int
}

func (c *formatCache) get(f Formatter) ([]byte, bool) {
	for i := range c.n {
		if c.arr[i].f == f {
			return c.arr[i].data, true
		}
	}
	if c.m != nil {
		data, ok := c.m[f]
		return data, ok
	}
	return nil, false
}

func (c *formatCache) put(f Formatter, data []byte) {
	if c.n < formatCacheSize {
		c.arr[c.n] = formatCacheEntry{f: f, data: data}
		c.n++
		return
	}
	if c.m == nil {
		c.m = make(map[Formatter][]byte)
	}
	c.m[f] = data
}

// formatCached returns the serialised bytes for the output's formatter,
// using the cache to avoid redundant serialisation. Returns nil if
// serialisation failed.
func (l *Logger) formatCached(oe *outputEntry, entry *auditEntry, ts time.Time, def *EventDef, cache *formatCache) []byte {
	f := oe.effectiveFormatter(l.formatter)
	if data, ok := cache.get(f); ok {
		return data // may be nil if serialisation failed
	}
	data, err := f.Format(ts, entry.eventType, entry.fields, def, nil)
	if err != nil {
		slog.Error("audit: serialisation failed",
			"event_type", entry.eventType,
			"error", err)
		if l.metrics != nil {
			l.metrics.RecordSerializationError(entry.eventType)
		}
		cache.put(f, nil) // mark as failed
		return nil
	}
	cache.put(f, data)
	return data
}

// recordWrite handles post-write metrics and error logging for both
// the plain Write and MetadataWriter paths. Called once per output per
// event with the result of the write call. No closures, no interface
// dispatch — all parameters are concrete values.
func (l *Logger) recordWrite(outputName, eventType string, selfReports bool, writeErr error) {
	if writeErr != nil {
		slog.Error("audit: output write failed",
			"output", outputName,
			"event_type", eventType,
			"error", writeErr)
		if l.metrics != nil && !selfReports {
			l.metrics.RecordOutputError(outputName)
			l.metrics.RecordEvent(outputName, "error")
		}
		return
	}
	if l.metrics != nil && !selfReports {
		l.metrics.RecordEvent(outputName, "success")
	}
}

// copyFieldsWithDefaults creates a shallow copy of fields and merges
// standard field defaults in a single pass. Per-event values take
// precedence (key existence, not zero value). This avoids the double
// allocation that would result from separate copy + merge steps.
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

// validateFields checks that all required fields are present and no
// unknown fields are included (behavior depends on validation mode).
func (l *Logger) validateFields(eventType string, def *EventDef, fields Fields) error {
	if err := checkRequiredFields(eventType, def, fields); err != nil {
		return err
	}
	return l.checkUnknownFields(eventType, def, fields)
}

// checkRequiredFields returns an error listing any missing required fields.
func checkRequiredFields(eventType string, def *EventDef, fields Fields) error {
	var missing []string
	for _, f := range def.Required {
		if _, ok := fields[f]; !ok {
			missing = append(missing, f)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	slices.Sort(missing)
	return fmt.Errorf("audit: event %q missing required fields: [%s]",
		eventType, strings.Join(missing, ", "))
}

// checkUnknownFields validates unknown fields per the validation mode.
func (l *Logger) checkUnknownFields(eventType string, def *EventDef, fields Fields) error {
	if l.cfg.ValidationMode == ValidationPermissive {
		return nil
	}

	known := effectiveKnownFields(def)
	var unknown []string
	for k := range fields {
		if _, ok := known[k]; !ok && !isReservedStandardField(k) {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) == 0 {
		return nil
	}

	slices.Sort(unknown)

	switch l.cfg.ValidationMode {
	case ValidationStrict:
		return fmt.Errorf("audit: event %q has unknown fields: [%s]",
			eventType, strings.Join(unknown, ", "))
	case ValidationWarn:
		slog.Warn("audit: event has unknown fields",
			"event_type", eventType,
			"unknown_fields", unknown)
	case ValidationPermissive:
		// Unreachable: early return at function entry guards this case.
		// Kept to satisfy exhaustive switch linter.
	}
	return nil
}

// isZeroValue reports whether v is a zero value for its type. It uses
// a type switch for common types to avoid reflection overhead and
// panics. Unknown types fall back to a non-nil check only.
//
//nolint:cyclop,gocyclo // flat type switch over primitive types; linear structure, not true branch complexity
func isZeroValue(v any) bool {
	if v == nil {
		return true
	}
	switch val := v.(type) {
	case string:
		return val == ""
	case bool:
		return !val
	case int:
		return val == 0
	case int64:
		return val == 0
	case float64:
		return val == 0
	case int32:
		return val == 0
	case float32:
		return val == 0
	case uint:
		return val == 0
	case uint64:
		return val == 0
	default:
		// For slices, maps, funcs, and other complex types, we only
		// check nil. We do not use reflect to avoid panics on types
		// like func or chan.
		return false
	}
}
