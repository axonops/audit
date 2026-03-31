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
// Audit() validates the event against the registered taxonomy, checks
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
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Sentinel errors returned by Logger methods.
var (
	// ErrClosed is returned by [Logger.Audit] when the logger has
	// been closed.
	ErrClosed = errors.New("audit: logger is closed")

	// ErrBufferFull is returned by [Logger.Audit] when the async buffer
	// is at capacity and the event is dropped. Callers SHOULD treat
	// this as a drop notification. Increasing [Config.BufferSize] or
	// reducing event emission rate will reduce frequency.
	ErrBufferFull = errors.New("audit: buffer full")

	// ErrDuplicateDestination is returned by [WithOutputs] or
	// [WithNamedOutput] when two outputs implement [DestinationKeyer]
	// and return the same key.
	ErrDuplicateDestination = errors.New("audit: duplicate destination")
)

// auditEntryPool caches auditEntry instances to avoid per-Audit heap
// allocation. Entries are retrieved in Audit(), sent through the
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
	startupAppName atomic.Value
	closeErr       error
	filter         *filterState
	metrics        Metrics
	formatter      Formatter
	ch             chan *auditEntry
	taxonomy       *Taxonomy
	cancel         context.CancelFunc
	drainDone      chan struct{}
	// entries and outputsByName are immutable after construction.
	entries        []*outputEntry
	outputsByName  map[string]*outputEntry
	cfg            Config
	closeOnce      sync.Once
	closed         atomic.Bool
	startupEmitted atomic.Bool
	// destKeys tracks destination keys during construction to detect
	// duplicate output destinations. Only used by WithNamedOutput;
	// WithOutputs uses a local map.
	destKeys map[string]string
	// usedWithOutputs is set during construction when WithOutputs is
	// applied; prevents mixing WithOutputs and WithNamedOutput.
	usedWithOutputs bool
}

// NewLogger creates a new audit [Logger] with the given configuration
// and options. A taxonomy MUST be provided via [WithTaxonomy];
// NewLogger returns an error if none is supplied.
//
// When [Config.Enabled] is false, NewLogger returns a valid no-op
// logger. All [Logger.Audit] calls return nil immediately without
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

	// Default formatter if WithFormatter was not called.
	if l.formatter == nil {
		l.formatter = &JSONFormatter{OmitEmpty: cfg.OmitEmpty}
	}

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

// Audit validates and enqueues an audit event. The event type must be
// registered in the taxonomy and all required fields must be present.
//
// If the event's category is globally disabled (and no per-event
// override enables it), the event is silently discarded without error.
//
// Audit returns [ErrBufferFull] if the async buffer is at capacity
// (the event is dropped), [ErrClosed] if the logger has been closed,
// or a descriptive error for validation failures.
func (l *Logger) Audit(eventType string, fields Fields) error {
	if !l.cfg.Enabled {
		return nil
	}
	if l.closed.Load() {
		return ErrClosed
	}

	// taxonomy is immutable after construction; safe to read without lock.
	def, ok := l.taxonomy.Events[eventType]
	if !ok {
		if l.metrics != nil {
			l.metrics.RecordValidationError(eventType)
		}
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}

	if err := l.validateFields(eventType, def, fields); err != nil {
		// Only strict-mode rejections are validation errors. Warn-mode
		// unknown fields return nil (event accepted) and are observable
		// only via slog -- they are not validation errors.
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
	entry.fields = copyFields(fields)
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
		slog.Warn("audit: buffer full, dropping event",
			"event_type", entry.eventType,
			"buffer_size", l.cfg.BufferSize)
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
// outputs in sequence. If [Logger.EmitStartup] was called, Close
// automatically emits a shutdown event before draining.
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

		if l.startupEmitted.Load() {
			l.emitShutdown()
		}

		l.cancel()
		l.waitForDrain()

		for _, oe := range l.entries {
			if err := oe.output.Close(); err != nil {
				slog.Error("audit: output close failed",
					"output", oe.output.Name(),
					"error", err)
				if l.closeErr == nil {
					l.closeErr = fmt.Errorf("audit: output %q: %w", oe.output.Name(), err)
				}
			}
		}

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

// validateOutputRoutes checks all per-output event routes against
// the taxonomy.
func (l *Logger) validateOutputRoutes() error {
	for _, oe := range l.entries {
		route := oe.route.Load()
		if route == nil {
			continue
		}
		if err := ValidateEventRoute(route, l.taxonomy); err != nil {
			return fmt.Errorf("audit: output %q: %w", oe.output.Name(), err)
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

// EmitStartup emits a startup lifecycle event. The "app_name" field
// is required by the default lifecycle taxonomy; omitting it returns a
// validation error. [Logger.Close] will automatically emit a
// corresponding shutdown event only if EmitStartup returned nil; a
// failed EmitStartup (validation error, [ErrBufferFull], or
// [ErrClosed]) leaves the shutdown flag unset and Close will not
// emit a shutdown event.
//
// EmitStartup MUST be called before [Logger.Close]; calling it after
// returns [ErrClosed]. On a disabled logger (where [Config.Enabled] is
// false), EmitStartup returns nil immediately and no shutdown event
// will be emitted by Close.
func (l *Logger) EmitStartup(fields Fields) error {
	if err := l.Audit("startup", fields); err != nil {
		return err
	}
	if appName, ok := fields["app_name"]; ok {
		if s, ok := appName.(string); ok {
			l.startupAppName.Store(s)
		}
	}
	l.startupEmitted.Store(true)
	return nil
}

// emitShutdown enqueues a shutdown lifecycle event directly to the
// channel, bypassing the closed check and field validation. This is
// intentional: the framework controls the shutdown event's fields
// and the logger is already in the process of shutting down.
//
// It is called by Close before the drain goroutine is signalled to
// stop, ensuring the event is in the channel before cancel() fires.
func (l *Logger) emitShutdown() {
	appName := "unknown"
	if v := l.startupAppName.Load(); v != nil {
		if s, ok := v.(string); ok {
			appName = s
		}
	}
	entry, ok := auditEntryPool.Get().(*auditEntry)
	if !ok {
		entry = new(auditEntry)
	}
	entry.eventType = "shutdown"
	entry.fields = Fields{"app_name": appName}
	select {
	case l.ch <- entry:
	default:
		entry.eventType = ""
		entry.fields = nil
		auditEntryPool.Put(entry)
		slog.Warn("audit: buffer full, dropping shutdown event",
			"buffer_size", l.cfg.BufferSize)
		if l.metrics != nil {
			l.metrics.RecordBufferDrop()
		}
	}
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
		// Uncategorised event: deliver to outputs matching by event
		// type or with no route. Single pass, no category context.
		var fc formatCache
		for _, oe := range l.entries {
			if !oe.matchesEvent(entry.eventType, "") {
				if l.metrics != nil {
					l.metrics.RecordOutputFiltered(oe.output.Name())
				}
				continue
			}

			data := l.formatCached(oe, entry, ts, def, &fc)
			if data == nil {
				continue
			}
			l.writeToOutput(oe.output, data, entry.eventType)
		}
	} else {
		// Categorised event: deliver once per enabled category.
		// Each category pass is independent — an output may receive
		// the event multiple times on different category passes.
		//
		// If EnableEvent was called for this event, iterate ALL
		// categories regardless of their enabled/disabled state.
		eventForceEnabled := false
		if override, ok := l.filter.eventOverrides.Load(entry.eventType); ok && override {
			eventForceEnabled = true
		}

		// Format cache shared across category passes — the formatted
		// output is identical because ResolvedSeverity is a single
		// value per event, not per category.
		var fc formatCache

		for _, category := range def.Categories {
			if !eventForceEnabled && !l.filter.isCategoryEnabled(category) {
				continue
			}

			for _, oe := range l.entries {
				if !oe.matchesEvent(entry.eventType, category) {
					if l.metrics != nil {
						l.metrics.RecordOutputFiltered(oe.output.Name())
					}
					continue
				}

				data := l.formatCached(oe, entry, ts, def, &fc)
				if data == nil {
					continue
				}
				l.writeToOutput(oe.output, data, entry.eventType)
			}
		}
	}
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
	data, err := f.Format(ts, entry.eventType, entry.fields, def)
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

// writeToOutput sends data to a single output and records metrics.
func (l *Logger) writeToOutput(o Output, data []byte, eventType string) {
	// Check if this output reports its own delivery metrics.
	selfReports := false
	if dr, ok := o.(DeliveryReporter); ok {
		selfReports = dr.ReportsDelivery()
	}

	if writeErr := o.Write(data); writeErr != nil {
		slog.Error("audit: output write failed",
			"output", o.Name(),
			"event_type", eventType,
			"error", writeErr)
		if l.metrics != nil && !selfReports {
			l.metrics.RecordOutputError(o.Name())
			l.metrics.RecordEvent(o.Name(), "error")
		}
		return
	}
	if l.metrics != nil && !selfReports {
		l.metrics.RecordEvent(o.Name(), "success")
	}
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
		if _, ok := known[k]; !ok {
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
		// Silently accept unknown fields.
	}
	return nil
}

// copyFields creates a shallow copy of the fields map to avoid data
// races when the caller modifies the map after Audit returns.
func copyFields(fields Fields) Fields {
	if fields == nil {
		return nil
	}
	cp := make(Fields, len(fields))
	for k, v := range fields {
		cp[k] = v
	}
	return cp
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
