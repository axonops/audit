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

// Architecture: async buffer → single drain goroutine → serialise → fan-out
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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
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

	// ErrBufferFull is returned when the async buffer is at capacity
	// and the event cannot be enqueued.
	ErrBufferFull = errors.New("audit: buffer full")
)

// Logger is the core audit logger. It validates events against a
// registered [Taxonomy], filters by category and per-event overrides,
// and delivers events asynchronously to configured [Output]
// destinations.
//
// A Logger is safe for concurrent use by multiple goroutines.
type Logger struct {
	cfg Config
	// taxonomy is immutable after construction; no synchronisation
	// needed for reads.
	taxonomy *Taxonomy
	outputs  []Output
	metrics  Metrics

	// Async delivery.
	ch     chan *auditEntry
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Shutdown state.
	closeOnce      sync.Once
	closed         atomic.Bool
	startupEmitted atomic.Bool
	closeErr       error
	startupAppName atomic.Value // stores string from EmitStartup

	// Filter state, protected by mu.
	mu     sync.RWMutex
	filter filterState
}

// NewLogger creates a new audit [Logger] with the given configuration
// and options. A taxonomy must be provided via [WithTaxonomy];
// otherwise NewLogger returns an error.
//
// NewLogger validates both the configuration and the taxonomy at
// startup, failing fast with clear errors for any problems.
func NewLogger(cfg Config, opts ...Option) (*Logger, error) {
	if err := migrateConfig(&cfg); err != nil {
		return nil, err
	}
	if err := validateConfig(&cfg); err != nil {
		return nil, err
	}

	l := &Logger{
		cfg: cfg,
	}

	for _, opt := range opts {
		if err := opt(l); err != nil {
			return nil, err
		}
	}

	if l.taxonomy == nil {
		return nil, fmt.Errorf("audit: taxonomy is required — use WithTaxonomy")
	}

	// If disabled, return a valid but inert logger.
	if !cfg.Enabled {
		return l, nil
	}

	// Start async delivery.
	ctx, cancel := context.WithCancel(context.Background())
	l.cancel = cancel
	l.ch = make(chan *auditEntry, cfg.BufferSize)
	l.wg.Add(1)
	go l.drainLoop(ctx)

	return l, nil
}

// Audit validates and enqueues an audit event. The event type must be
// registered in the taxonomy and all required fields must be present.
//
// If the event's category is globally disabled (and no per-event
// override enables it), the event is silently discarded without error.
//
// Audit returns an error if the logger is closed, the event type is
// unknown, required fields are missing, or unknown fields are present
// in strict validation mode.
func (l *Logger) Audit(eventType string, fields Fields) error {
	// Fast path: disabled logger.
	if !l.cfg.Enabled {
		return nil
	}

	// Closed check.
	if l.closed.Load() {
		return ErrClosed
	}

	// Look up event definition.
	def, ok := l.taxonomy.Events[eventType]
	if !ok {
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}

	// Validate required fields.
	if err := l.validateFields(eventType, &def, fields); err != nil {
		return err
	}

	// Check global filter.
	l.mu.RLock()
	enabled := l.filter.isEnabled(eventType, l.taxonomy)
	l.mu.RUnlock()
	if !enabled {
		return nil
	}

	// Enqueue.
	entry := &auditEntry{
		eventType: eventType,
		fields:    copyFields(fields),
	}

	select {
	case l.ch <- entry:
		return nil
	default:
		slog.Warn("audit: buffer full, dropping event",
			"event_type", eventType)
		if l.metrics != nil {
			l.metrics.RecordBufferDrop()
		}
		return ErrBufferFull
	}
}

// Close shuts down the logger gracefully. It signals the drain
// goroutine to stop, waits up to [Config.DrainTimeout] for pending
// events to flush, then closes all outputs in sequence.
//
// If [Logger.EmitStartup] was called, Close automatically emits a
// shutdown event before draining.
//
// Close is idempotent — subsequent calls return nil.
func (l *Logger) Close() error {
	l.closeOnce.Do(func() {
		l.closed.Store(true)

		// If not enabled, there is no drain goroutine to stop.
		if !l.cfg.Enabled {
			return
		}

		// Auto-emit shutdown if startup was emitted.
		if l.startupEmitted.Load() {
			l.emitShutdown()
		}

		// Signal drain goroutine to stop.
		l.cancel()

		// Wait with timeout.
		done := make(chan struct{})
		go func() {
			l.wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Drained successfully.
		case <-time.After(l.cfg.DrainTimeout):
			slog.Warn("audit: drain timed out, some events may be lost")
		}

		// Close all outputs in order.
		for _, o := range l.outputs {
			if err := o.Close(); err != nil && l.closeErr == nil {
				l.closeErr = fmt.Errorf("audit: output %q: %w", o.Name(), err)
			}
		}
	})
	return l.closeErr
}

// EnableCategory enables all events in the named category. The
// category must exist in the registered taxonomy.
func (l *Logger) EnableCategory(category string) error {
	if _, ok := l.taxonomy.Categories[category]; !ok {
		return fmt.Errorf("audit: unknown category %q", category)
	}
	l.mu.Lock()
	l.filter.enabledCategories[category] = true
	l.mu.Unlock()
	return nil
}

// DisableCategory disables all events in the named category. The
// category must exist in the registered taxonomy. Per-event overrides
// via [Logger.EnableEvent] take precedence.
func (l *Logger) DisableCategory(category string) error {
	if _, ok := l.taxonomy.Categories[category]; !ok {
		return fmt.Errorf("audit: unknown category %q", category)
	}
	l.mu.Lock()
	l.filter.enabledCategories[category] = false
	l.mu.Unlock()
	return nil
}

// EnableEvent enables a specific event type regardless of its
// category's state. The event type must exist in the registered
// taxonomy.
func (l *Logger) EnableEvent(eventType string) error {
	if _, ok := l.taxonomy.Events[eventType]; !ok {
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}
	l.mu.Lock()
	l.filter.eventOverrides[eventType] = true
	l.mu.Unlock()
	return nil
}

// DisableEvent disables a specific event type regardless of its
// category's state. The event type must exist in the registered
// taxonomy.
func (l *Logger) DisableEvent(eventType string) error {
	if _, ok := l.taxonomy.Events[eventType]; !ok {
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}
	l.mu.Lock()
	l.filter.eventOverrides[eventType] = false
	l.mu.Unlock()
	return nil
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
// It panics if the event type is not registered.
func (l *Logger) MustHandle(eventType string) *EventType {
	h, err := l.Handle(eventType)
	if err != nil {
		panic(err)
	}
	return h
}

// EmitStartup emits a startup lifecycle event. The "app_name" field is
// required. Close will automatically emit a corresponding shutdown
// event if EmitStartup was called, using the same app_name.
func (l *Logger) EmitStartup(fields Fields) error {
	if appName, ok := fields["app_name"]; ok {
		if s, ok := appName.(string); ok {
			l.startupAppName.Store(s)
		}
	}
	l.startupEmitted.Store(true)
	return l.Audit("startup", fields)
}

// emitShutdown enqueues a shutdown lifecycle event directly to the
// channel, bypassing the closed check. It is called by Close before
// the drain goroutine is signalled to stop.
func (l *Logger) emitShutdown() {
	appName := "unknown"
	if v := l.startupAppName.Load(); v != nil {
		appName = v.(string)
	}
	entry := &auditEntry{
		eventType: "shutdown",
		fields:    Fields{"app_name": appName},
	}
	// Non-blocking enqueue — if buffer is full, drop silently.
	select {
	case l.ch <- entry:
	default:
		slog.Warn("audit: buffer full, dropping shutdown event")
	}
}

// drainLoop is the single goroutine that reads events from the async
// channel, serialises them, and fans out to all outputs.
func (l *Logger) drainLoop(ctx context.Context) {
	defer l.wg.Done()
	for {
		select {
		case entry := <-l.ch:
			if entry != nil {
				l.processEntry(entry)
			}
		case <-ctx.Done():
			// Drain remaining events.
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
	}
}

// processEntry serialises an audit entry and writes it to all outputs.
func (l *Logger) processEntry(entry *auditEntry) {
	data, err := l.serialize(entry)
	if err != nil {
		slog.Error("audit: serialisation failed",
			"event_type", entry.eventType,
			"error", err)
		return
	}

	for _, o := range l.outputs {
		if writeErr := o.Write(data); writeErr != nil {
			slog.Error("audit: output write failed",
				"output", o.Name(),
				"event_type", entry.eventType,
				"error", writeErr)
			if l.metrics != nil {
				l.metrics.RecordOutputError(o.Name())
				l.metrics.RecordEvent(o.Name(), "error")
			}
			continue
		}
		if l.metrics != nil {
			l.metrics.RecordEvent(o.Name(), "success")
		}
	}
}

// serialize converts an audit entry to JSON bytes. This is a minimal
// implementation for the core logger; issue #2 adds the full Formatter
// interface with JSON and CEF support.
func (l *Logger) serialize(entry *auditEntry) ([]byte, error) {
	m := make(map[string]interface{}, len(entry.fields)+3)

	if l.cfg.OmitEmpty {
		// Only include non-zero fields.
		for k, v := range entry.fields {
			if !isZeroValue(v) {
				m[k] = v
			}
		}
	} else {
		// Include all registered fields, setting missing ones to nil.
		def := l.taxonomy.Events[entry.eventType]
		for _, f := range def.Required {
			m[f] = entry.fields[f]
		}
		for _, f := range def.Optional {
			m[f] = entry.fields[f]
		}
		// Also include any extra fields the consumer provided.
		for k, v := range entry.fields {
			m[k] = v
		}
	}

	// Framework-provided fields (overwrite consumer values).
	m["timestamp"] = time.Now().Format(time.RFC3339Nano)
	m["event_type"] = entry.eventType

	data, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("audit: json marshal: %w", err)
	}
	return append(data, '\n'), nil
}

// validateFields checks that all required fields are present and no
// unknown fields are included (behavior depends on validation mode).
func (l *Logger) validateFields(eventType string, def *EventDef, fields Fields) error {
	// Check required fields.
	var missing []string
	for _, f := range def.Required {
		if _, ok := fields[f]; !ok {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("audit: event %q missing required fields: [%s]",
			eventType, strings.Join(missing, ", "))
	}

	// Check for unknown fields.
	if l.cfg.ValidationMode == ValidationPermissive {
		return nil
	}

	known := make(map[string]bool, len(def.Required)+len(def.Optional))
	for _, f := range def.Required {
		known[f] = true
	}
	for _, f := range def.Optional {
		known[f] = true
	}

	var unknown []string
	for k := range fields {
		if !known[k] {
			unknown = append(unknown, k)
		}
	}

	if len(unknown) > 0 {
		sort.Strings(unknown)
		msg := fmt.Sprintf("audit: event %q has unknown fields: [%s]",
			eventType, strings.Join(unknown, ", "))

		switch l.cfg.ValidationMode {
		case ValidationStrict:
			return errors.New(msg)
		case ValidationWarn:
			slog.Warn(msg)
		}
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

// isZeroValue reports whether v is a zero value for its type. It
// handles nil, empty strings, zero numbers, and false booleans.
func isZeroValue(v interface{}) bool {
	if v == nil {
		return true
	}
	return reflect.ValueOf(v).IsZero()
}
