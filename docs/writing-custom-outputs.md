# Writing Custom Outputs

This guide explains how to implement a custom audit output for go-audit.

## Interface Hierarchy

Every output implements the base `audit.Output` interface. Additional
optional interfaces add capabilities:

```
Output (required)
├── MetadataWriter      — receive structured event metadata (type, severity, category)
├── FrameworkFieldReceiver — receive app_name, host, timezone, pid at startup
├── LoggerReceiver      — receive the library's slog.Logger for diagnostics
├── DestinationKeyer    — prevent duplicate outputs to the same destination
└── DeliveryReporter    — handle delivery metrics internally (for batching outputs)
```

## Decision Tree

| Question | Interface |
|----------|-----------|
| Do you need event type, severity, or category? | Implement `MetadataWriter` |
| Do you need app_name/host for labelling? | Implement `FrameworkFieldReceiver` |
| Do you want the library's diagnostic logger? | Implement `LoggerReceiver` |
| Can two outputs point to the same destination? | Implement `DestinationKeyer` |
| Does your output batch and report its own metrics? | Implement `DeliveryReporter` |

## Minimal Output

A minimal output implements only the `Output` interface:

```go
type MyOutput struct {
    name string
    mu   sync.Mutex
}

func (o *MyOutput) Name() string      { return o.name }
func (o *MyOutput) Write(data []byte) error {
    o.mu.Lock()
    defer o.mu.Unlock()
    // Write data to your destination
    return nil
}
func (o *MyOutput) Close() error { return nil }
```

Register it via a factory:

```go
func init() {
    audit.RegisterOutputFactory("my-output", func(name string, rawConfig []byte, metrics audit.Metrics) (audit.Output, error) {
        return audit.WrapOutput(&MyOutput{name: name}, name), nil
    })
}
```

## Adding MetadataWriter

If your output needs event type or severity for routing or labelling:

```go
func (o *MyOutput) WriteWithMetadata(data []byte, meta audit.EventMetadata) error {
    // meta.EventType, meta.Severity, meta.Category, meta.Timestamp available
    return o.Write(data)
}
```

When an output implements `MetadataWriter`, the library calls
`WriteWithMetadata` instead of `Write`.

## Thread Safety

All output methods (`Write`, `WriteWithMetadata`, `Close`) may be called
concurrently from the drain goroutine. Use a `sync.Mutex` to protect
shared state. In synchronous delivery mode (`WithSynchronousDelivery`),
calls are serialised by the library's internal mutex.
