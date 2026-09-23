# Tetragon Receiver

Reads eBPF security and observability events from the [Cilium Tetragon](https://tetragon.io/) daemon over gRPC and converts them to OpenTelemetry logs.

| Status        |           |
| ------------- |-----------|
| Stability     | [development]: logs   |
| Distributions | [] |
| [Code Owners](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/CONTRIBUTING.md#becoming-a-code-owner)    |  |

[development]: https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/component-stability.md#development

## Usage

Add to an OpenTelemetry Collector Builder manifest:

```yaml
receivers:
  - gomod: github.com/fastly/tetragon-receiver v0.0.1
```

## Supported Pipelines

- Logs

## Configuration

> ⚠️ **Sensitive data**: Tetragon events can include process command lines, which may contain passwords, tokens, or other secrets. Use `field_filters` (server-side) or OTel processors (downstream) to redact or remove `process.arguments` before exporting logs. See [Field Filtering](#field-filtering) below.

Required:

- `endpoint`: Tetragon daemon gRPC target. Defaults to `unix:///var/run/cilium/tetragon/tetragon.sock`.

Optional:

- `tls`: Standard TLS client config (CA, certificate, key, mTLS). Required for TCP endpoints. The default `unix://` endpoint uses filesystem permissions for transport security and sets `tls.insecure: true` by default.
- `buffer_size`: Size of the channel between the gRPC reader and the mapper workers. Default: `10000`.
- `workers`: Goroutines that drain the channel, convert events to `plog.Logs`, and call `ConsumeLogs`. Default: `4`.
- `field_filters`: Protobuf field masks applied server-side by Tetragon to redact specific fields.
- `max_recv_msg_size_mib`: Maximum gRPC message size accepted from Tetragon. Default: `2`. Peak receive buffer memory is approximately `buffer_size × max_recv_msg_size_mib`.

### Field Filtering

`field_filters` removes sensitive fields from events server-side. This is the only filtering mechanism available on the gRPC stream.

Per [Tetragon documentation](https://tetragon.io/docs/concepts/events/), event-level filtering (AllowList/DenyList) only applies to JSON file exports, not to gRPC streams. For event-level filtering in the OpenTelemetry Collector, use the [Filter processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/filterprocessor/README.md) with log attribute matching.

### Example: Field Redaction

`field_filters` tells Tetragon to omit a field before it is sent over the gRPC stream. Use this for server-side removal of sensitive data such as command-line arguments:

```yaml
receivers:
  tetragon:
    endpoint: "unix:///var/run/cilium/tetragon/tetragon.sock"
    field_filters:
      - event_set: ["PROCESS_EXEC"]
        fields: ["process.arguments"]
        action: "EXCLUDE"
```

This works for any field path Tetragon supports. For Tetragon custom trace policies (e.g., `process_kprobe` policies you define), replace `PROCESS_EXEC` with the matching event set and use the field path declared in the policy.

### Example: Redaction in the Collector Pipeline

For downstream edits after the receiver has emitted the log, use OTel processors. A common pattern is to delete, mask, or drop based on `process.command_line`.

#### Delete a field

```yaml
processors:
  attributes/delete_command_line:
    actions:
      - key: process.command_line
        action: delete
```

#### Mask a sensitive value

```yaml
processors:
  attributes/mask_command_line:
    actions:
      - key: process.command_line
        pattern: "^([^\\s]+)(\\s+.*)?$"
        value: "$1 <redacted>"
        action: extract
```

This keeps the executable path and replaces the arguments.

#### Discard an entire log

```yaml
processors:
  filter/drop_sensitive:
    logs:
      exclude:
        match_type: regexp
        record_attributes:
          - key: process.command_line
            value: "password|token|secret"
```

### Example: Event-Level Filtering via OTel Processor

To filter events by namespace or process name, configure the [Filter processor](https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/main/processor/filterprocessor/README.md):

```yaml
receivers:
  tetragon:
    endpoint: "unix:///var/run/cilium/tetragon/tetragon.sock"

processors:
  filter:
    logs:
      include:
        match_type: regexp
        record_attributes:
          - key: k8s.namespace.name
            value: "^(prod|payments)$"
      exclude:
        match_type: regexp
        record_attributes:
          - key: process.executable.path
            value: "^/usr/bin/kubelet$"

service:
  pipelines:
    logs:
      receivers: [tetragon]
      processors: [filter]
      exporters: [...]
```

## Data Conversion

Each event becomes one OpenTelemetry log record.

- Body: event type string (`"process_exec"`, `"process_exit"`, `"process_kprobe"`, ...).
- Severity: `INFO` for most event types (`process_exec`, `process_exit`, `process_kprobe`, etc.). `WARN` for `process_throttle`, `process_lsm`, `rate_limit_info`, and unrecognized event types.
- Timestamp: event time from the Tetragon response header.
- Resource attributes:
  - `service.name`: `"tetragon"`
  - `k8s.node.name`: from `GetEventsResponse.node_name`
- Log record attributes (when present):
  - `tetragon.exec_id`, `process.pid`, `process.user.id`
  - `process.executable.path`, `process.command_line`, `process.working_directory`, `process.flags`
  - `tetragon.parent.exec_id`, `process.parent_pid`, `process.parent.executable.path`
  - `k8s.namespace.name`, `k8s.pod.name`
  - `container.id`, `container.name`, `container.image.name`

## Metrics

Internal OTel metrics emitted by this receiver. Expose them as Prometheus metrics by enabling the Collector Prometheus exporter on the telemetry/internal pipeline. See [`documentation.md`](documentation.md) for full metric details.

- `otelcol_tetragonreceiver_consume_errors`
- `otelcol_tetragonreceiver_events_dropped`
- `otelcol_tetragonreceiver_events_received`
- `otelcol_tetragonreceiver_queue_depth`
- `otelcol_tetragonreceiver_stream_errors`
- `otelcol_tetragonreceiver_unknown_events`

## Architecture

- One goroutine reads Protobuf events from the Tetragon gRPC stream.
- Events go on a buffered channel. When the channel is full, the receiver drops the event and increments `otelcol_tetragonreceiver_events_dropped_total` to avoid backpressuring Tetragon's kernel ring buffers.
- A pool of workers drains the channel, maps events to `pdata.Logs`, and forwards them to the next consumer over the shared channel.

### Workers

`workers` controls how many events can be converted and in flight downstream at the same time:

- Conversion is pure in-memory mapping; a single worker can keep up with realistic event rates.
- Extra workers are usually idle.
- Multiple workers help only when `ConsumeLogs` blocks on backpressure from the next consumer. With `N` workers, up to `N` events can be in flight downstream simultaneously.
- The single shared channel with competing consumers is intentional and self-balancing.
