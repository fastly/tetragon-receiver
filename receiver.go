// Copyright Fastly, Inc.
// SPDX-License-Identifier: Apache-2.0

package tetragonreceiver // import "github.com/fastly/tetragon-receiver"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/fastly/tetragon-receiver/internal/metadata"
)

// tetragonReceiver consumes Tetragon eBPF events over gRPC and emits OTel logs.
type tetragonReceiver struct {
	cfg      *Config
	settings receiver.Settings
	consumer consumer.Logs

	grpcClient *grpc.ClientConn

	eventsChan chan *eventWithReceiveTime
	stopWG     sync.WaitGroup
	cancel     context.CancelFunc

	telemetry          *metadata.TelemetryBuilder
	unknownEventLogger *logLimiter
}

// eventWithReceiveTime pairs a Tetragon response with the time it was received.
type eventWithReceiveTime struct {
	resp       *tetragon.GetEventsResponse
	receivedAt time.Time
}

// newTetragonReceiver creates a new tetragonReceiver.
func newTetragonReceiver(
	settings receiver.Settings,
	cfg *Config,
	consumer consumer.Logs,
) (*tetragonReceiver, error) {
	telemetryBuilder, err := metadata.NewTelemetryBuilder(settings.TelemetrySettings)
	if err != nil {
		return nil, fmt.Errorf("failed to create telemetry builder: %w", err)
	}

	r := &tetragonReceiver{
		cfg:                cfg,
		settings:           settings,
		consumer:           consumer,
		eventsChan:         make(chan *eventWithReceiveTime, cfg.BufferSize),
		telemetry:          telemetryBuilder,
		unknownEventLogger: &logLimiter{every: 1 * time.Minute},
	}

	meter := metadata.Meter(settings.TelemetrySettings)
	if _, err := meter.Int64ObservableGauge(
		"otelcol_tetragonreceiver_queue_depth",
		metric.WithDescription("Current number of events buffered in the worker channel [Development]"),
		metric.WithUnit("1"),
		metric.WithInt64Callback(func(_ context.Context, o metric.Int64Observer) error {
			o.Observe(int64(len(r.eventsChan)))
			return nil
		}),
	); err != nil {
		return nil, fmt.Errorf("failed to register queue depth gauge: %w", err)
	}

	return r, nil
}

// Start dials the Tetragon daemon and starts the stream reader and worker pool.
func (r *tetragonReceiver) Start(ctx context.Context, host component.Host) (err error) {
	clientConfig := r.cfg.ClientConfig
	maxRecvBytes := r.cfg.MaxRecvMsgSizeMiB * 1024 * 1024
	grpcClient, err := clientConfig.ToClientConn(
		ctx,
		host.GetExtensions(),
		r.settings.TelemetrySettings,
		configgrpc.WithGrpcDialOption(grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(maxRecvBytes))),
	)
	if err != nil {
		return fmt.Errorf("failed to dial Tetragon: %w", err)
	}
	r.grpcClient = grpcClient

	ctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	defer func() {
		if err != nil {
			cancel()
			r.cancel = nil
		}
	}()

	if !commandLineIsFiltered(r.cfg.FieldFilters) {
		r.settings.Logger.Warn(
			"process.command_line is being captured without redaction; " +
				"command lines may contain sensitive data. " +
				"Consider using field_filters to exclude process.arguments.",
		)
	}

	r.stopWG.Add(1 + r.cfg.Workers)
	go r.streamReader(ctx)
	for i := 0; i < r.cfg.Workers; i++ {
		go r.worker(ctx)
	}

	return nil
}

// Shutdown stops the receiver and waits for goroutines to finish.
func (r *tetragonReceiver) Shutdown(ctx context.Context) error {
	if r.cancel != nil {
		r.cancel()
	}
	done := make(chan struct{})
	go func() {
		r.stopWG.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}

	if r.grpcClient != nil {
		return r.grpcClient.Close()
	}
	return nil
}

// streamReader maintains the Tetragon event stream and reconnects with
// exponential backoff if the stream breaks. It keeps running until the
// receiver context is cancelled.
func (r *tetragonReceiver) streamReader(ctx context.Context) {
	defer r.stopWG.Done()

	tetragonClient := tetragon.NewFineGuidanceSensorsClient(r.grpcClient)
	req := r.buildGetEventsRequest()
	backoff := r.cfg.InitialReconnectDelay

	for {
		if err := r.readStream(ctx, tetragonClient, req); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			r.telemetry.TetragonreceiverStreamErrors.Add(ctx, 1)
			r.settings.Logger.Error("Tetragon event stream broken, reconnecting", zap.Error(err), zap.Duration("backoff", backoff))
		} else {
			r.settings.Logger.Info("Tetragon event stream closed cleanly, reconnecting", zap.Duration("backoff", backoff))
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > r.cfg.MaxReconnectDelay {
			backoff = r.cfg.MaxReconnectDelay
		}
	}
}

// readStream opens a single GetEvents stream and receives events until it
// breaks or the context is cancelled. It returns nil on clean EOF and a
// non-nil error otherwise.
func (r *tetragonReceiver) readStream(
	ctx context.Context,
	client tetragon.FineGuidanceSensorsClient,
	req *tetragon.GetEventsRequest,
) error {
	stream, err := client.GetEvents(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to start Tetragon event stream: %w", err)
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}

		r.telemetry.TetragonreceiverEventsReceived.Add(ctx, 1)

		select {
		case r.eventsChan <- &eventWithReceiveTime{resp: resp, receivedAt: time.Now()}:
		case <-ctx.Done():
			return nil
		default:
			r.telemetry.TetragonreceiverEventsDropped.Add(ctx, 1)
		}
	}
}

// worker reads events from the channel, converts them to plog.Logs, and
// forwards them to the next consumer.
func (r *tetragonReceiver) worker(ctx context.Context) {
	defer r.stopWG.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-r.eventsChan:
			logs, unknown := convertToOTelLogs(ctx, ev.resp, ev.receivedAt, r.telemetry)
			if unknown && r.unknownEventLogger.allow(ev.receivedAt) {
				r.settings.Logger.Warn(
					"unmapped Tetragon event type",
					zap.String("event_type", fmt.Sprintf("%T", ev.resp.Event)),
				)
			}
			if err := r.consumer.ConsumeLogs(ctx, logs); err != nil {
				r.telemetry.TetragonreceiverConsumeErrors.Add(ctx, 1)
				r.settings.Logger.Error("consume logs failed", zap.Error(err))
				continue
			}
		}
	}
}

// buildGetEventsRequest translates the user-friendly YAML configuration into
// the Tetragon protobuf GetEventsRequest.
func (r *tetragonReceiver) buildGetEventsRequest() *tetragon.GetEventsRequest {
	req := &tetragon.GetEventsRequest{
		FieldFilters: make([]*tetragon.FieldFilter, 0, len(r.cfg.FieldFilters)),
	}
	for _, f := range r.cfg.FieldFilters {
		req.FieldFilters = append(req.FieldFilters, fieldFilterConfigToProto(f))
	}
	return req
}

// fieldFilterConfigToProto converts a YAML FieldFilterConfig into a Tetragon
// protobuf FieldFilter.
func fieldFilterConfigToProto(f FieldFilterConfig) *tetragon.FieldFilter {
	action := tetragon.FieldFilterAction_INCLUDE
	if strings.ToUpper(strings.TrimSpace(f.Action)) == "EXCLUDE" {
		action = tetragon.FieldFilterAction_EXCLUDE
	}
	pf := &tetragon.FieldFilter{
		Action: action,
		Fields: &fieldmaskpb.FieldMask{Paths: append([]string(nil), f.Fields...)},
	}
	if len(f.EventSet) > 0 {
		pf.EventSet = eventSetStringsToProto(f.EventSet)
	}
	return pf
}

func eventSetNameToType(name string) (tetragon.EventType, bool) {
	name = strings.ToUpper(strings.TrimSpace(name))
	v, ok := tetragon.EventType_value[name]
	if !ok {
		return tetragon.EventType_UNDEF, false
	}
	return tetragon.EventType(v), true
}

// eventSetStringsToProto maps strings to Tetragon EventType enum values.
func eventSetStringsToProto(values []string) []tetragon.EventType {
	result := make([]tetragon.EventType, 0, len(values))
	for _, v := range values {
		if et, ok := eventSetNameToType(v); ok {
			result = append(result, et)
		}
	}
	return result
}

// logLimiter rate-limits a log line to once per configured interval.
type logLimiter struct {
	every time.Duration
	mu    sync.Mutex
	last  time.Time
}

// allow reports whether a log line may be emitted at time t and records t
// when it returns true.
func (l *logLimiter) allow(t time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t.Sub(l.last) < l.every {
		return false
	}
	l.last = t
	return true
}
