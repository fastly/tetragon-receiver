// Copyright Fastly, Inc.
// SPDX-License-Identifier: Apache-2.0

package tetragonreceiver

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/config/configtls"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/fastly/tetragon-receiver/internal/metadata"
	"github.com/fastly/tetragon-receiver/internal/metadatatest"
)

type mockFineGuidanceSensorsServer struct {
	tetragon.UnimplementedFineGuidanceSensorsServer

	events      []*tetragon.GetEventsResponse
	recvDone    chan struct{}
	connectedCh chan struct{}

	mu              sync.Mutex
	requestCh       chan *tetragon.GetEventsRequest
	streamCount     int
	closeAfterSendN int
}

func (s *mockFineGuidanceSensorsServer) GetEvents(req *tetragon.GetEventsRequest, stream grpc.ServerStreamingServer[tetragon.GetEventsResponse]) error {
	s.mu.Lock()
	s.streamCount++
	closeAfter := s.closeAfterSendN
	ch := s.requestCh
	s.mu.Unlock()

	if s.connectedCh != nil {
		close(s.connectedCh)
	}

	if ch != nil {
		select {
		case ch <- req:
		default:
		}
	}

	sent := 0
	for _, ev := range s.events {
		if err := stream.Send(ev); err != nil {
			return err
		}
		sent++
		if closeAfter > 0 && sent >= closeAfter {
			return fmt.Errorf("mock stream closed after %d events", sent)
		}
	}

	// Keep the stream open until the test cancels the context.
	<-stream.Context().Done()
	if s.recvDone != nil {
		close(s.recvDone)
	}
	return stream.Context().Err()
}

func startMockTetragonServer(t *testing.T) (net.Listener, *mockFineGuidanceSensorsServer) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	mock := &mockFineGuidanceSensorsServer{}
	grpcServer := grpc.NewServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, mock)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	return listener, mock
}

func TestFieldFilterPropagation(t *testing.T) {
	listener, mock := startMockTetragonServer(t)
	mock.requestCh = make(chan *tetragon.GetEventsRequest, 1)

	cfg := createDefaultConfig().(*Config)
	cfg.ClientConfig = configgrpc.ClientConfig{
		Endpoint: listener.Addr().String(),
		TLS:      configtls.ClientConfig{Insecure: true},
	}
	cfg.FieldFilters = []FieldFilterConfig{
		{EventSet: []string{"PROCESS_EXEC"}, Fields: []string{"process.arguments"}, Action: "EXCLUDE"},
	}

	recv, err := newTetragonReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)

	require.NoError(t, recv.Start(t.Context(), componenttest.NewNopHost()))

	var req *tetragon.GetEventsRequest
	select {
	case req = <-mock.requestCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for GetEvents request")
	}

	require.Len(t, req.FieldFilters, 1)
	assert.Equal(t, []tetragon.EventType{tetragon.EventType_PROCESS_EXEC}, req.FieldFilters[0].EventSet)
	assert.Equal(t, []string{"process.arguments"}, req.FieldFilters[0].Fields.GetPaths())
	assert.Equal(t, tetragon.FieldFilterAction_EXCLUDE, req.FieldFilters[0].Action)

	require.NoError(t, recv.Shutdown(t.Context()))
}

func TestReceiveEvents(t *testing.T) {
	listener, mock := startMockTetragonServer(t)
	mock.events = []*tetragon.GetEventsResponse{
		{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{Binary: "/bin/ls"},
				},
			},
		},
	}

	cfg := createDefaultConfig().(*Config)
	cfg.ClientConfig = configgrpc.ClientConfig{
		Endpoint: listener.Addr().String(),
		TLS:      configtls.ClientConfig{Insecure: true},
	}
	cfg.BufferSize = 100
	cfg.Workers = 1

	sink := new(consumertest.LogsSink)
	recv, err := newTetragonReceiver(receivertest.NewNopSettings(metadata.Type), cfg, sink)
	require.NoError(t, err)

	require.NoError(t, recv.Start(t.Context(), componenttest.NewNopHost()))

	require.Eventually(t, func() bool {
		return sink.LogRecordCount() >= 1
	}, 5*time.Second, 50*time.Millisecond)

	require.NoError(t, recv.Shutdown(t.Context()))

	require.Equal(t, 1, sink.LogRecordCount())
	lr := sink.AllLogs()[0].ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Equal(t, "process_exec", lr.Body().AsString())
	assert.Equal(t, "/bin/ls", lr.Attributes().AsRaw()["process.executable.path"])
}

func TestDefaultConfigConnectsToPlainUDS(t *testing.T) {
	sockPath := "/tmp/tetragon-receiver-default-test.sock"
	_ = os.Remove(sockPath)
	defer os.Remove(sockPath)

	l, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer l.Close()

	mock := &mockFineGuidanceSensorsServer{connectedCh: make(chan struct{})}
	grpcServer := grpc.NewServer()
	tetragon.RegisterFineGuidanceSensorsServer(grpcServer, mock)
	go grpcServer.Serve(l)
	defer grpcServer.Stop()

	cfg := createDefaultConfig().(*Config)
	cfg.Endpoint = fmt.Sprintf("unix://%s", sockPath)

	recv, err := newTetragonReceiver(receivertest.NewNopSettings(metadata.Type), cfg, consumertest.NewNop())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	require.NoError(t, recv.Start(ctx, componenttest.NewNopHost()))

	select {
	case <-mock.connectedCh:
	case <-time.After(time.Second):
		t.Fatal("default config did not connect to plaintext UDS")
	}

	require.NoError(t, recv.Shutdown(ctx))
}

func TestQueueDepthObservableGauge(t *testing.T) {
	tel := componenttest.NewTelemetry()
	defer func() { _ = tel.Shutdown(context.Background()) }()

	cfg := createDefaultConfig().(*Config)
	cfg.BufferSize = 10
	cfg.Workers = 1
	cfg.InitialReconnectDelay = 1 * time.Second
	cfg.MaxReconnectDelay = 1 * time.Second

	recv, err := newTetragonReceiver(metadatatest.NewSettings(tel), cfg, consumertest.NewNop())
	require.NoError(t, err)

	// Fill the channel without consuming to observe non-zero depth.
	for i := 0; i < 3; i++ {
		recv.eventsChan <- &eventWithReceiveTime{resp: &tetragon.GetEventsResponse{}}
	}

	data, err := tel.GetMetric("otelcol_tetragonreceiver_queue_depth")
	require.NoError(t, err)
	sum := data.Data.(metricdata.Gauge[int64])
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(3), sum.DataPoints[0].Value)

	require.NoError(t, recv.Shutdown(context.Background()))
}

func TestReconnectAfterStreamDrop(t *testing.T) {
	listener, mock := startMockTetragonServer(t)
	mock.events = []*tetragon.GetEventsResponse{
		{
			Event: &tetragon.GetEventsResponse_ProcessExec{
				ProcessExec: &tetragon.ProcessExec{
					Process: &tetragon.Process{Binary: "/bin/ls"},
				},
			},
		},
	}
	mock.closeAfterSendN = 1

	cfg := createDefaultConfig().(*Config)
	cfg.ClientConfig = configgrpc.ClientConfig{
		Endpoint: listener.Addr().String(),
		TLS:      configtls.ClientConfig{Insecure: true},
	}
	cfg.BufferSize = 100
	cfg.Workers = 1
	cfg.InitialReconnectDelay = 50 * time.Millisecond
	cfg.MaxReconnectDelay = 100 * time.Millisecond

	sink := new(consumertest.LogsSink)
	recv, err := newTetragonReceiver(receivertest.NewNopSettings(metadata.Type), cfg, sink)
	require.NoError(t, err)

	require.NoError(t, recv.Start(t.Context(), componenttest.NewNopHost()))

	require.Eventually(t, func() bool {
		return sink.LogRecordCount() >= 2
	}, 5*time.Second, 50*time.Millisecond)

	require.NoError(t, recv.Shutdown(t.Context()))

	require.GreaterOrEqual(t, sink.LogRecordCount(), 2)
	mock.mu.Lock()
	streamCount := mock.streamCount
	mock.mu.Unlock()
	require.GreaterOrEqual(t, streamCount, 2, "expected at least one reconnect")
}

func TestUnknownEventLogsAreRateLimited(t *testing.T) {
	listener, mock := startMockTetragonServer(t)
	mock.events = []*tetragon.GetEventsResponse{
		{Event: nil},
		{Event: nil},
	}

	cfg := createDefaultConfig().(*Config)
	cfg.ClientConfig = configgrpc.ClientConfig{
		Endpoint: listener.Addr().String(),
		TLS:      configtls.ClientConfig{Insecure: true},
	}
	cfg.BufferSize = 100
	cfg.Workers = 1

	core, observed := observer.New(zapcore.WarnLevel)
	telSettings := componenttest.NewNopTelemetrySettings()
	telSettings.Logger = zap.New(core)
	settings := receiver.Settings{
		ID:                component.MustNewID(metadata.Type.String()),
		BuildInfo:         component.NewDefaultBuildInfo(),
		TelemetrySettings: telSettings,
	}

	sink := new(consumertest.LogsSink)
	recv, err := newTetragonReceiver(settings, cfg, sink)
	require.NoError(t, err)

	require.NoError(t, recv.Start(t.Context(), componenttest.NewNopHost()))
	require.Eventually(t, func() bool {
		return sink.LogRecordCount() >= 2
	}, 5*time.Second, 50*time.Millisecond)
	require.NoError(t, recv.Shutdown(t.Context()))

	warns := observed.FilterMessage("unmapped Tetragon event type").AllUntimed()
	require.Len(t, warns, 1, "expected only one rate-limited warning")
	assert.Equal(t, "<nil>", warns[0].ContextMap()["event_type"])
}
