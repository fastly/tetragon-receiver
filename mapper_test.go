// Copyright Fastly, Inc.
// SPDX-License-Identifier: Apache-2.0

package tetragonreceiver

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/fastly/tetragon-receiver/internal/metadata"
)

func TestEventBodyAndProcess(t *testing.T) {
	respExec := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{Binary: "/bin/cat"},
				Parent:  &tetragon.Process{Binary: "/bin/bash", Pid: wrapperspb.UInt32(1)},
			},
		},
	}

	body, process, parent, unknown := eventBodyAndProcess(respExec)
	assert.False(t, unknown)
	assert.Equal(t, "process_exec", body)
	assert.Equal(t, "/bin/cat", process.Binary)
	assert.Equal(t, "/bin/bash", parent.Binary)
}

func TestConvertToOTelLogs(t *testing.T) {
	resp := &tetragon.GetEventsResponse{
		Time:     timestamppb.Now(),
		NodeName: "test-node",
		Event: &tetragon.GetEventsResponse_ProcessKprobe{
			ProcessKprobe: &tetragon.ProcessKprobe{
				Process: &tetragon.Process{
					ExecId:    "a:b:c",
					Pid:       wrapperspb.UInt32(42),
					Uid:       wrapperspb.UInt32(1000),
					Binary:    "/usr/bin/curl",
					Arguments: "example.com",
					Cwd:       "/home/user",
					Flags:     "execve",
					Pod: &tetragon.Pod{
						Namespace: "prod",
						Name:      "web-0",
						Container: &tetragon.Container{
							Id:   "container-id",
							Name: "web",
							Image: &tetragon.Image{
								Name: "nginx:latest",
							},
						},
					},
				},
				Parent: &tetragon.Process{
					ExecId: "parent-exec-id",
					Pid:    wrapperspb.UInt32(1),
					Binary: "/usr/lib/systemd/systemd",
				},
			},
		},
	}

	receivedAt := time.Unix(1234567890, 0)
	logs, unknown := convertToOTelLogs(context.Background(), resp, receivedAt, nil)
	require.False(t, unknown)
	require.Equal(t, 1, logs.ResourceLogs().Len())
	rl := logs.ResourceLogs().At(0)
	res := rl.Resource()
	requireAttrStr(t, res.Attributes(), "service.name", "tetragon")
	requireAttrStr(t, res.Attributes(), "k8s.node.name", "test-node")

	sl := rl.ScopeLogs().At(0)
	require.Equal(t, 1, sl.LogRecords().Len())
	lr := sl.LogRecords().At(0)
	assert.Equal(t, "process_kprobe", lr.Body().AsString())
	assert.Equal(t, "INFO", lr.SeverityText())
	assert.Equal(t, pcommon.NewTimestampFromTime(receivedAt), lr.ObservedTimestamp())

	attrs := lr.Attributes()
	requireAttrStr(t, attrs, "tetragon.exec_id", "a:b:c")
	requireAttrInt(t, attrs, "process.pid", 42)
	requireAttrInt(t, attrs, "process.user.id", 1000)
	requireAttrStr(t, attrs, "process.executable.path", "/usr/bin/curl")
	requireAttrStr(t, attrs, "process.command_line", "example.com")
	requireAttrStr(t, attrs, "process.working_directory", "/home/user")
	requireAttrStr(t, attrs, "process.flags", "execve")
	requireAttrStr(t, attrs, "tetragon.parent.exec_id", "parent-exec-id")
	requireAttrInt(t, attrs, "process.parent_pid", 1)
	requireAttrStr(t, attrs, "process.parent.executable.path", "/usr/lib/systemd/systemd")
	requireAttrStr(t, attrs, "k8s.namespace.name", "prod")
	requireAttrStr(t, attrs, "k8s.pod.name", "web-0")
	requireAttrStr(t, attrs, "container.id", "container-id")
	requireAttrStr(t, attrs, "container.name", "web")
	requireAttrStr(t, attrs, "container.image.name", "nginx:latest")
}

func TestConvertToOTelLogsUnknownEvent(t *testing.T) {
	resp := &tetragon.GetEventsResponse{}
	logs, unknown := convertToOTelLogs(context.Background(), resp, time.Now(), nil)
	require.True(t, unknown)
	require.Equal(t, 1, logs.ResourceLogs().Len())
	lr := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Equal(t, "unknown", lr.Body().AsString())
}

func TestTimestampUnsetWhenNoEventTime(t *testing.T) {
	resp := &tetragon.GetEventsResponse{
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{Binary: "/bin/ls"},
			},
		},
	}

	logs, unknown := convertToOTelLogs(context.Background(), resp, time.Unix(1234567890, 0), nil)
	require.False(t, unknown)
	lr := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Equal(t, pcommon.Timestamp(0), lr.Timestamp())
}

func TestSeverityMapping(t *testing.T) {
	tests := []struct {
		body     string
		wantNum  plog.SeverityNumber
		wantText string
	}{
		{"process_exec", plog.SeverityNumberInfo, "INFO"},
		{"process_exit", plog.SeverityNumberInfo, "INFO"},
		{"process_kprobe", plog.SeverityNumberInfo, "INFO"},
		{"process_throttle", plog.SeverityNumberWarn, "WARN"},
		{"rate_limit_info", plog.SeverityNumberWarn, "WARN"},
		{"process_lsm", plog.SeverityNumberWarn, "WARN"},
		{"unknown", plog.SeverityNumberWarn, "WARN"},
	}

	for _, tt := range tests {
		t.Run(tt.body, func(t *testing.T) {
			num, text := severityForEventType(tt.body)
			assert.Equal(t, tt.wantNum, num)
			assert.Equal(t, tt.wantText, text)
		})
	}
}

func TestUnknownEventIncrementsMetric(t *testing.T) {
	tel := componenttest.NewTelemetry()
	defer func() { _ = tel.Shutdown(context.Background()) }()

	tb, err := metadata.NewTelemetryBuilder(tel.NewTelemetrySettings())
	require.NoError(t, err)

	resp := &tetragon.GetEventsResponse{}
	_, unknown := convertToOTelLogs(context.Background(), resp, time.Now(), tb)
	require.True(t, unknown)
	_, unknown = convertToOTelLogs(context.Background(), resp, time.Now(), tb)
	require.True(t, unknown)

	data, err := tel.GetMetric("otelcol_tetragonreceiver_unknown_events")
	require.NoError(t, err)
	sum := data.Data.(metricdata.Sum[int64])
	require.Len(t, sum.DataPoints, 1)
	assert.Equal(t, int64(2), sum.DataPoints[0].Value)
}

func TestTimestampFromEventTime(t *testing.T) {
	eventTime := time.Unix(1700000000, 0)
	resp := &tetragon.GetEventsResponse{
		Time: timestamppb.New(eventTime),
		Event: &tetragon.GetEventsResponse_ProcessExec{
			ProcessExec: &tetragon.ProcessExec{
				Process: &tetragon.Process{Binary: "/bin/ls"},
			},
		},
	}

	logs, unknown := convertToOTelLogs(context.Background(), resp, time.Unix(1234567890, 0), nil)
	require.False(t, unknown)
	lr := logs.ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0)
	assert.Equal(t, pcommon.NewTimestampFromTime(eventTime), lr.Timestamp())
}

func requireAttrStr(t *testing.T, attrs pcommon.Map, key, expected string) {
	t.Helper()
	v, ok := attrs.Get(key)
	require.True(t, ok, "expected attribute %q to be present", key)
	assert.Equal(t, expected, v.Str())
}

func requireAttrInt(t *testing.T, attrs pcommon.Map, key string, expected int64) {
	t.Helper()
	v, ok := attrs.Get(key)
	require.True(t, ok, "expected attribute %q to be present", key)
	assert.Equal(t, expected, v.Int())
}
