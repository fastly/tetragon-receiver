// Copyright Fastly, Inc.
// SPDX-License-Identifier: Apache-2.0

package tetragonreceiver // import "github.com/fastly/tetragon-receiver"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/fastly/tetragon-receiver/internal/metadata"
)

const (
	attrTetragonExecID          = "tetragon.exec_id"
	attrProcessPID              = "process.pid"
	attrProcessUserID           = "process.user.id"
	attrProcessExecutablePath   = "process.executable.path"
	attrProcessCommandLine      = "process.command_line"
	attrProcessWorkingDirectory = "process.working_directory"
	attrProcessFlags            = "process.flags"
	attrProcessParentPID        = "process.parent_pid"
	attrTetragonParentExecID    = "tetragon.parent.exec_id"
	attrProcessParentExecutable = "process.parent.executable.path"
	attrK8sNamespaceName        = "k8s.namespace.name"
	attrK8sPodName              = "k8s.pod.name"
	attrContainerID             = "container.id"
	attrContainerName           = "container.name"
	attrContainerImageName      = "container.image.name"
	attrServiceName             = "service.name"
	attrK8sNodeName             = "k8s.node.name"
)

// convertToOTelLogs converts a Tetragon GetEventsResponse into a plog.Logs
// payload containing a single LogRecord.
func convertToOTelLogs(
	ctx context.Context,
	resp *tetragon.GetEventsResponse,
	receivedAt time.Time,
	telemetry *metadata.TelemetryBuilder,
) (plog.Logs, bool) {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	res := rl.Resource()
	res.Attributes().PutStr(attrServiceName, "tetragon")
	if resp.NodeName != "" {
		res.Attributes().PutStr(attrK8sNodeName, resp.NodeName)
	}

	sl := rl.ScopeLogs().AppendEmpty()
	sl.Scope().SetName("tetragonreceiver")

	body, process, parent, unknown := eventBodyAndProcess(resp)
	if unknown && telemetry != nil {
		telemetry.TetragonreceiverUnknownEvents.Add(ctx, 1)
	}
	sevNum, sevText := severityForEventType(body)

	lr := sl.LogRecords().AppendEmpty()
	lr.SetTimestamp(timestampFromProto(resp.Time))
	lr.SetObservedTimestamp(pcommon.NewTimestampFromTime(receivedAt))
	lr.SetSeverityNumber(sevNum)
	lr.SetSeverityText(sevText)
	lr.Body().SetStr(body)

	if process != nil {
		mapProcess(lr.Attributes(), process)
	}
	if parent != nil {
		if parent.ExecId != "" {
			lr.Attributes().PutStr(attrTetragonParentExecID, parent.ExecId)
		}
		if parent.Pid != nil {
			lr.Attributes().PutInt(attrProcessParentPID, int64(parent.Pid.Value))
		}
		if parent.Binary != "" {
			lr.Attributes().PutStr(attrProcessParentExecutable, parent.Binary)
		}
	}

	return logs, unknown
}

// eventBodyAndProcess extracts the event-type string and the associated Process
// from a GetEventsResponse oneof event. unknown is true when the event type is
// not recognized, which typically means the Tetragon API has added a new type.
func eventBodyAndProcess(resp *tetragon.GetEventsResponse) (body string, process, parent *tetragon.Process, unknown bool) {
	switch ev := resp.Event.(type) {
	case *tetragon.GetEventsResponse_ProcessExec:
		body = "process_exec"
		if ev.ProcessExec != nil {
			process, parent = ev.ProcessExec.Process, ev.ProcessExec.Parent
		}
	case *tetragon.GetEventsResponse_ProcessExit:
		body = "process_exit"
		if ev.ProcessExit != nil {
			process, parent = ev.ProcessExit.Process, ev.ProcessExit.Parent
		}
	case *tetragon.GetEventsResponse_ProcessKprobe:
		body = "process_kprobe"
		if ev.ProcessKprobe != nil {
			process, parent = ev.ProcessKprobe.Process, ev.ProcessKprobe.Parent
		}
	case *tetragon.GetEventsResponse_ProcessTracepoint:
		body = "process_tracepoint"
		if ev.ProcessTracepoint != nil {
			process, parent = ev.ProcessTracepoint.Process, ev.ProcessTracepoint.Parent
		}
	case *tetragon.GetEventsResponse_ProcessLoader:
		body = "process_loader"
		if ev.ProcessLoader != nil {
			process, parent = ev.ProcessLoader.Process, ev.ProcessLoader.Parent
		}
	case *tetragon.GetEventsResponse_ProcessUprobe:
		body = "process_uprobe"
		if ev.ProcessUprobe != nil {
			process, parent = ev.ProcessUprobe.Process, ev.ProcessUprobe.Parent
		}
	case *tetragon.GetEventsResponse_ProcessThrottle:
		body = "process_throttle"
	case *tetragon.GetEventsResponse_ProcessLsm:
		body = "process_lsm"
		if ev.ProcessLsm != nil {
			process, parent = ev.ProcessLsm.Process, ev.ProcessLsm.Parent
		}
	case *tetragon.GetEventsResponse_ProcessUsdt:
		body = "process_usdt"
		if ev.ProcessUsdt != nil {
			process, parent = ev.ProcessUsdt.Process, ev.ProcessUsdt.Parent
		}
	case *tetragon.GetEventsResponse_Test:
		body = "test"
	case *tetragon.GetEventsResponse_RateLimitInfo:
		body = "rate_limit_info"
	default:
		body = "unknown"
		unknown = true
	}
	return body, process, parent, unknown
}

// mapProcess maps Tetragon Process fields to OTel log record attributes.
func mapProcess(attrs pcommon.Map, proc *tetragon.Process) {
	if proc.ExecId != "" {
		attrs.PutStr(attrTetragonExecID, proc.ExecId)
	}
	if proc.Pid != nil {
		attrs.PutInt(attrProcessPID, int64(proc.Pid.Value))
	}
	if proc.Uid != nil {
		attrs.PutInt(attrProcessUserID, int64(proc.Uid.Value))
	}
	if proc.Binary != "" {
		attrs.PutStr(attrProcessExecutablePath, proc.Binary)
	}
	if proc.Arguments != "" {
		attrs.PutStr(attrProcessCommandLine, proc.Arguments)
	}
	if proc.Cwd != "" {
		attrs.PutStr(attrProcessWorkingDirectory, proc.Cwd)
	}
	if proc.Flags != "" {
		attrs.PutStr(attrProcessFlags, proc.Flags)
	}

	if proc.Pod != nil {
		if proc.Pod.Namespace != "" {
			attrs.PutStr(attrK8sNamespaceName, proc.Pod.Namespace)
		}
		if proc.Pod.Name != "" {
			attrs.PutStr(attrK8sPodName, proc.Pod.Name)
		}
		if proc.Pod.Container != nil {
			if proc.Pod.Container.Id != "" {
				attrs.PutStr(attrContainerID, proc.Pod.Container.Id)
			}
			if proc.Pod.Container.Name != "" {
				attrs.PutStr(attrContainerName, proc.Pod.Container.Name)
			}
			if proc.Pod.Container.Image != nil && proc.Pod.Container.Image.Name != "" {
				attrs.PutStr(attrContainerImageName, proc.Pod.Container.Image.Name)
			}
		}
	}
}

// timestampFromProto converts a protobuf Timestamp to pcommon.Timestamp.
// If ts is nil or zero it returns the zero (unset) timestamp.
func timestampFromProto(ts *timestamppb.Timestamp) pcommon.Timestamp {
	if ts == nil || (ts.Seconds == 0 && ts.Nanos == 0) {
		return pcommon.Timestamp(0)
	}
	return pcommon.NewTimestampFromTime(ts.AsTime())
}

// severityForEventType maps a Tetragon event type to an OTel severity.
// Throttle, rate-limit, security-policy, and unrecognized events are WARN;
// everything else is INFO.
func severityForEventType(body string) (plog.SeverityNumber, string) {
	switch body {
	case "process_exec", "process_exit", "process_kprobe", "process_tracepoint",
		"process_loader", "process_uprobe", "process_usdt", "test":
		return plog.SeverityNumberInfo, "INFO"
	default:
		return plog.SeverityNumberWarn, "WARN"
	}
}
