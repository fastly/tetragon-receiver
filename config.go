// Copyright Fastly, Inc.
// SPDX-License-Identifier: Apache-2.0


package tetragonreceiver // import "github.com/fastly/tetragon-receiver"

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
)

const (
	defaultEndpoint              = "unix:///var/run/cilium/tetragon/tetragon.sock"
	defaultBufferSize            = 10_000
	defaultWorkers               = 4
	defaultMaxRecvMsgSizeMiB     = 2
	defaultMaxReconnectDelay     = 30 * time.Second
	defaultInitialReconnectDelay = 1 * time.Second
)

// FieldFilterConfig defines a user-friendly YAML representation of a Tetragon
// FieldFilter.
type FieldFilterConfig struct {
	// EventSet limits the filter to specific event types.
	EventSet []string `mapstructure:"event_set"`
	// Fields is the list of protobuf field paths to include or exclude.
	Fields []string `mapstructure:"fields"`
	// Action is either "INCLUDE" or "EXCLUDE".
	Action string `mapstructure:"action"`
}

// Config defines configuration for the Tetragon receiver.
type Config struct {
	// ClientConfig exposes the standard OTel gRPC client settings.
	// Endpoint defaults to the local Tetragon Unix Domain Socket.
	configgrpc.ClientConfig `mapstructure:",squash"`

	// BufferSize is the capacity of the channel between the gRPC stream
	// reader and the mapper worker pool.
	BufferSize int `mapstructure:"buffer_size"`
	// Workers is the number of goroutines that map Tetragon events into
	// plog.Logs and forward them to the next consumer.
	Workers int `mapstructure:"workers"`
	// InitialReconnectDelay is the delay before the first reconnect attempt
	// after the Tetragon event stream breaks.
	InitialReconnectDelay time.Duration `mapstructure:"initial_reconnect_delay"`
	// MaxReconnectDelay caps the exponential backoff between reconnect attempts.
	MaxReconnectDelay time.Duration `mapstructure:"max_reconnect_delay"`
	// MaxRecvMsgSizeMiB sets the maximum gRPC message size the Tetragon server may send.
	// The default is large enough for realistic Tetragon events while bounding per-event memory.
	MaxRecvMsgSizeMiB int `mapstructure:"max_recv_msg_size_mib"`

	// FieldFilters are protobuf field masks applied server-side by Tetragon.
	FieldFilters []FieldFilterConfig `mapstructure:"field_filters"`
}

var _ component.Config = (*Config)(nil)

// Validate checks the receiver configuration is valid.
func (cfg *Config) Validate() error {
	if cfg.Endpoint == "" {
		return errors.New("endpoint must be specified")
	}
	if cfg.TLS.Insecure && !strings.HasPrefix(cfg.Endpoint, "unix://") {
		return errors.New("tls.insecure may only be used with a unix:// endpoint; configure tls for TCP endpoints")
	}
	if cfg.BufferSize < 1 {
		return errors.New("buffer_size must be at least 1")
	}
	if cfg.Workers < 1 {
		return errors.New("workers must be at least 1")
	}
	if cfg.InitialReconnectDelay <= 0 {
		return errors.New("initial_reconnect_delay must be positive")
	}
	if cfg.MaxReconnectDelay <= 0 {
		return errors.New("max_reconnect_delay must be positive")
	}
	if cfg.MaxRecvMsgSizeMiB < 1 {
		return errors.New("max_recv_msg_size_mib must be at least 1")
	}
	for i, f := range cfg.FieldFilters {
		action := strings.ToUpper(strings.TrimSpace(f.Action))
		if action != "" && action != "INCLUDE" && action != "EXCLUDE" {
			return fmt.Errorf("field_filters[%d].action must be INCLUDE or EXCLUDE", i)
		}
		if err := validateEventSet(f.EventSet, fmt.Sprintf("field_filters[%d].event_set", i)); err != nil {
			return err
		}
	}
	return nil
}

// commandLineIsFiltered reports whether any field filter excludes process.arguments
// from PROCESS_EXEC events, which prevents command-line credentials from being exported.
func commandLineIsFiltered(filters []FieldFilterConfig) bool {
	for _, f := range filters {
		if !strings.EqualFold(f.Action, "EXCLUDE") {
			continue
		}
		hasExec := false
		for _, e := range f.EventSet {
			if strings.EqualFold(strings.TrimSpace(e), "PROCESS_EXEC") {
				hasExec = true
				break
			}
		}
		// If the event set is empty the filter applies to all events, which still counts
		// if it excludes process.arguments.
		if !hasExec && len(f.EventSet) > 0 {
			continue
		}
		for _, field := range f.Fields {
			if strings.EqualFold(strings.TrimSpace(field), "process.arguments") {
				return true
			}
		}
	}
	return false
}

func validateEventSet(values []string, path string) error {
	for _, v := range values {
		if _, ok := eventSetNameToType(strings.TrimSpace(v)); !ok {
			return fmt.Errorf("%s contains unknown event type %q", path, v)
		}
	}
	return nil
}
