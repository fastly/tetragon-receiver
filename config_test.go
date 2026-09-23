// Copyright Fastly, Inc.
// SPDX-License-Identifier: Apache-2.0


package tetragonreceiver

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/confmap/confmaptest"

	"github.com/fastly/tetragon-receiver/internal/metadata"
)

func TestLoadConfig(t *testing.T) {
	cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
	require.NoError(t, err)

	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()

	sub, err := cm.Sub(metadata.Type.String())
	require.NoError(t, err)
	require.NoError(t, sub.Unmarshal(cfg))

	assert.NoError(t, confmap.Validate(cfg))
	assert.Equal(t, factory.CreateDefaultConfig(), cfg)
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name: "valid default config",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				return c
			}(),
		},
		{
			name: "missing endpoint",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.ClientConfig = configgrpc.ClientConfig{Endpoint: ""}
				return c
			}(),
			wantErr: "endpoint must be specified",
		},
		{
			name: "invalid buffer_size",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.BufferSize = 0
				return c
			}(),
			wantErr: "buffer_size must be at least 1",
		},
		{
			name: "invalid workers",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.Workers = 0
				return c
			}(),
			wantErr: "workers must be at least 1",
		},
		{
			name: "invalid initial_reconnect_delay",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.InitialReconnectDelay = 0
				return c
			}(),
			wantErr: "initial_reconnect_delay must be positive",
		},
		{
			name: "invalid max_reconnect_delay",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.MaxReconnectDelay = 0
				return c
			}(),
			wantErr: "max_reconnect_delay must be positive",
		},
		{
			name: "invalid field filter action",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.FieldFilters = []FieldFilterConfig{{Action: "INVALID"}}
				return c
			}(),
			wantErr: "field_filters[0].action must be INCLUDE or EXCLUDE",
		},
		{
			name: "insecure with non-uds endpoint",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.Endpoint = "tcp://tetragon:54321"
				return c
			}(),
			wantErr: "tls.insecure may only be used with a unix:// endpoint",
		},
		{
			name: "insecure with uds endpoint",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.Endpoint = "unix:///var/run/cilium/tetragon/tetragon.sock"
				return c
			}(),
		},
		{
			name: "invalid max_recv_msg_size_mib",
			cfg: func() *Config {
				c := createDefaultConfig().(*Config)
				c.MaxRecvMsgSizeMiB = 0
				return c
			}(),
			wantErr: "max_recv_msg_size_mib must be at least 1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			}
		})
	}
}
