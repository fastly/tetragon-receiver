// Copyright Fastly, Inc.
// SPDX-License-Identifier: Apache-2.0


package tetragonreceiver // import "github.com/fastly/tetragon-receiver"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configgrpc"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"

	"github.com/fastly/tetragon-receiver/internal/metadata"
)

// NewFactory creates a new receiver factory for Tetragon.
func NewFactory() receiver.Factory {
	return xreceiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		xreceiver.WithLogs(
			func(_ context.Context, params receiver.Settings, cfg component.Config, consumer consumer.Logs) (receiver.Logs, error) {
				return newTetragonReceiver(params, cfg.(*Config), consumer)
			},
			metadata.LogsStability,
		),
	)
}

func createDefaultConfig() component.Config {
	clientConfig := configgrpc.NewDefaultClientConfig()
	clientConfig.Endpoint = defaultEndpoint
	// The default endpoint is a local Unix domain socket served by Tetragon as
	// plaintext gRPC; filesystem permissions enforce access. TLS does not apply,
	// so we default to insecure transport. Operators using a remote TCP endpoint
	// must configure tls explicitly.
	clientConfig.TLS.Insecure = true
	return &Config{
		ClientConfig:          clientConfig,
		BufferSize:            defaultBufferSize,
		Workers:               defaultWorkers,
		InitialReconnectDelay: defaultInitialReconnectDelay,
		MaxReconnectDelay:     defaultMaxReconnectDelay,
		MaxRecvMsgSizeMiB:     defaultMaxRecvMsgSizeMiB,
	}
}
