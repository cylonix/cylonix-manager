// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package client

import (
	"context"
	"time"

	api "github.com/cylonix/fw"
)

const (
	ClientTimeout = 90 * time.Second
)

// ConfigGet returns a daemon configuration.
func (c *Client) ConfigGet() (*api.DaemonConfiguration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), ClientTimeout)
	defer cancel()

	config, _, err := c.DaemonAPI.ConfigGet(ctx).Execute()
	if err != nil {
		return nil, Hint(err)
	}
	return config, nil
}

// ConfigPatch modifies the daemon configuration.
func (c *Client) ConfigPatch(cfg api.DaemonConfigurationSpec) error {
	fullCfg, err := c.ConfigGet()
	if err != nil {
		return err
	}

	if fullCfg.Spec == nil {
		fullCfg.Spec = &cfg
	}
	if cfg.Options != nil {
		options := *cfg.Options
		if fullCfg.Spec.Options == nil {
			fullCfg.Spec.Options = &options
		} else {
			for opt, value := range options {
				(*fullCfg.Spec.Options)[opt] = value
			}
		}
	}
	if cfg.PolicyEnforcement != nil {
		fullCfg.Spec.PolicyEnforcement = cfg.PolicyEnforcement
	}

	ctx, cancel := context.WithTimeout(context.Background(), ClientTimeout)
	defer cancel()

	_, err = c.DaemonAPI.ConfigPatch(ctx).Configuration(*fullCfg.Spec).Execute()
	return Hint(err)
}
