// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package client

import (
	"context"
	"cylonix/sase/pkg/logging"
	"cylonix/sase/pkg/logging/logfields"

	api "github.com/cylonix/fw"
)

// PolicyPut update the `policyJSON`
func (c *Client) PolicyPut(policyJSON string) (*api.Policy, error) {
	ret, _, err := c.PolicyAPI.PolicyPut(context.TODO()).Policy(policyJSON).Execute()
	if err != nil {
		return nil, Hint(err)
	}
	return ret, nil
}

// PolicyGet returns policy rules
func (c *Client) PolicyGet(labels []string) (*api.Policy, error) {
	ret, _, err := c.PolicyAPI.PolicyGet(context.TODO()).Labels(labels).Execute()
	if err != nil {
		return nil, Hint(err)
	}
	return ret, nil
}

// PolicyCacheGet returns the contents of a SelectorCache.
func (c *Client) PolicyCacheGet() ([]api.SelectorIdentityMapping, error) {
	ret, _, err := c.PolicyAPI.PolicySelectorsGet(context.TODO()).Execute()
	if err != nil {
		return nil, Hint(err)
	}
	return ret, nil
}

// PolicyDelete deletes policy rules
func (c *Client) PolicyDelete(labels []string) (*api.Policy, error) {
	ret, _, err := c.PolicyAPI.PolicyDelete(context.TODO()).Labels(labels).Execute()
	if err != nil {
		return nil, Hint(err)
	}
	return ret, Hint(err)
}

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "config")
)

func (c *Client) ListCategories(namespace string) ([]string, error) {
	return nil, nil
}
