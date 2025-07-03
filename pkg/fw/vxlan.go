package client

import (
	"context"

	api "github.com/cylonix/fw"
)

// VxlanGet returns vxlan tunnel configuration
func (c *Client) VxlanGet() ([][]api.RemoteVxlanTunnel, error) {
	ret, _, err := c.DaemonAPI.VxlanGet(context.TODO()).Execute()
	if err != nil {
		/* Since plugins rely on checking the error type, we don't wrap this
		 * with Hint(...)
		 */
		return nil, err
	}
	return ret, nil
}

// VxlanCreate creates vxlan tunnel
func (c *Client) VxlanCreate(config []api.RemoteVxlanTunnel) error {
	_, err := c.DaemonAPI.VxlanPost(context.TODO()).Vxlan(config).Execute()
	return Hint(err)
}
