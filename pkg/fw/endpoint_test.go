// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package client

import (
	"testing"

	api "github.com/cylonix/fw"
	"github.com/stretchr/testify/assert"
)

// newTestClient builds a Client pointing at a unreachable host so that
// every HTTP call fails. That lets us exercise the error paths of each
// endpoint function.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient("http", "127.0.0.1", 1, "uuid")
	assert.NoError(t, err)
	return c.(*Client)
}

func TestNewCiliumID(t *testing.T) {
	assert.Equal(t, "cilium-local:42", newCiliumID(42))
}

func TestNewIpQueryString(t *testing.T) {
	assert.Equal(t, "ns-ipv4:1.2.3.4", newIpQueryString("ns", "1.2.3.4"))
	assert.Equal(t, "ipv4:1.2.3.4", newIpQueryString("", "1.2.3.4"))
}

func TestEndpointList_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.EndpointList()
	assert.Error(t, err)
}

func TestEndpointGet_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.EndpointGet("bogus")
	assert.Error(t, err)
}

func TestEndpointGetWithIP_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.EndpointGetWithIP("ns", "1.2.3.4")
	assert.Error(t, err)
}

func TestEndpointCreate_Error(t *testing.T) {
	c := newTestClient(t)
	err := c.EndpointCreate(&api.EndpointChangeRequest{})
	assert.Error(t, err)
}

func TestEndpointPatch_Error(t *testing.T) {
	c := newTestClient(t)
	err := c.EndpointPatch("", &api.EndpointChangeRequest{})
	assert.Error(t, err)
	// With explicit ID path.
	err = c.EndpointPatch("cilium-local:10", &api.EndpointChangeRequest{})
	assert.Error(t, err)
}

func TestEndpointDelete_Error(t *testing.T) {
	c := newTestClient(t)
	err := c.EndpointDelete("cilium-local:1")
	assert.Error(t, err)
}

func TestEndpointLogGet_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.EndpointLogGet("id")
	assert.Error(t, err)
}

func TestEndpointHealthGet_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.EndpointHealthGet("id")
	assert.Error(t, err)
}

func TestEndpointConfigGet_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.EndpointConfigGet("id")
	assert.Error(t, err)
}

func TestEndpointLabelsGet_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.EndpointLabelsGet("id")
	assert.Error(t, err)
}

func TestConfigGet_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.ConfigGet()
	assert.Error(t, err)
}

func TestConfigPatch_Error(t *testing.T) {
	c := newTestClient(t)
	err := c.ConfigPatch(api.DaemonConfigurationSpec{})
	assert.Error(t, err)
}

func TestPolicyPut_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.PolicyPut("{}")
	assert.Error(t, err)
}

func TestPolicyGet_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.PolicyGet(nil)
	assert.Error(t, err)
}

func TestPolicyCacheGet_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.PolicyCacheGet()
	assert.Error(t, err)
}

func TestPolicyDelete_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.PolicyDelete(nil)
	assert.Error(t, err)
}

func TestVxlanGet_Error(t *testing.T) {
	c := newTestClient(t)
	_, err := c.VxlanGet()
	assert.Error(t, err)
}

func TestVxlanCreate_Error(t *testing.T) {
	c := newTestClient(t)
	err := c.VxlanCreate(nil)
	assert.Error(t, err)
}

func TestDeleteEndpointByLabel_Error(t *testing.T) {
	c := newTestClient(t)
	err := c.DeleteEndpointByLabel([]string{"a"})
	assert.Error(t, err)
}
