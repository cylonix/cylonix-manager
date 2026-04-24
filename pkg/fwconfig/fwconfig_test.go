// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package fwconfig

import (
	client "cylonix/sase/pkg/fw"
	"errors"
	"testing"
	"time"

	api "github.com/cylonix/fw"
	"github.com/cylonix/utils"
	"github.com/stretchr/testify/assert"
)

type mockClient struct {
	*client.ClientEmulator
	getEP            *api.Endpoint
	getEPErr         error
	createErr        error
	patchErr         error
	policyPolicy     string
	policyGetErr     error
	policyPutErr     error
	policyDelErr     error
	listCategoriesV  []string
	listCategoriesE  error
	deleteByLabelErr error
}

func (m *mockClient) EndpointGetWithIP(namespace, ip string) (*api.Endpoint, error) {
	return m.getEP, m.getEPErr
}
func (m *mockClient) EndpointCreate(*api.EndpointChangeRequest) error { return m.createErr }
func (m *mockClient) EndpointPatch(string, *api.EndpointChangeRequest) error {
	return m.patchErr
}
func (m *mockClient) PolicyPut(string) (*api.Policy, error) {
	if m.policyPutErr != nil {
		return nil, m.policyPutErr
	}
	p := m.policyPolicy
	return &api.Policy{Policy: &p}, nil
}
func (m *mockClient) PolicyGet([]string) (*api.Policy, error) {
	if m.policyGetErr != nil {
		return nil, m.policyGetErr
	}
	p := m.policyPolicy
	return &api.Policy{Policy: &p}, nil
}
func (m *mockClient) PolicyDelete([]string) (*api.Policy, error) {
	if m.policyDelErr != nil {
		return nil, m.policyDelErr
	}
	p := m.policyPolicy
	return &api.Policy{Policy: &p}, nil
}
func (m *mockClient) ListCategories(string) ([]string, error) {
	return m.listCategoriesV, m.listCategoriesE
}
func (m *mockClient) DeleteEndpointByLabel([]string) error {
	return m.deleteByLabelErr
}

func newConfig(m *mockClient) *Config {
	if m.ClientEmulator == nil {
		m.ClientEmulator = &client.ClientEmulator{}
	}
	return NewConfig("t", "pop", m)
}

func TestNewConfigEvent(t *testing.T) {
	e := NewConfigEvent("ns", "1.2.3.4", "if0", map[string]string{"a": "b"})
	assert.Equal(t, "ns", e.Namespace)
	assert.Equal(t, "1.2.3.4", e.IP)
	assert.Equal(t, "if0", e.InterfaceName)
	assert.Equal(t, "b", e.Attributes["a"])
}

func TestGenerateEndpointConfig(t *testing.T) {
	e := NewConfigEvent("ns", "1.2.3.4", "if0", map[string]string{"k": "v"})
	c := e.GenerateEndpointConfig()
	assert.NotNil(t, c)
	assert.Equal(t, "1.2.3.4", *c.Addressing.IPv4)
	assert.Equal(t, "if0", *c.InterfaceName)
	assert.Equal(t, "ns", *c.InterfaceNamespace)
	assert.NotEmpty(t, c.Labels)
}

func TestGenerateEndpointLabels(t *testing.T) {
	// Missing instance label -> appended.
	e := NewConfigEvent("ns", "1.2.3.4", "if0", map[string]string{"k": "", "a": "b"})
	labels := e.GenerateEndpointLabels()
	// Should contain "k" bare, "a=b", and the instance label.
	found := map[string]bool{}
	for _, l := range labels {
		found[l] = true
	}
	assert.True(t, found["k"])
	assert.True(t, found["a=b"])
	assert.True(t, found[utils.FwEndpointKey+"="+utils.FwEndpointValue])

	// Already contains instance label -> not appended twice.
	e2 := NewConfigEvent("ns", "1.2.3.4", "if0", map[string]string{utils.FwEndpointKey: utils.FwEndpointValue})
	labels2 := e2.GenerateEndpointLabels()
	count := 0
	for _, l := range labels2 {
		if l == utils.FwEndpointKey+"="+utils.FwEndpointValue {
			count++
		}
	}
	assert.Equal(t, 1, count)
}

func TestConfig_BasicAccessors(t *testing.T) {
	c := newConfig(&mockClient{})
	assert.Equal(t, "t", c.Name())
	assert.Equal(t, "pop", c.GetPopName())
	assert.False(t, c.IsActive())
	c.SetActive(true)
	assert.True(t, c.IsActive())
}

func TestConfig_RunAndStop(t *testing.T) {
	c := newConfig(&mockClient{})
	c.Run()
	// Send an event; the run loop must pick it up.
	assert.NoError(t, c.Send(&ConfigEvent{Namespace: "ns", IP: "1.1.1.1"}))
	// Give the goroutine time to process.
	time.Sleep(50 * time.Millisecond)
	c.Stop()
}

func TestConfig_Send_Full(t *testing.T) {
	c := NewConfig("t", "pop", &mockClient{ClientEmulator: &client.ClientEmulator{}})
	// Fill the channel
	for i := 0; i < cap(c.configCh); i++ {
		assert.NoError(t, c.Send(&ConfigEvent{}))
	}
	// Next send should fail
	err := c.Send(&ConfigEvent{})
	assert.Error(t, err)
}

func TestConfig_Policies(t *testing.T) {
	m := &mockClient{policyPolicy: "p"}
	c := newConfig(m)
	s, err := c.GetPolicy(nil)
	assert.NoError(t, err)
	assert.Equal(t, "p", s)

	s, err = c.NewPolicy("{}")
	assert.NoError(t, err)
	assert.Equal(t, "p", s)

	s, err = c.UpdatePolicy("{}")
	assert.NoError(t, err)
	assert.Equal(t, "p", s)

	s, err = c.DeletePolicy(nil)
	assert.NoError(t, err)
	assert.Equal(t, "p", s)
}

func TestConfig_Policies_Errors(t *testing.T) {
	m := &mockClient{policyGetErr: errors.New("x"), policyPutErr: errors.New("x"), policyDelErr: errors.New("x")}
	c := newConfig(m)
	_, err := c.GetPolicy(nil)
	assert.Error(t, err)
	_, err = c.NewPolicy("")
	assert.Error(t, err)
	_, err = c.UpdatePolicy("")
	assert.Error(t, err)
	_, err = c.DeletePolicy(nil)
	assert.Error(t, err)
}

func TestConfig_ListWebCategory(t *testing.T) {
	m := &mockClient{listCategoriesV: []string{"a"}}
	c := newConfig(m)
	cs, err := c.ListWebCategory("ns")
	assert.NoError(t, err)
	assert.Equal(t, []string{"a"}, cs)

	m.listCategoriesE = errors.New("e")
	_, err = c.ListWebCategory("ns")
	assert.Error(t, err)
}

func TestConfig_DelEndpoint(t *testing.T) {
	m := &mockClient{}
	c := newConfig(m)
	assert.NoError(t, c.DelEndpoint("ns", "id"))
	m.deleteByLabelErr = errors.New("x")
	assert.Error(t, c.DelEndpoint("ns", "id"))
}

func TestConfig_handleConfigEvent_createBranch(t *testing.T) {
	// getEP returns nil -> should create.
	m := &mockClient{getEP: nil}
	c := newConfig(m)
	c.handleConfigEvent(&ConfigEvent{Namespace: "ns", IP: "1.2.3.4", Attributes: map[string]string{"k": "v"}})

	// Create error branch.
	m.createErr = errors.New("boom")
	c.handleConfigEvent(&ConfigEvent{Namespace: "ns", IP: "1.2.3.4"})
}

func TestConfig_handleConfigEvent_patchBranch(t *testing.T) {
	id := int32(10)
	m := &mockClient{getEP: &api.Endpoint{ID: &id}}
	c := newConfig(m)
	// Success branch
	c.handleConfigEvent(&ConfigEvent{Namespace: "ns", IP: "1.2.3.4"})
	// Patch error branch
	m.patchErr = errors.New("patch")
	c.handleConfigEvent(&ConfigEvent{Namespace: "ns", IP: "1.2.3.4"})
}

func TestConfig_handleConfigEvent_getError(t *testing.T) {
	m := &mockClient{getEPErr: errors.New("unexpected")}
	c := newConfig(m)
	// Non-ErrEndpointNotExist error should short-circuit.
	c.handleConfigEvent(&ConfigEvent{Namespace: "ns", IP: "1.2.3.4"})
}

func TestMatchAll(t *testing.T) {
	assert.False(t, matchAll("foo", nil))
	assert.True(t, matchAll("foo/bar", []string{"foo", "bar"}))
	assert.False(t, matchAll("foo", []string{"xyz"}))
}
