package client

import (
	api "github.com/cylonix/fw"
)

type ClientInterface interface {
	EndpointGet(id string) (*api.Endpoint, error)
	EndpointGetWithIP(namespace, ip string) (*api.Endpoint, error)
	EndpointLogGet(id string) ([]api.EndpointStatusChange, error)
	EndpointHealthGet(id string) (*api.EndpointHealth, error)
	EndpointConfigGet(id string) (*api.EndpointConfigurationStatus, error)
	EndpointLabelsGet(id string) (*api.LabelConfiguration, error)

	PolicyPut(policyJSON string) (*api.Policy, error)
	PolicyGet(labels []string) (*api.Policy, error)
	PolicyDelete(labels []string) (*api.Policy, error)
	ListCategories(namespace string) ([]string, error)

	VxlanGet() ([][]api.RemoteVxlanTunnel, error)
	VxlanCreate(config []api.RemoteVxlanTunnel) error

	EndpointCreate(change *api.EndpointChangeRequest) error
	EndpointPatch(string, *api.EndpointChangeRequest) error
	DeleteEndpointByLabel([]string) error
}

type ClientEmulator struct {
}

func (c *ClientEmulator) DeleteEndpointByLabel([]string) error {
	return nil
}
func (c *ClientEmulator) EndpointPatch(string, *api.EndpointChangeRequest) error {
	return nil
}
func (c *ClientEmulator) EndpointCreate(change *api.EndpointChangeRequest) error {
	return nil
}
func (c *ClientEmulator) EndpointGet(id string) (*api.Endpoint, error) {
	return &api.Endpoint{}, nil
}
func (c *ClientEmulator) EndpointGetWithIP(namespace, ip string) (*api.Endpoint, error) {
	return &api.Endpoint{}, nil
}
func (c *ClientEmulator) EndpointLogGet(id string) ([]api.EndpointStatusChange, error) {
	return []api.EndpointStatusChange{}, nil
}
func (c *ClientEmulator) EndpointHealthGet(id string) (*api.EndpointHealth, error) {
	return &api.EndpointHealth{}, nil
}
func (c *ClientEmulator) EndpointConfigGet(id string) (*api.EndpointConfigurationStatus, error) {
	return &api.EndpointConfigurationStatus{}, nil
}
func (c *ClientEmulator) EndpointLabelsGet(id string) (*api.LabelConfiguration, error) {
	return &api.LabelConfiguration{}, nil
}
func (c *ClientEmulator) PolicyPut(policyJSON string) (*api.Policy, error) {
	return &api.Policy{}, nil
}
func (c *ClientEmulator) PolicyPost(policyJSON string) (*api.Policy, error) {
	return &api.Policy{}, nil
}
func (c *ClientEmulator) PolicyGet(labels []string) (*api.Policy, error) {
	return &api.Policy{}, nil
}
func (c *ClientEmulator) PolicyDelete(labels []string) (*api.Policy, error) {
	return &api.Policy{}, nil
}
func (c *ClientEmulator) PolicyResolveGet(traceSelector *api.TraceSelector) (*api.PolicyTraceResult, error) {
	return &api.PolicyTraceResult{}, nil
}
func (c *ClientEmulator) ListCategories(namespace string) ([]string, error) {
	return []string{}, nil
}
func (c *ClientEmulator) VxlanGet() ([][]api.RemoteVxlanTunnel, error) {
	return [][]api.RemoteVxlanTunnel{}, nil
}
func (c *ClientEmulator) VxlanCreate(config []api.RemoteVxlanTunnel) error {
	return nil
}
