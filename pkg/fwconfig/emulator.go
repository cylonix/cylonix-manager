// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package fwconfig

import (
	"cylonix/sase/daemon/db/types"
	"errors"
)

type Emulator struct {
	Active              bool
	DeleteEndpointError bool
	Endpoints           []string
	EndpointMap         map[string][]string
	PopName             string
	SendError           bool
	WebCategories       []string
}

func NewEmulator() *Emulator {
	return &Emulator{
		Active: true,
	}
}

func (e *Emulator) Send(tce *ConfigEvent) error {
	if e.SendError {
		return errors.New("failed to send")
	}
	return nil
}
func (e *Emulator) HandleConfigEvent(*ConfigEvent) {

}
func (e *Emulator) IsActive() bool {
	return e.Active
}
func (e *Emulator) GetPopName() string {
	return e.PopName
}
func (e *Emulator) SetActive(isActive bool) {

}
func (e *Emulator) Run() {

}
func (e *Emulator) Stop() {

}
func (e *Emulator) Name() string {
	return ""
}
func (e *Emulator) GetPolicy(labels []string) (string, error) {
	return "", nil
}
func (e *Emulator) NewPolicy(policyJSON string) (string, error) {
	return "", nil
}
func (e *Emulator) UpdatePolicy(policyJSON string) (string, error) {
	return "", nil
}
func (e *Emulator) DeletePolicy(labels []string) (string, error) {
	return "", nil
}
func (e *Emulator) ListWebCategory(namespace string) ([]string, error) {
	return e.WebCategories, nil
}
func (e *Emulator) DelEndpoint(namespace string, id string) error {
	if e.DeleteEndpointError {
		return errors.New("failed to delete device")
	}
	return nil
}
func (e *Emulator) EndpointIdentityByLabels(namespace string, labels map[string]string, mapKey string, mapKeyList []string) ([]string, map[string][]string, error) {
	return e.Endpoints, e.EndpointMap, nil
}

type ServiceEmulator struct {
	Agents           []ConfigInterface
	AddEndPointError error
	DelEndpointError error
}

func NewServiceEmulator() *ServiceEmulator {
	return &ServiceEmulator{}
}

// ServiceEmulator implements ConfigService interface.
func (s *ServiceEmulator) Enabled(namespace string, userID types.UserID, deviceID types.DeviceID) bool {
	return len(s.Agents) > 0
}
func (s *ServiceEmulator) List(namespace string, onlyActive bool) []ConfigInterface {
	return s.Agents
}
func (s *ServiceEmulator) AddEndpoint(namespace string, userID types.UserID, deviceID types.DeviceID, ip, wgName string) error {
	return s.AddEndPointError
}
func (s *ServiceEmulator) DelEndpoint(namespace, endpointID, ip, wgName string) error {
	return s.DelEndpointError
}
