// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package fwconfig

import (
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewEmulator(t *testing.T) {
	e := NewEmulator()
	assert.NotNil(t, e)
	assert.True(t, e.IsActive())
	assert.Equal(t, "", e.Name())
	assert.Equal(t, "", e.GetPopName())
}

func TestEmulator_Send(t *testing.T) {
	e := NewEmulator()
	assert.NoError(t, e.Send(&ConfigEvent{}))
	e.SendError = true
	assert.Error(t, e.Send(&ConfigEvent{}))
}

func TestEmulator_NoopMethods(t *testing.T) {
	e := NewEmulator()
	e.HandleConfigEvent(nil)
	e.SetActive(true)
	e.Run()
	e.Stop()
}

func TestEmulator_Policies(t *testing.T) {
	e := NewEmulator()
	s, err := e.GetPolicy(nil)
	assert.NoError(t, err)
	assert.Equal(t, "", s)
	s, err = e.NewPolicy("{}")
	assert.NoError(t, err)
	assert.Equal(t, "", s)
	s, err = e.UpdatePolicy("{}")
	assert.NoError(t, err)
	assert.Equal(t, "", s)
	s, err = e.DeletePolicy(nil)
	assert.NoError(t, err)
	assert.Equal(t, "", s)
}

func TestEmulator_ListWebCategory(t *testing.T) {
	e := NewEmulator()
	e.WebCategories = []string{"a"}
	cs, err := e.ListWebCategory("ns")
	assert.NoError(t, err)
	assert.Equal(t, []string{"a"}, cs)
}

func TestEmulator_DelEndpoint(t *testing.T) {
	e := NewEmulator()
	assert.NoError(t, e.DelEndpoint("ns", "id"))
	e.DeleteEndpointError = true
	assert.Error(t, e.DelEndpoint("ns", "id"))
}

func TestEmulator_EndpointIdentityByLabels(t *testing.T) {
	e := NewEmulator()
	e.Endpoints = []string{"x"}
	e.EndpointMap = map[string][]string{"k": {"v"}}
	ids, m, err := e.EndpointIdentityByLabels("ns", nil, "", nil)
	assert.NoError(t, err)
	assert.Equal(t, []string{"x"}, ids)
	assert.Equal(t, []string{"v"}, m["k"])
}

func TestServiceEmulator(t *testing.T) {
	s := NewServiceEmulator()
	assert.False(t, s.Enabled("ns", types.UserID(uuid.New()), types.DeviceID(uuid.New())))
	assert.Empty(t, s.List("ns", false))
	s.Agents = []ConfigInterface{NewEmulator()}
	assert.True(t, s.Enabled("ns", types.UserID(uuid.New()), types.DeviceID(uuid.New())))
	assert.Len(t, s.List("ns", false), 1)

	assert.NoError(t, s.AddEndpoint("ns", types.UserID(uuid.New()), types.DeviceID(uuid.New()), "1.2.3.4", "wg0"))
	assert.NoError(t, s.DelEndpoint("ns", "id", "1.2.3.4", "wg0"))
}
