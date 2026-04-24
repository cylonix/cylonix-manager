// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package resource_test

import (
	"testing"

	"github.com/cylonix/supervisor"
	"github.com/cylonix/wg_agent"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewEmulator(t *testing.T) {
	e := NewEmulator()
	assert.NotNil(t, e)
}

func TestWgPopName(t *testing.T) {
	e := NewEmulator()
	_, err := e.PopNameForWg("ns", "wg")
	assert.Error(t, err)

	e.SetWgPopName("ns", "wg", "pop1")
	name, err := e.PopNameForWg("ns", "wg")
	assert.NoError(t, err)
	assert.Equal(t, "pop1", name)

	e.DelWgPopName("ns", "wg")
	_, err = e.PopNameForWg("ns", "wg")
	assert.Error(t, err)
}

func TestWgResourceDetail(t *testing.T) {
	e := NewEmulator()
	_, err := e.WgResourceDetail("ns", "wg")
	assert.Error(t, err)

	detail := &wg_agent.WgNamespaceDetail{Name: "wg"}
	e.SetWgResourceDetail("ns", "wg", detail)
	out, err := e.WgResourceDetail("ns", "wg")
	assert.NoError(t, err)
	assert.Equal(t, "wg", out.Name)

	e.DelWgResourceDetail("ns", "wg")
	_, err = e.WgResourceDetail("ns", "wg")
	assert.Error(t, err)
}

func TestWgAccessPoints(t *testing.T) {
	e := NewEmulator()
	_, err := e.WgAccessPoints("ns", "id")
	assert.Error(t, err)

	e.SetWgAccessPoints("ns", "id", []string{"a"})
	aps, err := e.WgAccessPoints("ns", "id")
	assert.NoError(t, err)
	assert.Equal(t, []string{"a"}, aps)

	list, err := e.AccessPoints("ns")
	assert.NoError(t, err)
	assert.Len(t, list, 1)

	e.DelWgAccessPoints("ns", "id")
	_, err = e.WgAccessPoints("ns", "id")
	assert.Error(t, err)
}

func TestAccessPoints_ErrorOnNil(t *testing.T) {
	e := NewEmulator()
	e.AccessListErrorOnNil = true
	_, err := e.AccessPoints("ns")
	assert.Error(t, err)
}

func TestNamespaceList(t *testing.T) {
	e := NewEmulator()
	e.NamespacesListErrOnNil = true
	_, err := e.NamespaceList()
	assert.Error(t, err)

	e.Namespaces = []*supervisor.FullNamespace{{Name: "a"}}
	list, err := e.NamespaceList()
	assert.NoError(t, err)
	assert.Len(t, list, 1)
}

func TestNotImplementedMethods(t *testing.T) {
	e := NewEmulator()
	_, err := e.AllowedIPs("ns", "wg")
	assert.Error(t, err)
	_, err = e.RelayServers("ns")
	assert.Error(t, err)
	assert.Error(t, e.Run())
	e.SetLogLevel(logrus.DebugLevel)
	_, err = e.SubnetRouterDeviceID("ns", "wg")
	assert.Error(t, err)
	_, err = e.WgNameByDeviceID("ns", "d")
	assert.Error(t, err)
}
