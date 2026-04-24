// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon_test

import (
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewEmulator(t *testing.T) {
	e := NewEmulator()
	assert.NotNil(t, e)
}

func TestEmulator_AllMethods(t *testing.T) {
	e := NewEmulator()
	assert.NoError(t, e.AddDnsRecord("a", "1.2.3.4"))
	assert.NoError(t, e.DelDnsRecord("a", "1.2.3.4"))
	assert.Nil(t, e.AppTask())
	assert.Equal(t, "", e.DefaultMeshMode("", nil))
	assert.Nil(t, e.EsClient())
	assert.Nil(t, e.FwConfigService())
	assert.Nil(t, e.GlobalConfig())
	assert.False(t, e.IsExitNodeSupported("ns", types.UserID(uuid.New()), types.DeviceID(uuid.New())))
	_, err := e.NamespaceInfo("ns")
	assert.Error(t, err)
	assert.Nil(t, e.ResourceService())
	assert.NotNil(t, e.Viper())
}
