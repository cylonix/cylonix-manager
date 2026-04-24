// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/fwconfig"
	dt "cylonix/sase/pkg/test/daemon"
	"testing"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestWgHandler_List(t *testing.T) {
	d := dt.NewEmulator()
	f := fwconfig.NewServiceEmulator()
	s := NewService(d, f, testLogger)
	nh := NewNodeHandler(s)
	h := newWgHandlerImpl(d, f, nh, testLogger)

	// No token -> unauthorized.
	_, err := h.List(nil, api.ListVpnDeviceRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// With a non-admin user token.
	list, err := h.List(testUserToken, api.ListVpnDeviceRequestObject{})
	assert.NoError(t, err)
	assert.NotNil(t, list)

	// With a sysadmin token.
	sysToken := &utils.UserTokenData{
		Token:       "sys",
		Namespace:   testNamespace,
		UserID:      uuid.New(),
		IsAdminUser: true,
		IsSysAdmin:  true,
	}
	list, err = h.List(sysToken, api.ListVpnDeviceRequestObject{})
	assert.NoError(t, err)
	assert.NotNil(t, list)
}

func TestWgHandler_ListNodes(t *testing.T) {
	d := dt.NewEmulator()
	f := fwconfig.NewServiceEmulator()
	s := NewService(d, f, testLogger)
	nh := NewNodeHandler(s)
	h := newWgHandlerImpl(d, f, nh, testLogger)

	// Non-admin path returns 0/empty because no gateway is enabled.
	total, list, err := h.ListNodes(nil, api.ListWgNodesRequestObject{})
	assert.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, list)

	// Non-admin user, no gateway enabled -> 0/nil.
	total, list, err = h.ListNodes(testUserToken, api.ListWgNodesRequestObject{})
	assert.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, list)
}

func TestWgHandler_DeleteNodes(t *testing.T) {
	d := dt.NewEmulator()
	f := fwconfig.NewServiceEmulator()
	s := NewService(d, f, testLogger)
	nh := NewNodeHandler(s)
	h := newWgHandlerImpl(d, f, nh, testLogger)

	// No token -> unauthorized.
	err := h.DeleteNodes(nil, api.DeleteWgNodesRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Non-admin user: unauthorized.
	err = h.DeleteNodes(testUserToken, api.DeleteWgNodesRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}

func TestWgHandler_SetNodeAdminState(t *testing.T) {
	d := dt.NewEmulator()
	f := fwconfig.NewServiceEmulator()
	s := NewService(d, f, testLogger)
	nh := NewNodeHandler(s)
	h := newWgHandlerImpl(d, f, nh, testLogger)

	err := h.SetNodeAdminState(nil, api.SetWgNodeAdminStateRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	err = h.SetNodeAdminState(testUserToken, api.SetWgNodeAdminStateRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}
