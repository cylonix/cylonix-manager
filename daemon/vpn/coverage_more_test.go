// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	dt "cylonix/sase/pkg/test/daemon"
	"testing"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestVpnService_MetaAndStop(t *testing.T) {
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	assert.Equal(t, "vpn api handler", svc.Name())
	assert.NotNil(t, svc.Logger())
	assert.NoError(t, svc.Start())
	svc.Stop()
}

func TestVpnService_ActiveWgName_Invalid(t *testing.T) {
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	// Unknown wg name -> empty string + log.
	got := svc.ActiveWgName("ns-active-wg", "no-such-wg")
	assert.Equal(t, "", got)
}

func TestVpnService_GetWgGatewayPeers(t *testing.T) {
	setupFakeHeadscale(t)
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	// Even without any wg nodes it should return empty lists.
	all, online, err := svc.getWgGatewayPeers(&types.WgInfo{Namespace: "ns-getwg"})
	assert.NoError(t, err)
	assert.Empty(t, all)
	assert.Empty(t, online)
}

func TestVpnService_Resource(t *testing.T) {
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	// resource() delegates to daemon.ResourceService; emulator returns nil.
	_ = svc.resource()
}

func TestVpnService_NameServers(t *testing.T) {
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	_ = svc.NameServers("ns", "pop")
}

func TestWgHandler_ListNodes_Admin(t *testing.T) {
	setupFakeHeadscale(t)
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	wh := svc.wgHandler.(*wgHandlerImpl)

	// Nil token -> falls back to checking gateway-enabled on anon user and returns empty.
	total, list, err := wh.ListNodes(nil, api.ListWgNodesRequestObject{})
	assert.NoError(t, err)
	assert.Equal(t, 0, total)
	_ = list

	// Admin token.
	uid, _ := types.NewID()
	tok := &utils.UserTokenData{
		Token:       "t",
		Namespace:   "ns-wg-list",
		UserID:      uid.UUID(),
		IsAdminUser: true,
	}
	total, list, err = wh.ListNodes(tok, api.ListWgNodesRequestObject{})
	assert.NoError(t, err)
	_ = list
	_ = total

	// Sysadmin token.
	tokSys := &utils.UserTokenData{
		Token:      "t",
		Namespace:  "ns-wg-list",
		UserID:     uid.UUID(),
		IsAdminUser: true,
		IsSysAdmin: true,
	}
	_, _, err = wh.ListNodes(tokSys, api.ListWgNodesRequestObject{})
	assert.NoError(t, err)
}

func TestWgHandler_SetNodeAdminState_Errors(t *testing.T) {
	setupFakeHeadscale(t)
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	wh := svc.wgHandler.(*wgHandlerImpl)

	// Nil token -> unauthorized.
	err := wh.SetNodeAdminState(nil, api.SetWgNodeAdminStateRequestObject{})
	assert.Error(t, err)

	uid, _ := types.NewID()
	tok := &utils.UserTokenData{
		Token:       "t",
		Namespace:   "ns-wg-state",
		UserID:      uid.UUID(),
		IsAdminUser: true,
	}

	// Missing body.
	err = wh.SetNodeAdminState(tok, api.SetWgNodeAdminStateRequestObject{})
	assert.Error(t, err)

	// Invalid state value.
	err = wh.SetNodeAdminState(tok, api.SetWgNodeAdminStateRequestObject{
		Body: &models.WgAdminState{State: "garbage"},
	})
	assert.Error(t, err)

	// Invalid wg id.
	err = wh.SetNodeAdminState(tok, api.SetWgNodeAdminStateRequestObject{
		WgID: "not-a-uuid",
		Body: &models.WgAdminState{State: models.WgAdminStateStateDown},
	})
	assert.Error(t, err)

	// Unknown wg id -> unauthorized (ErrWgNodeNotExists branch).
	err = wh.SetNodeAdminState(tok, api.SetWgNodeAdminStateRequestObject{
		WgID: uuid.New().String(),
		Body: &models.WgAdminState{State: models.WgAdminStateStateDown},
	})
	assert.Error(t, err)
}

func TestWgHandler_DeleteNodes_Errors(t *testing.T) {
	setupFakeHeadscale(t)
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	wh := svc.wgHandler.(*wgHandlerImpl)

	err := wh.DeleteNodes(nil, api.DeleteWgNodesRequestObject{})
	assert.Error(t, err)

	uid, _ := types.NewID()
	tok := &utils.UserTokenData{
		Token:       "t",
		Namespace:   "ns-wg-del",
		UserID:      uid.UUID(),
		IsAdminUser: true,
	}
	ids := []uuid.UUID{uuid.New()}
	err = wh.DeleteNodes(tok, api.DeleteWgNodesRequestObject{Body: &ids})
	// Unknown id is silently ignored.
	assert.NoError(t, err)
}
