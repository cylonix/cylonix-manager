// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

type fakeWgHandler struct {
	list         *models.WgDeviceList
	listErr      error
	addRet       string
	addErr       error
	delErr       error
	listNodesRet []models.WgNode
	listNodesTot int
	listNodesErr error
	delNodesErr  error
	adminStateErr error
}

func (f *fakeWgHandler) List(_ any, _ api.ListVpnDeviceRequestObject) (*models.WgDeviceList, error) {
	return f.list, f.listErr
}
func (f *fakeWgHandler) Add(_ any, _ api.AddVpnDeviceRequestObject) (string, error) {
	return f.addRet, f.addErr
}
func (f *fakeWgHandler) Delete(_ any, _ api.DeleteVpnDevicesRequestObject) error {
	return f.delErr
}
func (f *fakeWgHandler) ListNodes(_ any, _ api.ListWgNodesRequestObject) (int, []models.WgNode, error) {
	return f.listNodesTot, f.listNodesRet, f.listNodesErr
}
func (f *fakeWgHandler) DeleteNodes(_ any, _ api.DeleteWgNodesRequestObject) error {
	return f.delNodesErr
}
func (f *fakeWgHandler) SetNodeAdminState(_ any, _ api.SetWgNodeAdminStateRequestObject) error {
	return f.adminStateErr
}

func newVpnSvcWithHandler(h wgHandler) *VpnService {
	return &VpnService{wgHandler: h, logger: testLogger}
}

func TestVpnService_Meta(t *testing.T) {
	s := newVpnSvcWithHandler(&fakeWgHandler{})
	assert.Equal(t, "vpn api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
	d := &api.StrictServer{}
	assert.NoError(t, s.Register(d))
	assert.NotNil(t, d.ListVpnDeviceHandler)
}

func TestListDevice_Branches(t *testing.T) {
	list := &models.WgDeviceList{}
	s := newVpnSvcWithHandler(&fakeWgHandler{list: list})
	resp, _ := s.listDevice(context.Background(), api.ListVpnDeviceRequestObject{})
	assert.IsType(t, api.ListVpnDevice200JSONResponse{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{listErr: common.ErrInternalErr})
	resp, _ = s.listDevice(context.Background(), api.ListVpnDeviceRequestObject{})
	assert.IsType(t, api.ListVpnDevice500JSONResponse{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{listErr: common.ErrModelUnauthorized})
	resp, _ = s.listDevice(context.Background(), api.ListVpnDeviceRequestObject{})
	assert.IsType(t, api.ListVpnDevice401Response{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{listErr: errors.New("x")})
	resp, _ = s.listDevice(context.Background(), api.ListVpnDeviceRequestObject{})
	assert.IsType(t, api.ListVpnDevice400JSONResponse{}, resp)
}

func TestAddDevice_Branches(t *testing.T) {
	s := newVpnSvcWithHandler(&fakeWgHandler{addRet: "ok"})
	resp, _ := s.addDevice(context.Background(), api.AddVpnDeviceRequestObject{})
	assert.IsType(t, api.AddVpnDevice200TextResponse(""), resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{addErr: common.ErrInternalErr})
	resp, _ = s.addDevice(context.Background(), api.AddVpnDeviceRequestObject{})
	assert.IsType(t, api.AddVpnDevice500JSONResponse{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{addErr: common.ErrModelUnauthorized})
	resp, _ = s.addDevice(context.Background(), api.AddVpnDeviceRequestObject{})
	assert.IsType(t, api.AddVpnDevice401Response{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{addErr: errors.New("x")})
	resp, _ = s.addDevice(context.Background(), api.AddVpnDeviceRequestObject{})
	assert.IsType(t, api.AddVpnDevice400JSONResponse{}, resp)
}

func TestDeleteDevices_Branches(t *testing.T) {
	s := newVpnSvcWithHandler(&fakeWgHandler{})
	resp, _ := s.deleteDevices(context.Background(), api.DeleteVpnDevicesRequestObject{})
	assert.IsType(t, api.DeleteVpnDevices200Response{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{delErr: common.ErrInternalErr})
	resp, _ = s.deleteDevices(context.Background(), api.DeleteVpnDevicesRequestObject{})
	assert.IsType(t, api.DeleteVpnDevices500JSONResponse{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{delErr: common.ErrModelUnauthorized})
	resp, _ = s.deleteDevices(context.Background(), api.DeleteVpnDevicesRequestObject{})
	assert.IsType(t, api.DeleteVpnDevices401Response{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{delErr: errors.New("x")})
	resp, _ = s.deleteDevices(context.Background(), api.DeleteVpnDevicesRequestObject{})
	assert.IsType(t, api.DeleteVpnDevices400JSONResponse{}, resp)
}

func TestListWgNodes_Branches(t *testing.T) {
	s := newVpnSvcWithHandler(&fakeWgHandler{listNodesTot: 1, listNodesRet: []models.WgNode{{}}})
	resp, _ := s.listWgNodes(context.Background(), api.ListWgNodesRequestObject{})
	assert.IsType(t, api.ListWgNodes200JSONResponse{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{listNodesErr: common.ErrInternalErr})
	resp, _ = s.listWgNodes(context.Background(), api.ListWgNodesRequestObject{})
	assert.IsType(t, api.ListWgNodes500JSONResponse{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{listNodesErr: common.ErrModelUnauthorized})
	resp, _ = s.listWgNodes(context.Background(), api.ListWgNodesRequestObject{})
	assert.IsType(t, api.ListWgNodes401Response{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{listNodesErr: errors.New("x")})
	resp, _ = s.listWgNodes(context.Background(), api.ListWgNodesRequestObject{})
	assert.IsType(t, api.ListWgNodes400JSONResponse{}, resp)
}

func TestDeleteWgNodes_Branches(t *testing.T) {
	s := newVpnSvcWithHandler(&fakeWgHandler{})
	resp, _ := s.deleteWgNodes(context.Background(), api.DeleteWgNodesRequestObject{})
	assert.IsType(t, api.DeleteWgNodes200Response{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{delNodesErr: common.ErrInternalErr})
	resp, _ = s.deleteWgNodes(context.Background(), api.DeleteWgNodesRequestObject{})
	assert.IsType(t, api.DeleteWgNodes500JSONResponse{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{delNodesErr: common.ErrModelUnauthorized})
	resp, _ = s.deleteWgNodes(context.Background(), api.DeleteWgNodesRequestObject{})
	assert.IsType(t, api.DeleteWgNodes401Response{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{delNodesErr: errors.New("x")})
	resp, _ = s.deleteWgNodes(context.Background(), api.DeleteWgNodesRequestObject{})
	assert.IsType(t, api.DeleteWgNodes400JSONResponse{}, resp)
}

func TestSetWgNodeAdminState_Branches(t *testing.T) {
	s := newVpnSvcWithHandler(&fakeWgHandler{})
	resp, _ := s.setWgNodeAdminState(context.Background(), api.SetWgNodeAdminStateRequestObject{})
	assert.IsType(t, api.SetWgNodeAdminState200Response{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{adminStateErr: common.ErrInternalErr})
	resp, _ = s.setWgNodeAdminState(context.Background(), api.SetWgNodeAdminStateRequestObject{})
	assert.IsType(t, api.SetWgNodeAdminState500JSONResponse{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{adminStateErr: common.ErrModelUnauthorized})
	resp, _ = s.setWgNodeAdminState(context.Background(), api.SetWgNodeAdminStateRequestObject{})
	assert.IsType(t, api.SetWgNodeAdminState401Response{}, resp)

	s = newVpnSvcWithHandler(&fakeWgHandler{adminStateErr: errors.New("x")})
	resp, _ = s.setWgNodeAdminState(context.Background(), api.SetWgNodeAdminStateRequestObject{})
	assert.IsType(t, api.SetWgNodeAdminState400JSONResponse{}, resp)
}
