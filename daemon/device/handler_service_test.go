// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package device

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakeDeviceHandler struct {
	err          error
	devices      *models.DeviceList
	approvalTot  int
	approvalList []models.DeviceApprovalRecord
}

func (f *fakeDeviceHandler) GetDevices(_ any, _ api.GetDevicesRequestObject) (*models.DeviceList, error) {
	return f.devices, f.err
}
func (f *fakeDeviceHandler) PutDevice(_ any, _ api.PutDeviceRequestObject) error {
	return f.err
}
func (f *fakeDeviceHandler) PostDevice(_ any, _ api.PostDeviceRequestObject) error {
	return f.err
}
func (f *fakeDeviceHandler) DeleteDevices(_ any, _ api.DeleteDevicesRequestObject) error {
	return f.err
}
func (f *fakeDeviceHandler) GetApprovalRecords(_ any, _ api.ListDeviceApprovalRecordsRequestObject) (int, []models.DeviceApprovalRecord, error) {
	return f.approvalTot, f.approvalList, f.err
}
func (f *fakeDeviceHandler) ApproveDevices(_ any, _ api.ApproveDevicesRequestObject) error {
	return f.err
}
func (f *fakeDeviceHandler) DeleteApprovalRecords(_ any, _ api.DeleteDeviceApprovalRecordsRequestObject) error {
	return f.err
}

func newDeviceSvc(h *fakeDeviceHandler) *DeviceService {
	return &DeviceService{handler: h, logger: logrus.NewEntry(logrus.New())}
}

func TestDeviceService_MetaAndRegister(t *testing.T) {
	s := newDeviceSvc(&fakeDeviceHandler{})
	assert.Equal(t, "device api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
	d := &api.StrictServer{}
	assert.NoError(t, s.Register(d))
	assert.NotNil(t, d.GetDevicesHandler)
	assert.NotNil(t, d.ApproveDevicesHandler)
}

func TestGetDevices_Branches(t *testing.T) {
	s := newDeviceSvc(&fakeDeviceHandler{devices: &models.DeviceList{}})
	resp, _ := s.getDevices(context.Background(), api.GetDevicesRequestObject{})
	assert.IsType(t, api.GetDevices200JSONResponse{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrInternalErr})
	resp, _ = s.getDevices(context.Background(), api.GetDevicesRequestObject{})
	assert.IsType(t, api.GetDevices500JSONResponse{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrModelUnauthorized})
	resp, _ = s.getDevices(context.Background(), api.GetDevicesRequestObject{})
	assert.IsType(t, api.GetDevices401Response{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: errors.New("x")})
	resp, _ = s.getDevices(context.Background(), api.GetDevicesRequestObject{})
	assert.IsType(t, api.GetDevices400JSONResponse{}, resp)
}

func TestPutDevice_Branches(t *testing.T) {
	s := newDeviceSvc(&fakeDeviceHandler{})
	resp, _ := s.putDevice(context.Background(), api.PutDeviceRequestObject{})
	assert.IsType(t, api.PutDevice200Response{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrInternalErr})
	resp, _ = s.putDevice(context.Background(), api.PutDeviceRequestObject{})
	assert.IsType(t, api.PutDevice500JSONResponse{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrModelUnauthorized})
	resp, _ = s.putDevice(context.Background(), api.PutDeviceRequestObject{})
	assert.IsType(t, api.PutDevice401Response{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: errors.New("x")})
	resp, _ = s.putDevice(context.Background(), api.PutDeviceRequestObject{})
	assert.IsType(t, api.PutDevice400JSONResponse{}, resp)
}

func TestPostDevice_Branches(t *testing.T) {
	s := newDeviceSvc(&fakeDeviceHandler{})
	resp, _ := s.postDevice(context.Background(), api.PostDeviceRequestObject{})
	assert.IsType(t, api.PostDevice200Response{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrInternalErr})
	resp, _ = s.postDevice(context.Background(), api.PostDeviceRequestObject{})
	assert.IsType(t, api.PostDevice500JSONResponse{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrModelUnauthorized})
	resp, _ = s.postDevice(context.Background(), api.PostDeviceRequestObject{})
	assert.IsType(t, api.PostDevice401Response{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: errors.New("x")})
	resp, _ = s.postDevice(context.Background(), api.PostDeviceRequestObject{})
	assert.IsType(t, api.PostDevice400JSONResponse{}, resp)
}

func TestDeleteDevices_Branches(t *testing.T) {
	s := newDeviceSvc(&fakeDeviceHandler{})
	resp, _ := s.deleteDevices(context.Background(), api.DeleteDevicesRequestObject{})
	assert.IsType(t, api.DeleteDevices200Response{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrInternalErr})
	resp, _ = s.deleteDevices(context.Background(), api.DeleteDevicesRequestObject{})
	assert.IsType(t, api.DeleteDevices500JSONResponse{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrModelUnauthorized})
	resp, _ = s.deleteDevices(context.Background(), api.DeleteDevicesRequestObject{})
	assert.IsType(t, api.DeleteDevices401Response{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: errors.New("x")})
	resp, _ = s.deleteDevices(context.Background(), api.DeleteDevicesRequestObject{})
	assert.IsType(t, api.DeleteDevices400JSONResponse{}, resp)
}

func TestDeviceDeleteApprovalRecords_Branches(t *testing.T) {
	s := newDeviceSvc(&fakeDeviceHandler{})
	resp, _ := s.deleteApprovalRecords(context.Background(), api.DeleteDeviceApprovalRecordsRequestObject{})
	assert.IsType(t, api.DeleteDeviceApprovalRecords200TextResponse(""), resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrInternalErr})
	resp, _ = s.deleteApprovalRecords(context.Background(), api.DeleteDeviceApprovalRecordsRequestObject{})
	assert.IsType(t, api.DeleteDeviceApprovalRecords500JSONResponse{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrModelUnauthorized})
	resp, _ = s.deleteApprovalRecords(context.Background(), api.DeleteDeviceApprovalRecordsRequestObject{})
	assert.IsType(t, api.DeleteDeviceApprovalRecords401Response{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: errors.New("x")})
	resp, _ = s.deleteApprovalRecords(context.Background(), api.DeleteDeviceApprovalRecordsRequestObject{})
	assert.IsType(t, api.DeleteDeviceApprovalRecords400JSONResponse{}, resp)
}

func TestDeviceGetApprovalRecords_Branches(t *testing.T) {
	s := newDeviceSvc(&fakeDeviceHandler{approvalTot: 1})
	resp, _ := s.getApprovalRecords(context.Background(), api.ListDeviceApprovalRecordsRequestObject{})
	assert.IsType(t, api.ListDeviceApprovalRecords200JSONResponse{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrInternalErr})
	resp, _ = s.getApprovalRecords(context.Background(), api.ListDeviceApprovalRecordsRequestObject{})
	assert.IsType(t, api.ListDeviceApprovalRecords500JSONResponse{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrModelUnauthorized})
	resp, _ = s.getApprovalRecords(context.Background(), api.ListDeviceApprovalRecordsRequestObject{})
	assert.IsType(t, api.ListDeviceApprovalRecords401Response{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: errors.New("x")})
	resp, _ = s.getApprovalRecords(context.Background(), api.ListDeviceApprovalRecordsRequestObject{})
	assert.IsType(t, api.ListDeviceApprovalRecords400JSONResponse{}, resp)
}

func TestApproveDevices_Branches(t *testing.T) {
	s := newDeviceSvc(&fakeDeviceHandler{})
	resp, _ := s.approveDevices(context.Background(), api.ApproveDevicesRequestObject{})
	assert.IsType(t, api.ApproveDevices200TextResponse(""), resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrInternalErr})
	resp, _ = s.approveDevices(context.Background(), api.ApproveDevicesRequestObject{})
	assert.IsType(t, api.ApproveDevices500JSONResponse{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: common.ErrModelUnauthorized})
	resp, _ = s.approveDevices(context.Background(), api.ApproveDevicesRequestObject{})
	assert.IsType(t, api.ApproveDevices401Response{}, resp)

	s = newDeviceSvc(&fakeDeviceHandler{err: errors.New("x")})
	resp, _ = s.approveDevices(context.Background(), api.ApproveDevicesRequestObject{})
	assert.IsType(t, api.ApproveDevices400JSONResponse{}, resp)
}
