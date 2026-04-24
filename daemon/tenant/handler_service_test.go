// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tenant

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

type fakeTenantHandler struct {
	err           error
	configTotal   int
	configList    []models.TenantConfig
	addConfig     string
	regUpdate     string
	approvalTotal int
	approvalList  []models.TenantApproval
	summary       models.SummaryStatsList
	isAvailable   bool
}

func (f *fakeTenantHandler) ListConfig(_ any, _ api.ListTenantConfigRequestObject) (int, []models.TenantConfig, error) {
	return f.configTotal, f.configList, f.err
}
func (f *fakeTenantHandler) UpdateConfig(_ any, _ api.UpdateTenantConfigRequestObject) error {
	return f.err
}
func (f *fakeTenantHandler) AddConfig(_ any, _ api.AddTenantConfigRequestObject) (string, error) {
	return f.addConfig, f.err
}
func (f *fakeTenantHandler) DeleteConfigs(_ any, _ api.DeleteTenantConfigsRequestObject) error {
	return f.err
}
func (f *fakeTenantHandler) RegisterTenant(_ any, _ api.RegisterTenantRequestObject) error {
	return f.err
}
func (f *fakeTenantHandler) UpdateTenantRegistration(_ any, _ api.UpdateTenantRegistrationRequestObject) (string, error) {
	return f.regUpdate, f.err
}
func (f *fakeTenantHandler) UpdateApprovals(_ any, _ api.UpdateTenantApprovalRecordsRequestObject) error {
	return f.err
}
func (f *fakeTenantHandler) DeleteApprovals(_ any, _ api.DeleteTenantApprovalRecordsRequestObject) error {
	return f.err
}
func (f *fakeTenantHandler) ApprovalRecords(_ any, _ api.GetTenantApprovalRecordsRequestObject) (int, []models.TenantApproval, error) {
	return f.approvalTotal, f.approvalList, f.err
}
func (f *fakeTenantHandler) TenantSummary(_ any, _ api.GetTenantSummaryRequestObject) (models.SummaryStatsList, error) {
	return f.summary, f.err
}
func (f *fakeTenantHandler) IsNamespaceAvailable(_ api.CheckNamespaceRequestObject) (bool, error) {
	return f.isAvailable, f.err
}

type fakeSystemHandler struct {
	err    error
	paths  *models.PathSelectList
	health *models.HealthStatus
}

func (f *fakeSystemHandler) PutLogs(_ any, _ api.PutLogsRequestObject) error {
	return f.err
}
func (f *fakeSystemHandler) ListPathSelect(_ any, _ api.ListPathSelectRequestObject) (*models.PathSelectList, error) {
	return f.paths, f.err
}
func (f *fakeSystemHandler) HealthStatus(_ any, _ api.GetHealthStatusRequestObject) (*models.HealthStatus, error) {
	return f.health, f.err
}

func newTenantSvc(th *fakeTenantHandler, sh *fakeSystemHandler) *TenantService {
	return &TenantService{handler: th, system: sh, logger: logrus.NewEntry(logrus.New())}
}

func TestTenantService_MetaAndRegister(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{})
	assert.Equal(t, "user api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
	d := &api.StrictServer{}
	assert.NoError(t, s.Register(d))
	assert.NotNil(t, d.AddTenantConfigHandler)
	assert.NotNil(t, d.GetHealthStatusHandler)
}

func TestTenantListConfig_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{configTotal: 1}, &fakeSystemHandler{})
	resp, _ := s.listConfig(context.Background(), api.ListTenantConfigRequestObject{})
	assert.IsType(t, api.ListTenantConfig200JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrInternalErr}, &fakeSystemHandler{})
	resp, _ = s.listConfig(context.Background(), api.ListTenantConfigRequestObject{})
	assert.IsType(t, api.ListTenantConfig500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrModelUnauthorized}, &fakeSystemHandler{})
	resp, _ = s.listConfig(context.Background(), api.ListTenantConfigRequestObject{})
	assert.IsType(t, api.ListTenantConfig401Response{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.listConfig(context.Background(), api.ListTenantConfigRequestObject{})
	assert.IsType(t, api.ListTenantConfig400JSONResponse{}, resp)
}

func TestTenantUpdateConfig_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{})
	resp, _ := s.updateConfig(context.Background(), api.UpdateTenantConfigRequestObject{})
	assert.IsType(t, api.UpdateTenantConfig200TextResponse(""), resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrInternalErr}, &fakeSystemHandler{})
	resp, _ = s.updateConfig(context.Background(), api.UpdateTenantConfigRequestObject{})
	assert.IsType(t, api.UpdateTenantConfig500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrModelUnauthorized}, &fakeSystemHandler{})
	resp, _ = s.updateConfig(context.Background(), api.UpdateTenantConfigRequestObject{})
	assert.IsType(t, api.UpdateTenantConfig401Response{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.updateConfig(context.Background(), api.UpdateTenantConfigRequestObject{})
	assert.IsType(t, api.UpdateTenantConfig400JSONResponse{}, resp)
}

func TestTenantAddConfig_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{addConfig: "id"}, &fakeSystemHandler{})
	resp, _ := s.addConfig(context.Background(), api.AddTenantConfigRequestObject{})
	assert.IsType(t, api.AddTenantConfig200TextResponse(""), resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrInternalErr}, &fakeSystemHandler{})
	resp, _ = s.addConfig(context.Background(), api.AddTenantConfigRequestObject{})
	assert.IsType(t, api.AddTenantConfig500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrModelUnauthorized}, &fakeSystemHandler{})
	resp, _ = s.addConfig(context.Background(), api.AddTenantConfigRequestObject{})
	assert.IsType(t, api.AddTenantConfig401Response{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.addConfig(context.Background(), api.AddTenantConfigRequestObject{})
	assert.IsType(t, api.AddTenantConfig400JSONResponse{}, resp)
}

func TestTenantDeleteConfigs_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{})
	resp, _ := s.deleteConfigs(context.Background(), api.DeleteTenantConfigsRequestObject{})
	assert.IsType(t, api.DeleteTenantConfigs200TextResponse(""), resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrInternalErr}, &fakeSystemHandler{})
	resp, _ = s.deleteConfigs(context.Background(), api.DeleteTenantConfigsRequestObject{})
	assert.IsType(t, api.DeleteTenantConfigs500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrModelUnauthorized}, &fakeSystemHandler{})
	resp, _ = s.deleteConfigs(context.Background(), api.DeleteTenantConfigsRequestObject{})
	assert.IsType(t, api.DeleteTenantConfigs401Response{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.deleteConfigs(context.Background(), api.DeleteTenantConfigsRequestObject{})
	assert.IsType(t, api.DeleteTenantConfigs400JSONResponse{}, resp)
}

func TestRegisterTenant_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{})
	resp, _ := s.registerTenant(context.Background(), api.RegisterTenantRequestObject{})
	assert.IsType(t, api.RegisterTenant200TextResponse(""), resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrInternalErr}, &fakeSystemHandler{})
	resp, _ = s.registerTenant(context.Background(), api.RegisterTenantRequestObject{})
	assert.IsType(t, api.RegisterTenant500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.registerTenant(context.Background(), api.RegisterTenantRequestObject{})
	assert.IsType(t, api.RegisterTenant400JSONResponse{}, resp)
}

func TestApprovalRecordsTenant_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{approvalTotal: 1}, &fakeSystemHandler{})
	resp, _ := s.approvalRecords(context.Background(), api.GetTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.GetTenantApprovalRecords200JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrInternalErr}, &fakeSystemHandler{})
	resp, _ = s.approvalRecords(context.Background(), api.GetTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.GetTenantApprovalRecords500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrModelUnauthorized}, &fakeSystemHandler{})
	resp, _ = s.approvalRecords(context.Background(), api.GetTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.GetTenantApprovalRecords401Response{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.approvalRecords(context.Background(), api.GetTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.GetTenantApprovalRecords400JSONResponse{}, resp)
}

func TestUpdateRegistration_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{regUpdate: "x"}, &fakeSystemHandler{})
	resp, _ := s.updateRegistration(context.Background(), api.UpdateTenantRegistrationRequestObject{})
	assert.IsType(t, api.UpdateTenantRegistration200TextResponse(""), resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrInternalErr}, &fakeSystemHandler{})
	resp, _ = s.updateRegistration(context.Background(), api.UpdateTenantRegistrationRequestObject{})
	assert.IsType(t, api.UpdateTenantRegistration500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.updateRegistration(context.Background(), api.UpdateTenantRegistrationRequestObject{})
	assert.IsType(t, api.UpdateTenantRegistration400JSONResponse{}, resp)
}

func TestUpdateApprovalsTenant_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{})
	resp, _ := s.updateApprovals(context.Background(), api.UpdateTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.UpdateTenantApprovalRecords200TextResponse(""), resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrInternalErr}, &fakeSystemHandler{})
	resp, _ = s.updateApprovals(context.Background(), api.UpdateTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.UpdateTenantApprovalRecords500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrModelUnauthorized}, &fakeSystemHandler{})
	resp, _ = s.updateApprovals(context.Background(), api.UpdateTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.UpdateTenantApprovalRecords401Response{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.updateApprovals(context.Background(), api.UpdateTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.UpdateTenantApprovalRecords400JSONResponse{}, resp)
}

func TestDeleteApprovalsTenant_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{})
	resp, _ := s.deleteApprovals(context.Background(), api.DeleteTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.DeleteTenantApprovalRecords200TextResponse(""), resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrInternalErr}, &fakeSystemHandler{})
	resp, _ = s.deleteApprovals(context.Background(), api.DeleteTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.DeleteTenantApprovalRecords500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrModelUnauthorized}, &fakeSystemHandler{})
	resp, _ = s.deleteApprovals(context.Background(), api.DeleteTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.DeleteTenantApprovalRecords401Response{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.deleteApprovals(context.Background(), api.DeleteTenantApprovalRecordsRequestObject{})
	assert.IsType(t, api.DeleteTenantApprovalRecords400JSONResponse{}, resp)
}

func TestCheckNamespace_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{isAvailable: true}, &fakeSystemHandler{})
	resp, _ := s.checkNamespace(context.Background(), api.CheckNamespaceRequestObject{})
	assert.IsType(t, api.CheckNamespace200JSONResponse(false), resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.checkNamespace(context.Background(), api.CheckNamespaceRequestObject{})
	assert.IsType(t, api.CheckNamespace500JSONResponse{}, resp)
}

func TestTenantSummary_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{summary: models.SummaryStatsList{}}, &fakeSystemHandler{})
	resp, _ := s.tenantSummary(context.Background(), api.GetTenantSummaryRequestObject{})
	assert.IsType(t, api.GetTenantSummary200JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrInternalErr}, &fakeSystemHandler{})
	resp, _ = s.tenantSummary(context.Background(), api.GetTenantSummaryRequestObject{})
	assert.IsType(t, api.GetTenantSummary500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: common.ErrModelUnauthorized}, &fakeSystemHandler{})
	resp, _ = s.tenantSummary(context.Background(), api.GetTenantSummaryRequestObject{})
	assert.IsType(t, api.GetTenantSummary401Response{}, resp)

	s = newTenantSvc(&fakeTenantHandler{err: errors.New("x")}, &fakeSystemHandler{})
	resp, _ = s.tenantSummary(context.Background(), api.GetTenantSummaryRequestObject{})
	assert.IsType(t, api.GetTenantSummary400JSONResponse{}, resp)
}

func TestListPathSelect_Branches(t *testing.T) {
	paths := &models.PathSelectList{}
	s := newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{paths: paths})
	resp, _ := s.listPathSelect(context.Background(), api.ListPathSelectRequestObject{})
	assert.IsType(t, api.ListPathSelect200JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{err: common.ErrInternalErr})
	resp, _ = s.listPathSelect(context.Background(), api.ListPathSelectRequestObject{})
	assert.IsType(t, api.ListPathSelect500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{err: common.ErrModelUnauthorized})
	resp, _ = s.listPathSelect(context.Background(), api.ListPathSelectRequestObject{})
	assert.IsType(t, api.ListPathSelect401Response{}, resp)

	s = newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{err: errors.New("x")})
	resp, _ = s.listPathSelect(context.Background(), api.ListPathSelectRequestObject{})
	assert.IsType(t, api.ListPathSelect400JSONResponse{}, resp)
}

func TestPutLogs_Branches(t *testing.T) {
	s := newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{})
	resp, _ := s.putLogs(context.Background(), api.PutLogsRequestObject{})
	assert.IsType(t, api.PutLogs200TextResponse(""), resp)

	s = newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{err: common.ErrInternalErr})
	resp, _ = s.putLogs(context.Background(), api.PutLogsRequestObject{})
	assert.IsType(t, api.PutLogs500JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{err: common.ErrModelUnauthorized})
	resp, _ = s.putLogs(context.Background(), api.PutLogsRequestObject{})
	assert.IsType(t, api.PutLogs401Response{}, resp)

	s = newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{err: errors.New("x")})
	resp, _ = s.putLogs(context.Background(), api.PutLogsRequestObject{})
	assert.IsType(t, api.PutLogs400JSONResponse{}, resp)
}

func TestHealthStatus_Branches(t *testing.T) {
	hs := &models.HealthStatus{}
	s := newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{health: hs})
	resp, _ := s.healthStatus(context.Background(), api.GetHealthStatusRequestObject{})
	assert.IsType(t, api.GetHealthStatus200JSONResponse{}, resp)

	s = newTenantSvc(&fakeTenantHandler{}, &fakeSystemHandler{err: common.ErrInternalErr})
	resp, _ = s.healthStatus(context.Background(), api.GetHealthStatusRequestObject{})
	assert.IsType(t, api.GetHealthStatus500JSONResponse{}, resp)
}
