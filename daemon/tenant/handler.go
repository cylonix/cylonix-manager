// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tenant

// Tenant handlers handle the api request for tenants (namespace) of the sase
// network.

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	ulog "cylonix/sase/pkg/logging/logfields"
	"errors"

	"github.com/sirupsen/logrus"
)

type serviceHandler interface {
	// Tenant config CRUD.
	ListConfig(auth interface{}, requestObject api.ListTenantConfigRequestObject) (int, []models.TenantConfig, error)
	UpdateConfig(auth interface{}, requestObject api.UpdateTenantConfigRequestObject) error
	AddConfig(auth interface{}, requestObject api.AddTenantConfigRequestObject) (string, error)
	DeleteConfigs(auth interface{}, requestObject api.DeleteTenantConfigsRequestObject) error

	// Approval records.
	RegisterTenant(auth interface{}, requestObject api.RegisterTenantRequestObject) error
	UpdateTenantRegistration(auth interface{}, requestObject api.UpdateTenantRegistrationRequestObject) (string, error)
	UpdateApprovals(auth interface{}, requestObject api.UpdateTenantApprovalRecordsRequestObject) error
	DeleteApprovals(auth interface{}, requestObject api.DeleteTenantApprovalRecordsRequestObject) error
	ApprovalRecords(auth interface{}, requestObject api.GetTenantApprovalRecordsRequestObject) (int, []models.TenantApproval, error)

	// Stats.
	TenantSummary(auth interface{}, requestObject api.GetTenantSummaryRequestObject) (models.SummaryStatsList, error)

	// Misc.
	IsNamespaceAvailable(params api.CheckNamespaceRequestObject) (bool, error)
}

type systemServiceHandler interface {
	PutLogs(auth interface{}, requestObject api.PutLogsRequestObject) error
	ListPathSelect(auth interface{}, requestObject api.ListPathSelectRequestObject) (*models.PathSelectList, error)
	HealthStatus(auth interface{}, requestObject api.GetHealthStatusRequestObject) (*models.HealthStatus, error)
}

type TenantService struct {
	handler serviceHandler
	system  systemServiceHandler
	logger  *logrus.Entry
}

// Register Implements the daemon register interface
func (s *TenantService) Register(d *api.StrictServer) error {
	s.logger.Infoln("Register tenant API handlers.")

	// Tenant CRUD operations.
	d.AddTenantConfigHandler = s.addConfig
	d.ListTenantConfigHandler = s.listConfig
	d.UpdateTenantConfigHandler = s.updateConfig
	d.DeleteTenantConfigsHandler = s.deleteConfigs

	// Tenant approval CRUD operations.
	d.RegisterTenantHandler = s.registerTenant
	d.GetTenantApprovalRecordsHandler = s.approvalRecords
	d.UpdateTenantRegistrationHandler = s.updateRegistration
	d.UpdateTenantApprovalRecordsHandler = s.updateApprovals
	d.DeleteTenantApprovalRecordsHandler = s.deleteApprovals

	// Stats.
	d.GetTenantSummaryHandler = s.tenantSummary

	// Misc.
	d.CheckNamespaceHandler = s.checkNamespace

	// System.
	d.PutLogsHandler = s.putLogs
	d.ListPathSelectHandler = s.listPathSelect
	d.GetHealthStatusHandler = s.healthStatus
	return nil
}

func NewService(logger *logrus.Entry) *TenantService {
	logger = logger.WithField(ulog.LogSubsys, "tenant-handler")
	return &TenantService{
		handler: newHandlerImpl(logger),
		system:  newSystemHandlerImpl(logger),
		logger:  logger,
	}
}

func (s *TenantService) Logger() *logrus.Entry {
	return s.logger
}

func (s *TenantService) Name() string {
	return "user api handler"
}

func (s *TenantService) Start() error {
	return nil
}

func (s *TenantService) Stop() {
	// no-op
}

func (s *TenantService) listConfig(ctx context.Context, requestObject api.ListTenantConfigRequestObject) (api.ListTenantConfigResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	total, list, err := s.handler.ListConfig(auth, requestObject)
	if err == nil {
		return api.ListTenantConfig200JSONResponse{
			Items: &list,
			Total: total,
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListTenantConfig500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListTenantConfig401Response{}, nil
	}
	return api.ListTenantConfig400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *TenantService) updateConfig(ctx context.Context, requestObject api.UpdateTenantConfigRequestObject) (api.UpdateTenantConfigResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.UpdateConfig(auth, requestObject)
	if err == nil {
		return api.UpdateTenantConfig200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateTenantConfig500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateTenantConfig401Response{}, nil
	}
	return api.UpdateTenantConfig400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *TenantService) addConfig(ctx context.Context, requestObject api.AddTenantConfigRequestObject) (api.AddTenantConfigResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	password, err := s.handler.AddConfig(auth, requestObject)
	if err == nil {
		return api.AddTenantConfig200TextResponse(password), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.AddTenantConfig500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.AddTenantConfig401Response{}, nil
	}
	return api.AddTenantConfig400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *TenantService) deleteConfigs(ctx context.Context, requestObject api.DeleteTenantConfigsRequestObject) (api.DeleteTenantConfigsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.DeleteConfigs(auth, requestObject)
	if err == nil {
		return api.DeleteTenantConfigs200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteTenantConfigs500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteTenantConfigs401Response{}, nil
	}
	return api.DeleteTenantConfigs400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *TenantService) registerTenant(ctx context.Context, requestObject api.RegisterTenantRequestObject) (api.RegisterTenantResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.RegisterTenant(auth, requestObject)
	if err == nil {
		return api.RegisterTenant200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.RegisterTenant500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.RegisterTenant401Response{}, nil
	}
	return api.RegisterTenant400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *TenantService) approvalRecords(ctx context.Context, requestObject api.GetTenantApprovalRecordsRequestObject) (api.GetTenantApprovalRecordsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	total, list, err := s.handler.ApprovalRecords(auth, requestObject)
	if err == nil {
		return api.GetTenantApprovalRecords200JSONResponse{
			Items: &list,
			Total: total,
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetTenantApprovalRecords500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetTenantApprovalRecords401Response{}, nil
	}
	return api.GetTenantApprovalRecords400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *TenantService) updateRegistration(ctx context.Context, requestObject api.UpdateTenantRegistrationRequestObject) (api.UpdateTenantRegistrationResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	password, err := s.handler.UpdateTenantRegistration(auth, requestObject)
	if err == nil {
		return api.UpdateTenantRegistration200TextResponse(password), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateTenantRegistration500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateTenantRegistration401Response{}, nil
	}
	return api.UpdateTenantRegistration400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *TenantService) updateApprovals(ctx context.Context, requestObject api.UpdateTenantApprovalRecordsRequestObject) (api.UpdateTenantApprovalRecordsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.UpdateApprovals(auth, requestObject)
	if err == nil {
		return api.UpdateTenantApprovalRecords200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateTenantApprovalRecords500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateTenantApprovalRecords401Response{}, nil
	}
	return api.UpdateTenantApprovalRecords400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *TenantService) deleteApprovals(ctx context.Context, requestObject api.DeleteTenantApprovalRecordsRequestObject) (api.DeleteTenantApprovalRecordsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.DeleteApprovals(auth, requestObject)
	if err == nil {
		return api.DeleteTenantApprovalRecords200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteTenantApprovalRecords500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteTenantApprovalRecords401Response{}, nil
	}
	return api.DeleteTenantApprovalRecords400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *TenantService) checkNamespace(ctx context.Context, requestObject api.CheckNamespaceRequestObject) (api.CheckNamespaceResponseObject, error) {
	ret, err := s.handler.IsNamespaceAvailable(requestObject)
	if err == nil {
		return api.CheckNamespace200JSONResponse(ret), nil
	}
	return api.CheckNamespace500JSONResponse{}, nil
}
func (s *TenantService) tenantSummary(ctx context.Context, requestObject api.GetTenantSummaryRequestObject) (api.GetTenantSummaryResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.handler.TenantSummary(auth, requestObject)
	if err == nil {
		return api.GetTenantSummary200JSONResponse(ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetTenantSummary500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetTenantSummary401Response{}, nil
	}
	return api.GetTenantSummary400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *TenantService) listPathSelect(ctx context.Context, requestObject api.ListPathSelectRequestObject) (api.ListPathSelectResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.system.ListPathSelect(auth, requestObject)
	if err == nil {
		return api.ListPathSelect200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListPathSelect500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListPathSelect401Response{}, nil
	}
	return api.ListPathSelect400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *TenantService) putLogs(ctx context.Context, requestObject api.PutLogsRequestObject) (api.PutLogsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.system.PutLogs(auth, requestObject)
	if err == nil {
		return api.PutLogs200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.PutLogs500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.PutLogs401Response{}, nil
	}
	return api.PutLogs400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *TenantService) healthStatus(ctx context.Context, requestObject api.GetHealthStatusRequestObject) (api.GetHealthStatusResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.system.HealthStatus(auth, requestObject)
	if err == nil {
		return api.GetHealthStatus200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetHealthStatus500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetHealthStatus401Response{}, nil
	}
	return api.GetHealthStatus400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
