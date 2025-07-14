// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package analysis

import (
	"context"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/logging/logfields"
	"errors"

	api "cylonix/sase/api/v2"

	"github.com/sirupsen/logrus"
)

type appServiceHandler interface {
	ListEvent(auth interface{}, requestObject api.ListAppEventRequestObject) (*models.AppAccessEventList, error)
	TopCategories(auth interface{}, requestObject api.TopCategoriesRequestObject) ([]models.AppStats, error)
	TopClouds(auth interface{}, requestObject api.TopCloudsRequestObject) ([]models.AppCloud, error)
	TopDomains(auth interface{}, requestObject api.TopDomainsRequestObject) ([]models.AppStats, error)
	TopFlows(auth interface{}, requestObject api.TopFlowsRequestObject) (*models.TopUserFlows, error)
}

type monitorServiceHandler interface {
	ListFlow(auth interface{}, requestObject api.ListMonitorFlowRequestObject) (*models.MonitorFlowList, error)
}

type topoServiceHandler interface {
	NetworkTopo(auth interface{}, requestObject api.NetworkTopoRequestObject) ([]models.NetworkTopo, error)
}

type webServiceHandler interface {
	ListCategory(auth interface{}, requestObject api.ListWebCategoryRequestObject) (*models.WebCategoryList, error)
}

type AnalysisService struct {
	app     appServiceHandler
	monitor monitorServiceHandler
	topo    topoServiceHandler
	web     webServiceHandler
	logger  *logrus.Entry
}

func (s *AnalysisService) Register(d *api.StrictServer) error {
	s.logger.Infoln("Registering the analysis API handlers.")
	d.ListAppEventHandler = s.listAppEvent
	d.TopCategoriesHandler = s.topCategories
	d.TopCloudsHandler = s.topClouds
	d.TopDomainsHandler = s.topDomains
	d.TopFlowsHandler = s.topFlows
	d.ListMonitorFlowHandler = s.listMonitorFlow
	d.NetworkTopoHandler = s.networkTopo
	d.ListWebCategoryHandler = s.listWebCategory
	return nil
}

func NewService(daemon interfaces.DaemonInterface, logger *logrus.Entry) *AnalysisService {
	logger = logger.WithField(logfields.LogSubsys, "analysis-handler")
	return &AnalysisService{
		app:     newAppHandlerImpl(daemon, logger),
		monitor: newMonitorHandlerImpl(logger),
		topo:    newTopoHandlerImpl(logger),
		web:     newWebHandlerImpl(daemon, logger),
		logger:  logger,
	}
}

func (s *AnalysisService) Logger() *logrus.Entry {
	return s.logger
}

func (s *AnalysisService) Name() string {
	return "user api handler"
}

func (s *AnalysisService) Start() error {
	return nil
}

func (s *AnalysisService) Stop() {
	// no-op
}

func (s *AnalysisService) listAppEvent(ctx context.Context, requestObject api.ListAppEventRequestObject) (api.ListAppEventResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.app.ListEvent(auth, requestObject)
	if err == nil {
		return api.ListAppEvent200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListAppEvent500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListAppEvent401Response{}, nil
	}
	return api.ListAppEvent400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *AnalysisService) topCategories(ctx context.Context, requestObject api.TopCategoriesRequestObject) (api.TopCategoriesResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.app.TopCategories(auth, requestObject)
	if err == nil {
		return api.TopCategories200JSONResponse(ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.TopCategories500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.TopCategories401Response{}, nil
	}
	return api.TopCategories400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *AnalysisService) topClouds(ctx context.Context, requestObject api.TopCloudsRequestObject) (api.TopCloudsResponseObject, error) {

	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.app.TopClouds(auth, requestObject)
	if err == nil {
		return api.TopClouds200JSONResponse(ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.TopClouds500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.TopClouds401Response{}, nil
	}
	return api.TopClouds400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *AnalysisService) topDomains(ctx context.Context, requestObject api.TopDomainsRequestObject) (api.TopDomainsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.app.TopDomains(auth, requestObject)
	if err == nil {
		return api.TopDomains200JSONResponse(ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.TopDomains500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.TopDomains401Response{}, nil
	}
	return api.TopDomains400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *AnalysisService) topFlows(ctx context.Context, requestObject api.TopFlowsRequestObject) (api.TopFlowsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.app.TopFlows(auth, requestObject)
	if err == nil {
		return api.TopFlows200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.TopFlows500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.TopFlows401Response{}, nil
	}
	return api.TopFlows400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *AnalysisService) listMonitorFlow(ctx context.Context, requestObject api.ListMonitorFlowRequestObject) (api.ListMonitorFlowResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.monitor.ListFlow(auth, requestObject)
	if err == nil {
		return api.ListMonitorFlow200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListMonitorFlow500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListMonitorFlow401Response{}, nil
	}
	return api.ListMonitorFlow400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *AnalysisService) networkTopo(ctx context.Context, requestObject api.NetworkTopoRequestObject) (api.NetworkTopoResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.topo.NetworkTopo(auth, requestObject)
	if err == nil {
		return api.NetworkTopo200JSONResponse(ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.NetworkTopo500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.NetworkTopo401Response{}, nil
	}
	return api.NetworkTopo400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *AnalysisService) listWebCategory(ctx context.Context, requestObject api.ListWebCategoryRequestObject) (api.ListWebCategoryResponseObject, error) {

	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.web.ListCategory(auth, requestObject)
	if err == nil {
		return api.ListWebCategory200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListWebCategory500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListWebCategory401Response{}, nil
	}
	return api.ListWebCategory400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
