// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package analysis

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

type fakeApp struct {
	listEvent      *models.AppAccessEventList
	topCategories  []models.AppStats
	topClouds      []models.AppCloud
	topDomains     []models.AppStats
	topFlows       *models.TopUserFlows
	listEventErr   error
	topCatErr      error
	topCloudsErr   error
	topDomainsErr  error
	topFlowsErr    error
}

func (f *fakeApp) ListEvent(_ any, _ api.ListAppEventRequestObject) (*models.AppAccessEventList, error) {
	return f.listEvent, f.listEventErr
}
func (f *fakeApp) TopCategories(_ any, _ api.TopCategoriesRequestObject) ([]models.AppStats, error) {
	return f.topCategories, f.topCatErr
}
func (f *fakeApp) TopClouds(_ any, _ api.TopCloudsRequestObject) ([]models.AppCloud, error) {
	return f.topClouds, f.topCloudsErr
}
func (f *fakeApp) TopDomains(_ any, _ api.TopDomainsRequestObject) ([]models.AppStats, error) {
	return f.topDomains, f.topDomainsErr
}
func (f *fakeApp) TopFlows(_ any, _ api.TopFlowsRequestObject) (*models.TopUserFlows, error) {
	return f.topFlows, f.topFlowsErr
}

type fakeMonitor struct {
	list    *models.MonitorFlowList
	listErr error
}

func (f *fakeMonitor) ListFlow(_ any, _ api.ListMonitorFlowRequestObject) (*models.MonitorFlowList, error) {
	return f.list, f.listErr
}

type fakeTopo struct {
	topo []models.NetworkTopo
	err  error
}

func (f *fakeTopo) NetworkTopo(_ any, _ api.NetworkTopoRequestObject) ([]models.NetworkTopo, error) {
	return f.topo, f.err
}

type fakeWeb struct {
	cats *models.WebCategoryList
	err  error
}

func (f *fakeWeb) ListCategory(_ any, _ api.ListWebCategoryRequestObject) (*models.WebCategoryList, error) {
	return f.cats, f.err
}

func newAnalysisSvc(a *fakeApp, m *fakeMonitor, topo *fakeTopo, w *fakeWeb) *AnalysisService {
	return &AnalysisService{app: a, monitor: m, topo: topo, web: w, logger: logrus.NewEntry(logrus.New())}
}

func TestAnalysis_Meta(t *testing.T) {
	s := newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	assert.Equal(t, "user api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
	d := &api.StrictServer{}
	assert.NoError(t, s.Register(d))
	assert.NotNil(t, d.ListAppEventHandler)
}

func TestListAppEvent_Branches(t *testing.T) {
	ev := &models.AppAccessEventList{}
	s := newAnalysisSvc(&fakeApp{listEvent: ev}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ := s.listAppEvent(context.Background(), api.ListAppEventRequestObject{})
	assert.IsType(t, api.ListAppEvent200JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{listEventErr: common.ErrInternalErr}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.listAppEvent(context.Background(), api.ListAppEventRequestObject{})
	assert.IsType(t, api.ListAppEvent500JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{listEventErr: common.ErrModelUnauthorized}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.listAppEvent(context.Background(), api.ListAppEventRequestObject{})
	assert.IsType(t, api.ListAppEvent401Response{}, resp)

	s = newAnalysisSvc(&fakeApp{listEventErr: errors.New("x")}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.listAppEvent(context.Background(), api.ListAppEventRequestObject{})
	assert.IsType(t, api.ListAppEvent400JSONResponse{}, resp)
}

func TestTopCategories_Branches(t *testing.T) {
	s := newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ := s.topCategories(context.Background(), api.TopCategoriesRequestObject{})
	assert.IsType(t, api.TopCategories200JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{topCatErr: common.ErrInternalErr}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topCategories(context.Background(), api.TopCategoriesRequestObject{})
	assert.IsType(t, api.TopCategories500JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{topCatErr: common.ErrModelUnauthorized}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topCategories(context.Background(), api.TopCategoriesRequestObject{})
	assert.IsType(t, api.TopCategories401Response{}, resp)

	s = newAnalysisSvc(&fakeApp{topCatErr: errors.New("x")}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topCategories(context.Background(), api.TopCategoriesRequestObject{})
	assert.IsType(t, api.TopCategories400JSONResponse{}, resp)
}

func TestTopClouds_Branches(t *testing.T) {
	s := newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ := s.topClouds(context.Background(), api.TopCloudsRequestObject{})
	assert.IsType(t, api.TopClouds200JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{topCloudsErr: common.ErrInternalErr}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topClouds(context.Background(), api.TopCloudsRequestObject{})
	assert.IsType(t, api.TopClouds500JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{topCloudsErr: common.ErrModelUnauthorized}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topClouds(context.Background(), api.TopCloudsRequestObject{})
	assert.IsType(t, api.TopClouds401Response{}, resp)

	s = newAnalysisSvc(&fakeApp{topCloudsErr: errors.New("x")}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topClouds(context.Background(), api.TopCloudsRequestObject{})
	assert.IsType(t, api.TopClouds400JSONResponse{}, resp)
}

func TestTopDomains_Branches(t *testing.T) {
	s := newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ := s.topDomains(context.Background(), api.TopDomainsRequestObject{})
	assert.IsType(t, api.TopDomains200JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{topDomainsErr: common.ErrInternalErr}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topDomains(context.Background(), api.TopDomainsRequestObject{})
	assert.IsType(t, api.TopDomains500JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{topDomainsErr: common.ErrModelUnauthorized}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topDomains(context.Background(), api.TopDomainsRequestObject{})
	assert.IsType(t, api.TopDomains401Response{}, resp)

	s = newAnalysisSvc(&fakeApp{topDomainsErr: errors.New("x")}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topDomains(context.Background(), api.TopDomainsRequestObject{})
	assert.IsType(t, api.TopDomains400JSONResponse{}, resp)
}

func TestTopFlows_Branches(t *testing.T) {
	flows := &models.TopUserFlows{}
	s := newAnalysisSvc(&fakeApp{topFlows: flows}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ := s.topFlows(context.Background(), api.TopFlowsRequestObject{})
	assert.IsType(t, api.TopFlows200JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{topFlowsErr: common.ErrInternalErr}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topFlows(context.Background(), api.TopFlowsRequestObject{})
	assert.IsType(t, api.TopFlows500JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{topFlowsErr: common.ErrModelUnauthorized}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topFlows(context.Background(), api.TopFlowsRequestObject{})
	assert.IsType(t, api.TopFlows401Response{}, resp)

	s = newAnalysisSvc(&fakeApp{topFlowsErr: errors.New("x")}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.topFlows(context.Background(), api.TopFlowsRequestObject{})
	assert.IsType(t, api.TopFlows400JSONResponse{}, resp)
}

func TestListMonitorFlow_Branches(t *testing.T) {
	list := &models.MonitorFlowList{}
	s := newAnalysisSvc(&fakeApp{}, &fakeMonitor{list: list}, &fakeTopo{}, &fakeWeb{})
	resp, _ := s.listMonitorFlow(context.Background(), api.ListMonitorFlowRequestObject{})
	assert.IsType(t, api.ListMonitorFlow200JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{}, &fakeMonitor{listErr: common.ErrInternalErr}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.listMonitorFlow(context.Background(), api.ListMonitorFlowRequestObject{})
	assert.IsType(t, api.ListMonitorFlow500JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{}, &fakeMonitor{listErr: common.ErrModelUnauthorized}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.listMonitorFlow(context.Background(), api.ListMonitorFlowRequestObject{})
	assert.IsType(t, api.ListMonitorFlow401Response{}, resp)

	s = newAnalysisSvc(&fakeApp{}, &fakeMonitor{listErr: errors.New("x")}, &fakeTopo{}, &fakeWeb{})
	resp, _ = s.listMonitorFlow(context.Background(), api.ListMonitorFlowRequestObject{})
	assert.IsType(t, api.ListMonitorFlow400JSONResponse{}, resp)
}

func TestNetworkTopo_Branches(t *testing.T) {
	s := newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{})
	resp, _ := s.networkTopo(context.Background(), api.NetworkTopoRequestObject{})
	assert.IsType(t, api.NetworkTopo200JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{err: common.ErrInternalErr}, &fakeWeb{})
	resp, _ = s.networkTopo(context.Background(), api.NetworkTopoRequestObject{})
	assert.IsType(t, api.NetworkTopo500JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{err: common.ErrModelUnauthorized}, &fakeWeb{})
	resp, _ = s.networkTopo(context.Background(), api.NetworkTopoRequestObject{})
	assert.IsType(t, api.NetworkTopo401Response{}, resp)

	s = newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{err: errors.New("x")}, &fakeWeb{})
	resp, _ = s.networkTopo(context.Background(), api.NetworkTopoRequestObject{})
	assert.IsType(t, api.NetworkTopo400JSONResponse{}, resp)
}

func TestListWebCategory_Branches(t *testing.T) {
	cats := &models.WebCategoryList{}
	s := newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{cats: cats})
	resp, _ := s.listWebCategory(context.Background(), api.ListWebCategoryRequestObject{})
	assert.IsType(t, api.ListWebCategory200JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{err: common.ErrInternalErr})
	resp, _ = s.listWebCategory(context.Background(), api.ListWebCategoryRequestObject{})
	assert.IsType(t, api.ListWebCategory500JSONResponse{}, resp)

	s = newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{err: common.ErrModelUnauthorized})
	resp, _ = s.listWebCategory(context.Background(), api.ListWebCategoryRequestObject{})
	assert.IsType(t, api.ListWebCategory401Response{}, resp)

	s = newAnalysisSvc(&fakeApp{}, &fakeMonitor{}, &fakeTopo{}, &fakeWeb{err: errors.New("x")})
	resp, _ = s.listWebCategory(context.Background(), api.ListWebCategoryRequestObject{})
	assert.IsType(t, api.ListWebCategory400JSONResponse{}, resp)
}
