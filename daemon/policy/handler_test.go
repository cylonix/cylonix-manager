// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/fwconfig"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakePolicyHandler struct {
	createErr, updateErr, delErr, delListErr error
	getErr, countErr, listErr, templateErr   error
	pacErr                                   error
	getRet                                   *models.Policy
	count                                    int64
	listTotal                                int64
	listRet                                  []models.Policy
	tmplTotal                                int64
	tmplRet                                  []models.PolicyTemplate
	pacRet                                   models.PacFileList
}

func (f *fakePolicyHandler) Create(_ interface{}, _ api.CreatePolicyRequestObject) error {
	return f.createErr
}
func (f *fakePolicyHandler) Get(_ interface{}, _ api.GetPolicyRequestObject) (*models.Policy, error) {
	return f.getRet, f.getErr
}
func (f *fakePolicyHandler) Count(_ interface{}, _ api.PolicyCountRequestObject) (int64, error) {
	return f.count, f.countErr
}
func (f *fakePolicyHandler) List(_ interface{}, _ api.ListPolicyRequestObject) (int64, []models.Policy, error) {
	return f.listTotal, f.listRet, f.listErr
}
func (f *fakePolicyHandler) Update(_ interface{}, _ api.UpdatePolicyRequestObject) error {
	return f.updateErr
}
func (f *fakePolicyHandler) Delete(_ interface{}, _ api.DeletePolicyRequestObject) error {
	return f.delErr
}
func (f *fakePolicyHandler) DeleteList(_ interface{}, _ api.DeletePolicyListRequestObject) error {
	return f.delListErr
}
func (f *fakePolicyHandler) ListTemplate(_ interface{}, _ api.ListPolicyTemplateRequestObject) (int64, []models.PolicyTemplate, error) {
	return f.tmplTotal, f.tmplRet, f.templateErr
}
func (f *fakePolicyHandler) PacFileList(_ interface{}, _ api.GetPacFileListRequestObject) (models.PacFileList, error) {
	return f.pacRet, f.pacErr
}

type fakeTargetHandler struct {
	createErr, updateErr, delErr, delListErr error
	getErr, listErr                          error
	getRet                                   *models.PolicyTarget
	listRet                                  *models.PolicyTargetList
}

func (f *fakeTargetHandler) Create(_ interface{}, _ api.CreatePolicyTargetRequestObject) error {
	return f.createErr
}
func (f *fakeTargetHandler) Get(_ interface{}, _ api.GetPolicyTargetRequestObject) (*models.PolicyTarget, error) {
	return f.getRet, f.getErr
}
func (f *fakeTargetHandler) List(_ interface{}, _ api.ListPolicyTargetRequestObject) (*models.PolicyTargetList, error) {
	return f.listRet, f.listErr
}
func (f *fakeTargetHandler) Update(_ interface{}, _ api.UpdatePolicyTargetRequestObject) error {
	return f.updateErr
}
func (f *fakeTargetHandler) Delete(_ interface{}, _ api.DeletePolicyTargetRequestObject) error {
	return f.delErr
}
func (f *fakeTargetHandler) DeleteList(_ interface{}, _ api.DeletePolicyTargetListRequestObject) error {
	return f.delListErr
}

func newTestService(p *fakePolicyHandler, ta *fakeTargetHandler) *policyService {
	return &policyService{
		fwService: fwconfig.NewServiceEmulator(),
		logger:    logrus.NewEntry(logrus.New()),
		policy:    p,
		target:    ta,
	}
}

func TestPolicyService_Meta(t *testing.T) {
	svc := NewService(fwconfig.NewServiceEmulator(), logrus.NewEntry(logrus.New()))
	assert.Equal(t, "policy api handler", svc.Name())
	assert.NotNil(t, svc.Logger())
	assert.NoError(t, svc.Start())
	svc.Stop()
	d := &api.StrictServer{}
	assert.NoError(t, svc.Register(d))
	assert.NotNil(t, d.CreatePolicyHandler)
	assert.NotNil(t, d.DeletePolicyTargetListHandler)
}

func TestCreatePolicy_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{})
	ctx := context.Background()
	// Success
	resp, err := s.createPolicy(ctx, api.CreatePolicyRequestObject{})
	assert.NoError(t, err)
	assert.IsType(t, api.CreatePolicy200TextResponse(""), resp)

	// Internal err
	s.policy = &fakePolicyHandler{createErr: common.ErrInternalErr}
	resp, _ = s.createPolicy(ctx, api.CreatePolicyRequestObject{})
	assert.IsType(t, api.CreatePolicy500JSONResponse{}, resp)

	// Unauthorized
	s.policy = &fakePolicyHandler{createErr: common.ErrModelUnauthorized}
	resp, _ = s.createPolicy(ctx, api.CreatePolicyRequestObject{})
	assert.IsType(t, api.CreatePolicy401Response{}, resp)

	// Bad request
	s.policy = &fakePolicyHandler{createErr: errors.New("bad")}
	resp, _ = s.createPolicy(ctx, api.CreatePolicyRequestObject{})
	assert.IsType(t, api.CreatePolicy400JSONResponse{}, resp)
}

func TestGetPolicy_Branches(t *testing.T) {
	p := &models.Policy{}
	s := newTestService(&fakePolicyHandler{getRet: p}, &fakeTargetHandler{})
	resp, _ := s.getPolicy(context.Background(), api.GetPolicyRequestObject{})
	assert.IsType(t, api.GetPolicy200JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{getErr: common.ErrInternalErr}
	resp, _ = s.getPolicy(context.Background(), api.GetPolicyRequestObject{})
	assert.IsType(t, api.GetPolicy500JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{getErr: common.ErrModelUnauthorized}
	resp, _ = s.getPolicy(context.Background(), api.GetPolicyRequestObject{})
	assert.IsType(t, api.GetPolicy401Response{}, resp)

	s.policy = &fakePolicyHandler{getErr: errors.New("bad")}
	resp, _ = s.getPolicy(context.Background(), api.GetPolicyRequestObject{})
	assert.IsType(t, api.GetPolicy400JSONResponse{}, resp)
}

func TestListPolicy_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{listTotal: 5}, &fakeTargetHandler{})
	resp, _ := s.listPolicy(context.Background(), api.ListPolicyRequestObject{})
	assert.IsType(t, api.ListPolicy200JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{listErr: common.ErrInternalErr}
	resp, _ = s.listPolicy(context.Background(), api.ListPolicyRequestObject{})
	assert.IsType(t, api.ListPolicy500JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{listErr: common.ErrModelUnauthorized}
	resp, _ = s.listPolicy(context.Background(), api.ListPolicyRequestObject{})
	assert.IsType(t, api.ListPolicy401Response{}, resp)

	s.policy = &fakePolicyHandler{listErr: errors.New("bad")}
	resp, _ = s.listPolicy(context.Background(), api.ListPolicyRequestObject{})
	assert.IsType(t, api.ListPolicy400JSONResponse{}, resp)
}

func TestPolicyCount_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{count: 3}, &fakeTargetHandler{})
	resp, _ := s.policyCount(context.Background(), api.PolicyCountRequestObject{})
	assert.IsType(t, api.PolicyCount200JSONResponse(0), resp)

	s.policy = &fakePolicyHandler{countErr: common.ErrInternalErr}
	resp, _ = s.policyCount(context.Background(), api.PolicyCountRequestObject{})
	assert.IsType(t, api.PolicyCount500JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{countErr: common.ErrModelUnauthorized}
	resp, _ = s.policyCount(context.Background(), api.PolicyCountRequestObject{})
	assert.IsType(t, api.PolicyCount401Response{}, resp)

	s.policy = &fakePolicyHandler{countErr: errors.New("bad")}
	resp, _ = s.policyCount(context.Background(), api.PolicyCountRequestObject{})
	assert.IsType(t, api.PolicyCount400JSONResponse{}, resp)
}

func TestUpdatePolicy_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{})
	resp, _ := s.updatePolicy(context.Background(), api.UpdatePolicyRequestObject{})
	assert.IsType(t, api.UpdatePolicy200Response{}, resp)

	s.policy = &fakePolicyHandler{updateErr: common.ErrInternalErr}
	resp, _ = s.updatePolicy(context.Background(), api.UpdatePolicyRequestObject{})
	assert.IsType(t, api.UpdatePolicy500JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{updateErr: common.ErrModelUnauthorized}
	resp, _ = s.updatePolicy(context.Background(), api.UpdatePolicyRequestObject{})
	assert.IsType(t, api.UpdatePolicy401Response{}, resp)

	s.policy = &fakePolicyHandler{updateErr: errors.New("x")}
	resp, _ = s.updatePolicy(context.Background(), api.UpdatePolicyRequestObject{})
	assert.IsType(t, api.UpdatePolicy400JSONResponse{}, resp)
}

func TestDeletePolicy_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{})
	resp, _ := s.deletePolicy(context.Background(), api.DeletePolicyRequestObject{})
	assert.IsType(t, api.DeletePolicy200Response{}, resp)

	s.policy = &fakePolicyHandler{delErr: common.ErrInternalErr}
	resp, _ = s.deletePolicy(context.Background(), api.DeletePolicyRequestObject{})
	assert.IsType(t, api.DeletePolicy500JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{delErr: common.ErrModelUnauthorized}
	resp, _ = s.deletePolicy(context.Background(), api.DeletePolicyRequestObject{})
	assert.IsType(t, api.DeletePolicy401Response{}, resp)

	s.policy = &fakePolicyHandler{delErr: errors.New("x")}
	resp, _ = s.deletePolicy(context.Background(), api.DeletePolicyRequestObject{})
	assert.IsType(t, api.DeletePolicy400JSONResponse{}, resp)
}

func TestDeletePolicyList_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{})
	resp, _ := s.deletePolicyList(context.Background(), api.DeletePolicyListRequestObject{})
	assert.IsType(t, api.DeletePolicyList200TextResponse(""), resp)

	s.policy = &fakePolicyHandler{delListErr: common.ErrInternalErr}
	resp, _ = s.deletePolicyList(context.Background(), api.DeletePolicyListRequestObject{})
	assert.IsType(t, api.DeletePolicyList500JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{delListErr: common.ErrModelUnauthorized}
	resp, _ = s.deletePolicyList(context.Background(), api.DeletePolicyListRequestObject{})
	assert.IsType(t, api.DeletePolicyList401Response{}, resp)

	s.policy = &fakePolicyHandler{delListErr: errors.New("x")}
	resp, _ = s.deletePolicyList(context.Background(), api.DeletePolicyListRequestObject{})
	assert.IsType(t, api.DeletePolicyList400JSONResponse{}, resp)
}

func TestListTemplate_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{tmplTotal: 2}, &fakeTargetHandler{})
	resp, _ := s.listTemplate(context.Background(), api.ListPolicyTemplateRequestObject{})
	assert.IsType(t, api.ListPolicyTemplate200JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{templateErr: common.ErrInternalErr}
	resp, _ = s.listTemplate(context.Background(), api.ListPolicyTemplateRequestObject{})
	assert.IsType(t, api.ListPolicyTemplate500JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{templateErr: common.ErrModelUnauthorized}
	resp, _ = s.listTemplate(context.Background(), api.ListPolicyTemplateRequestObject{})
	assert.IsType(t, api.ListPolicyTemplate401Response{}, resp)

	s.policy = &fakePolicyHandler{templateErr: errors.New("x")}
	resp, _ = s.listTemplate(context.Background(), api.ListPolicyTemplateRequestObject{})
	assert.IsType(t, api.ListPolicyTemplate400JSONResponse{}, resp)
}

func TestGetPacFileList_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{})
	resp, _ := s.getPacFileList(context.Background(), api.GetPacFileListRequestObject{})
	assert.IsType(t, api.GetPacFileList200JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{pacErr: common.ErrInternalErr}
	resp, _ = s.getPacFileList(context.Background(), api.GetPacFileListRequestObject{})
	assert.IsType(t, api.GetPacFileList500JSONResponse{}, resp)

	s.policy = &fakePolicyHandler{pacErr: common.ErrModelUnauthorized}
	resp, _ = s.getPacFileList(context.Background(), api.GetPacFileListRequestObject{})
	assert.IsType(t, api.GetPacFileList401Response{}, resp)

	s.policy = &fakePolicyHandler{pacErr: errors.New("x")}
	resp, _ = s.getPacFileList(context.Background(), api.GetPacFileListRequestObject{})
	assert.IsType(t, api.GetPacFileList400JSONResponse{}, resp)
}

func TestCreateTarget_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{})
	resp, _ := s.createTarget(context.Background(), api.CreatePolicyTargetRequestObject{})
	assert.IsType(t, api.CreatePolicyTarget200TextResponse(""), resp)

	s.target = &fakeTargetHandler{createErr: common.ErrInternalErr}
	resp, _ = s.createTarget(context.Background(), api.CreatePolicyTargetRequestObject{})
	assert.IsType(t, api.CreatePolicyTarget500JSONResponse{}, resp)

	s.target = &fakeTargetHandler{createErr: common.ErrModelUnauthorized}
	resp, _ = s.createTarget(context.Background(), api.CreatePolicyTargetRequestObject{})
	assert.IsType(t, api.CreatePolicyTarget401Response{}, resp)

	s.target = &fakeTargetHandler{createErr: errors.New("x")}
	resp, _ = s.createTarget(context.Background(), api.CreatePolicyTargetRequestObject{})
	assert.IsType(t, api.CreatePolicyTarget400JSONResponse{}, resp)
}

func TestGetTarget_Branches(t *testing.T) {
	pt := &models.PolicyTarget{}
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{getRet: pt})
	resp, _ := s.getTarget(context.Background(), api.GetPolicyTargetRequestObject{})
	assert.IsType(t, api.GetPolicyTarget200JSONResponse{}, resp)

	s.target = &fakeTargetHandler{getErr: common.ErrInternalErr}
	resp, _ = s.getTarget(context.Background(), api.GetPolicyTargetRequestObject{})
	assert.IsType(t, api.GetPolicyTarget500JSONResponse{}, resp)

	s.target = &fakeTargetHandler{getErr: common.ErrModelUnauthorized}
	resp, _ = s.getTarget(context.Background(), api.GetPolicyTargetRequestObject{})
	assert.IsType(t, api.GetPolicyTarget401Response{}, resp)

	s.target = &fakeTargetHandler{getErr: errors.New("x")}
	resp, _ = s.getTarget(context.Background(), api.GetPolicyTargetRequestObject{})
	assert.IsType(t, api.GetPolicyTarget400JSONResponse{}, resp)
}

func TestListTarget_Branches(t *testing.T) {
	pl := &models.PolicyTargetList{}
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{listRet: pl})
	resp, _ := s.listTarget(context.Background(), api.ListPolicyTargetRequestObject{})
	assert.IsType(t, api.ListPolicyTarget200JSONResponse{}, resp)

	s.target = &fakeTargetHandler{listErr: common.ErrInternalErr}
	resp, _ = s.listTarget(context.Background(), api.ListPolicyTargetRequestObject{})
	assert.IsType(t, api.ListPolicyTarget500JSONResponse{}, resp)

	s.target = &fakeTargetHandler{listErr: common.ErrModelUnauthorized}
	resp, _ = s.listTarget(context.Background(), api.ListPolicyTargetRequestObject{})
	assert.IsType(t, api.ListPolicyTarget401Response{}, resp)

	s.target = &fakeTargetHandler{listErr: errors.New("x")}
	resp, _ = s.listTarget(context.Background(), api.ListPolicyTargetRequestObject{})
	assert.IsType(t, api.ListPolicyTarget400JSONResponse{}, resp)
}

func TestUpdateTarget_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{})
	resp, _ := s.updateTarget(context.Background(), api.UpdatePolicyTargetRequestObject{})
	assert.IsType(t, api.UpdatePolicyTarget200TextResponse(""), resp)

	s.target = &fakeTargetHandler{updateErr: common.ErrInternalErr}
	resp, _ = s.updateTarget(context.Background(), api.UpdatePolicyTargetRequestObject{})
	assert.IsType(t, api.UpdatePolicyTarget500JSONResponse{}, resp)

	s.target = &fakeTargetHandler{updateErr: common.ErrModelUnauthorized}
	resp, _ = s.updateTarget(context.Background(), api.UpdatePolicyTargetRequestObject{})
	assert.IsType(t, api.UpdatePolicyTarget401Response{}, resp)

	s.target = &fakeTargetHandler{updateErr: errors.New("x")}
	resp, _ = s.updateTarget(context.Background(), api.UpdatePolicyTargetRequestObject{})
	assert.IsType(t, api.UpdatePolicyTarget400JSONResponse{}, resp)
}

func TestDeleteTarget_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{})
	resp, _ := s.deleteTarget(context.Background(), api.DeletePolicyTargetRequestObject{})
	assert.IsType(t, api.DeletePolicyTarget200Response{}, resp)

	s.target = &fakeTargetHandler{delErr: common.ErrInternalErr}
	resp, _ = s.deleteTarget(context.Background(), api.DeletePolicyTargetRequestObject{})
	assert.IsType(t, api.DeletePolicyTarget500JSONResponse{}, resp)

	s.target = &fakeTargetHandler{delErr: common.ErrModelUnauthorized}
	resp, _ = s.deleteTarget(context.Background(), api.DeletePolicyTargetRequestObject{})
	assert.IsType(t, api.DeletePolicyTarget401Response{}, resp)

	s.target = &fakeTargetHandler{delErr: errors.New("x")}
	resp, _ = s.deleteTarget(context.Background(), api.DeletePolicyTargetRequestObject{})
	assert.IsType(t, api.DeletePolicyTarget400JSONResponse{}, resp)
}

func TestDeleteTargetList_Branches(t *testing.T) {
	s := newTestService(&fakePolicyHandler{}, &fakeTargetHandler{})
	resp, _ := s.deleteTargetList(context.Background(), api.DeletePolicyTargetListRequestObject{})
	assert.IsType(t, api.DeletePolicyTargetList200TextResponse(""), resp)

	s.target = &fakeTargetHandler{delListErr: common.ErrInternalErr}
	resp, _ = s.deleteTargetList(context.Background(), api.DeletePolicyTargetListRequestObject{})
	assert.IsType(t, api.DeletePolicyTargetList500JSONResponse{}, resp)

	s.target = &fakeTargetHandler{delListErr: common.ErrModelUnauthorized}
	resp, _ = s.deleteTargetList(context.Background(), api.DeletePolicyTargetListRequestObject{})
	assert.IsType(t, api.DeletePolicyTargetList401Response{}, resp)

	s.target = &fakeTargetHandler{delListErr: errors.New("x")}
	resp, _ = s.deleteTargetList(context.Background(), api.DeletePolicyTargetListRequestObject{})
	assert.IsType(t, api.DeletePolicyTargetList400JSONResponse{}, resp)
}
