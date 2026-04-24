// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package label

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

type fakeLabelHandler struct {
	err    error
	list   []models.Label
	total  int64
	label  *models.Label
}

func (f *fakeLabelHandler) ListLabel(_ any, _ api.ListLabelRequestObject) (int64, []models.Label, error) {
	return f.total, f.list, f.err
}
func (f *fakeLabelHandler) CreateLabels(_ any, _ api.CreateLabelsRequestObject) error { return f.err }
func (f *fakeLabelHandler) UpdateLabels(_ any, _ api.UpdateLabelsRequestObject) error { return f.err }
func (f *fakeLabelHandler) DeleteLabels(_ any, _ api.DeleteLabelsRequestObject) error { return f.err }
func (f *fakeLabelHandler) GetLabel(_ any, _ api.GetLabelRequestObject) (*models.Label, error) {
	return f.label, f.err
}
func (f *fakeLabelHandler) UpdateLabel(_ any, _ api.UpdateLabelRequestObject) error { return f.err }
func (f *fakeLabelHandler) DeleteLabel(_ any, _ api.DeleteLabelRequestObject) error { return f.err }

func newLabelSvc(h *fakeLabelHandler) *LabelService {
	return &LabelService{
		fwService: &fwconfig.ServiceEmulator{},
		handler:   h,
		logger:    logrus.NewEntry(logrus.New()),
	}
}

func TestLabelService_MetaAndRegister(t *testing.T) {
	s := NewService(&fwconfig.ServiceEmulator{}, logrus.NewEntry(logrus.New()))
	assert.NotNil(t, s)
	assert.Equal(t, "label api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
	d := &api.StrictServer{}
	assert.NoError(t, s.Register(d))
	assert.NotNil(t, d.ListLabelHandler)
	assert.NotNil(t, d.CreateLabelsHandler)
	assert.NotNil(t, d.UpdateLabelsHandler)
	assert.NotNil(t, d.DeleteLabelsHandler)
	assert.NotNil(t, d.GetLabelHandler)
	assert.NotNil(t, d.UpdateLabelHandler)
	assert.NotNil(t, d.DeleteLabelHandler)
}

func TestLabel_ListLabel_Branches(t *testing.T) {
	cases := []struct {
		err    error
		expect any
	}{
		{nil, api.ListLabel200JSONResponse{}},
		{common.ErrInternalErr, api.ListLabel500JSONResponse{}},
		{common.ErrModelUnauthorized, api.ListLabel401Response{}},
		{errors.New("x"), api.ListLabel400JSONResponse{}},
	}
	for _, c := range cases {
		s := newLabelSvc(&fakeLabelHandler{err: c.err})
		resp, _ := s.listLabel(context.Background(), api.ListLabelRequestObject{})
		assert.IsType(t, c.expect, resp)
	}
}

func TestLabel_CreateLabels_Branches(t *testing.T) {
	for _, err := range []error{nil, common.ErrInternalErr, common.ErrModelUnauthorized, errors.New("x")} {
		s := newLabelSvc(&fakeLabelHandler{err: err})
		_, _ = s.createLabels(context.Background(), api.CreateLabelsRequestObject{})
	}
}
func TestLabel_UpdateLabels_Branches(t *testing.T) {
	for _, err := range []error{nil, common.ErrInternalErr, common.ErrModelUnauthorized, errors.New("x")} {
		s := newLabelSvc(&fakeLabelHandler{err: err})
		_, _ = s.updateLabels(context.Background(), api.UpdateLabelsRequestObject{})
	}
}
func TestLabel_DeleteLabels_Branches(t *testing.T) {
	for _, err := range []error{nil, common.ErrInternalErr, common.ErrModelUnauthorized, errors.New("x")} {
		s := newLabelSvc(&fakeLabelHandler{err: err})
		_, _ = s.deleteLabels(context.Background(), api.DeleteLabelsRequestObject{})
	}
}
func TestLabel_UpdateLabel_Branches(t *testing.T) {
	for _, err := range []error{nil, common.ErrInternalErr, common.ErrModelUnauthorized, errors.New("x")} {
		s := newLabelSvc(&fakeLabelHandler{err: err})
		_, _ = s.updateLabel(context.Background(), api.UpdateLabelRequestObject{})
	}
}
func TestLabel_DeleteLabel_Branches(t *testing.T) {
	for _, err := range []error{nil, common.ErrInternalErr, common.ErrModelUnauthorized, errors.New("x")} {
		s := newLabelSvc(&fakeLabelHandler{err: err})
		_, _ = s.deleteLabel(context.Background(), api.DeleteLabelRequestObject{})
	}
}
func TestLabel_GetLabel_Branches(t *testing.T) {
	for _, err := range []error{nil, common.ErrInternalErr, common.ErrModelUnauthorized, errors.New("x")} {
		label := &models.Label{}
		s := newLabelSvc(&fakeLabelHandler{err: err, label: label})
		_, _ = s.getLabel(context.Background(), api.GetLabelRequestObject{})
	}
}
