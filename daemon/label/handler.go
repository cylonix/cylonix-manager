// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package label

// Label handlers handle the api request for the label operations.

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/fwconfig"
	ulog "cylonix/sase/pkg/logging/logfields"
	"errors"

	"github.com/sirupsen/logrus"
)

type serviceHandler interface {
	ListLabel(auth interface{}, requestObject api.ListLabelRequestObject) (int64, []models.Label, error)
	CreateLabels(auth interface{}, requestObject api.CreateLabelsRequestObject) error
	UpdateLabels(auth interface{}, requestObject api.UpdateLabelsRequestObject) error
	DeleteLabels(auth interface{}, requestObject api.DeleteLabelsRequestObject) error
	GetLabel(auth interface{}, requestObject api.GetLabelRequestObject) (*models.Label, error)
	UpdateLabel(auth interface{}, requestObject api.UpdateLabelRequestObject) error
	DeleteLabel(auth interface{}, requestObject api.DeleteLabelRequestObject) error
}

type LabelService struct {
	fwService fwconfig.ConfigService
	handler   serviceHandler
	logger    *logrus.Entry
}

// Register Implements the daemon register interface
func (s *LabelService) Register(d *api.StrictServer) error {
	s.logger.Infoln("Register label API handlers.")

	d.ListLabelHandler = s.listLabel
	d.CreateLabelsHandler = s.createLabels
	d.UpdateLabelsHandler = s.updateLabels
	d.DeleteLabelsHandler = s.deleteLabels
	d.GetLabelHandler = s.getLabel
	d.UpdateLabelHandler = s.updateLabel
	d.DeleteLabelHandler = s.deleteLabel
	return nil
}

func NewService(fw fwconfig.ConfigService, logger *logrus.Entry) *LabelService {
	logger = logger.WithField(ulog.LogSubsys, "label-handler")
	return &LabelService{
		fwService: fw,
		handler:   newHandlerImpl(logger, fw),
		logger:    logger,
	}
}

func (s *LabelService) Logger() *logrus.Entry {
	return s.logger
}

func (s *LabelService) Name() string {
	return "label api handler"
}

func (s *LabelService) Start() error {
	return nil
}

func (s *LabelService) Stop() {
	// no-op
}

func (s *LabelService) listLabel(ctx context.Context, requestObject api.ListLabelRequestObject) (api.ListLabelResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	total, list, err := s.handler.ListLabel(auth, requestObject)
	if err == nil {
		return api.ListLabel200JSONResponse{
			Total: int(total),
			Items: &list,
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListLabel500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListLabel401Response{}, nil
	}
	return api.ListLabel400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *LabelService) createLabels(ctx context.Context, requestObject api.CreateLabelsRequestObject) (api.CreateLabelsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.CreateLabels(auth, requestObject)
	if err == nil {
		return api.CreateLabels200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.CreateLabels500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.CreateLabels401Response{}, nil
	}
	return api.CreateLabels400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *LabelService) updateLabels(ctx context.Context, requestObject api.UpdateLabelsRequestObject) (api.UpdateLabelsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.UpdateLabels(auth, requestObject)
	if err == nil {
		return api.UpdateLabels200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateLabels500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateLabels401Response{}, nil
	}
	return api.UpdateLabels400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *LabelService) deleteLabels(ctx context.Context, requestObject api.DeleteLabelsRequestObject) (api.DeleteLabelsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.DeleteLabels(auth, requestObject)
	if err == nil {
		return api.DeleteLabels200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteLabels500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteLabels401Response{}, nil
	}
	return api.DeleteLabels400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil

}
func (s *LabelService) updateLabel(ctx context.Context, requestObject api.UpdateLabelRequestObject) (api.UpdateLabelResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.UpdateLabel(auth, requestObject)
	if err == nil {
		return api.UpdateLabel200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateLabel500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateLabel401Response{}, nil
	}
	return api.UpdateLabel400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *LabelService) deleteLabel(ctx context.Context, requestObject api.DeleteLabelRequestObject) (api.DeleteLabelResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.DeleteLabel(auth, requestObject)
	if err == nil {
		return api.DeleteLabel200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteLabel500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteLabel401Response{}, nil
	}
	return api.DeleteLabel400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *LabelService) getLabel(ctx context.Context, requestObject api.GetLabelRequestObject) (api.GetLabelResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.handler.GetLabel(auth, requestObject)
	if err == nil {
		return api.GetLabel200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetLabel500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetLabel401Response{}, nil
	}
	return api.GetLabel400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
