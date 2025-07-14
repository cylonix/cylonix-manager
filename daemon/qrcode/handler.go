// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package qrcode

// QR code handlers handle the api request for the qr code operations.

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	ulog "cylonix/sase/pkg/logging/logfields"
	"errors"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
)

type serviceHandler interface {
	CreateQrCode(auth interface{}, requestObject api.CreateQrCodeRequestObject) (*utils.QRCodeToken, error)
	UpdateQrCodeToken(auth interface{}, requestObject api.UpdateQrCodeTokenRequestObject) error
	CheckQrCodeState(auth interface{}, requestObject api.CheckQrCodeStateRequestObject) (*models.QrCodeTokenData, error)
}

type qrCodeService struct {
	handler serviceHandler
	logger  *logrus.Entry
}

// Register Implements the daemon register interface
func (s *qrCodeService) Register(d *api.StrictServer) error {
	s.logger.Infoln("Register QR code API handlers.")

	d.CreateQrCodeHandler = s.createQrCode
	d.CheckQrCodeStateHandler = s.checkQrCodeState
	d.UpdateQrCodeTokenHandler = s.updateQrCodeToken
	return nil
}

func NewService(logger *logrus.Entry) *qrCodeService {
	logger = logger.WithField(ulog.LogSubsys, "qr-code-handler")
	return &qrCodeService{
		handler: newHandlerImpl(logger),
		logger:  logger,
	}
}

func (s *qrCodeService) Logger() *logrus.Entry {
	return s.logger
}

func (s *qrCodeService) Name() string {
	return "qr-code api handler"
}

func (s *qrCodeService) Start() error {
	return nil
}

func (s *qrCodeService) Stop() {
	// no-op
}

func (s *qrCodeService) createQrCode(ctx context.Context, requestObject api.CreateQrCodeRequestObject) (api.CreateQrCodeResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.handler.CreateQrCode(auth, requestObject)
	if err == nil {
		return api.CreateQrCode200TextResponse(ret.Token), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.CreateQrCode500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.CreateQrCode401Response{}, nil
	}
	return api.CreateQrCode200TextResponse(""), nil
}
func (s *qrCodeService) checkQrCodeState(ctx context.Context, requestObject api.CheckQrCodeStateRequestObject) (api.CheckQrCodeStateResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.handler.CheckQrCodeState(auth, requestObject)
	if err == nil {
		return api.CheckQrCodeState200JSONResponse{
			QrCodeTokenDataJSONResponse: api.QrCodeTokenDataJSONResponse(*ret),
		}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.CheckQrCodeState401Response{}, nil
	}
	return api.CheckQrCodeState200JSONResponse{}, nil
}
func (s *qrCodeService) updateQrCodeToken(ctx context.Context, requestObject api.UpdateQrCodeTokenRequestObject) (api.UpdateQrCodeTokenResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.UpdateQrCodeToken(auth, requestObject)
	if err == nil {
		return api.UpdateQrCodeToken200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateQrCodeToken500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateQrCodeToken401Response{}, nil
	}
	return api.UpdateQrCodeToken400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
