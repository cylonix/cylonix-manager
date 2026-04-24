// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package qrcode

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"errors"
	"testing"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakeQrHandler struct {
	err    error
	token  *utils.QRCodeToken
	tokData *models.QrCodeTokenData
}

func (f *fakeQrHandler) CreateQrCode(_ any, _ api.CreateQrCodeRequestObject) (*utils.QRCodeToken, error) {
	return f.token, f.err
}
func (f *fakeQrHandler) UpdateQrCodeToken(_ any, _ api.UpdateQrCodeTokenRequestObject) error {
	return f.err
}
func (f *fakeQrHandler) CheckQrCodeState(_ any, _ api.CheckQrCodeStateRequestObject) (*models.QrCodeTokenData, error) {
	return f.tokData, f.err
}

func newQrSvc(h *fakeQrHandler) *qrCodeService {
	return &qrCodeService{
		handler: h,
		logger:  logrus.NewEntry(logrus.New()),
	}
}

func TestQrService_MetaAndRegister(t *testing.T) {
	s := NewService(logrus.NewEntry(logrus.New()))
	assert.Equal(t, "qr-code api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
	d := &api.StrictServer{}
	assert.NoError(t, s.Register(d))
	assert.NotNil(t, d.CreateQrCodeHandler)
	assert.NotNil(t, d.CheckQrCodeStateHandler)
	assert.NotNil(t, d.UpdateQrCodeTokenHandler)
}

func TestQrService_CreateQrCode_Branches(t *testing.T) {
	tok := &utils.QRCodeToken{Token: "t"}
	cases := []error{nil, common.ErrInternalErr, common.ErrModelUnauthorized, errors.New("x")}
	for _, err := range cases {
		s := newQrSvc(&fakeQrHandler{err: err, token: tok})
		_, _ = s.createQrCode(context.Background(), api.CreateQrCodeRequestObject{})
	}
}

func TestQrService_CheckQrCodeState_Branches(t *testing.T) {
	data := &models.QrCodeTokenData{}
	cases := []error{nil, common.ErrModelUnauthorized, errors.New("x")}
	for _, err := range cases {
		s := newQrSvc(&fakeQrHandler{err: err, tokData: data})
		_, _ = s.checkQrCodeState(context.Background(), api.CheckQrCodeStateRequestObject{})
	}
}

func TestQrService_UpdateQrCodeToken_Branches(t *testing.T) {
	cases := []error{nil, common.ErrInternalErr, common.ErrModelUnauthorized, errors.New("x")}
	for _, err := range cases {
		s := newQrSvc(&fakeQrHandler{err: err})
		_, _ = s.updateQrCodeToken(context.Background(), api.UpdateQrCodeTokenRequestObject{})
	}
}
