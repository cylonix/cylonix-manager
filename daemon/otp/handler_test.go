// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package otp

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

type fakeHandler struct {
	sendCodeSent   bool
	sendCodeResult *models.OneTimeCodeSendResult
	sendCodeErr    error
	verifyRet      *string
	verifyErr      error
}

func (f *fakeHandler) SendCode(_ api.SendCodeRequestObject) (bool, *models.OneTimeCodeSendResult, error) {
	return f.sendCodeSent, f.sendCodeResult, f.sendCodeErr
}
func (f *fakeHandler) Verify(_ api.VerifyCodeRequestObject) (*string, error) {
	return f.verifyRet, f.verifyErr
}

func newSvc(f *fakeHandler) *OTPService {
	return &OTPService{
		handler: f,
		logger:  logrus.NewEntry(logrus.New()),
	}
}

func TestOTPService_Meta(t *testing.T) {
	s := NewService(logrus.NewEntry(logrus.New()))
	assert.Equal(t, "OTP api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
}

func TestOTPService_Register(t *testing.T) {
	s := NewService(logrus.NewEntry(logrus.New()))
	d := &api.StrictServer{}
	assert.NoError(t, s.Register(d))
	assert.NotNil(t, d.SendCodeHandler)
	assert.NotNil(t, d.VerifyCodeHandler)
}

func TestSendCode_Sent(t *testing.T) {
	result := &models.OneTimeCodeSendResult{}
	s := newSvc(&fakeHandler{sendCodeSent: true, sendCodeResult: result})
	resp, err := s.sendCode(context.Background(), api.SendCodeRequestObject{})
	assert.NoError(t, err)
	assert.IsType(t, api.SendCode200JSONResponse{}, resp)
}

func TestSendCode_NotSent(t *testing.T) {
	result := &models.OneTimeCodeSendResult{SendAgainTooSoon: true}
	s := newSvc(&fakeHandler{sendCodeSent: false, sendCodeResult: result})
	resp, err := s.sendCode(context.Background(), api.SendCodeRequestObject{})
	assert.NoError(t, err)
	assert.IsType(t, api.SendCode202JSONResponse{}, resp)
}

func TestSendCode_InternalError(t *testing.T) {
	s := newSvc(&fakeHandler{sendCodeErr: common.ErrInternalErr})
	resp, err := s.sendCode(context.Background(), api.SendCodeRequestObject{})
	assert.NoError(t, err)
	assert.IsType(t, api.SendCode500JSONResponse{}, resp)
}

func TestSendCode_BadRequest(t *testing.T) {
	s := newSvc(&fakeHandler{sendCodeErr: errors.New("bad")})
	resp, err := s.sendCode(context.Background(), api.SendCodeRequestObject{})
	assert.NoError(t, err)
	assert.IsType(t, api.SendCode400JSONResponse{}, resp)
}

func TestVerify_OK_WithCode(t *testing.T) {
	ret := "new-code"
	s := newSvc(&fakeHandler{verifyRet: &ret})
	resp, err := s.verify(context.Background(), api.VerifyCodeRequestObject{})
	assert.NoError(t, err)
	assert.IsType(t, api.VerifyCode200TextResponse(""), resp)
}

func TestVerify_OK_NoCode(t *testing.T) {
	s := newSvc(&fakeHandler{})
	resp, err := s.verify(context.Background(), api.VerifyCodeRequestObject{})
	assert.NoError(t, err)
	assert.IsType(t, api.VerifyCode200TextResponse(""), resp)
}

func TestVerify_Internal(t *testing.T) {
	s := newSvc(&fakeHandler{verifyErr: common.ErrInternalErr})
	resp, err := s.verify(context.Background(), api.VerifyCodeRequestObject{})
	assert.NoError(t, err)
	assert.IsType(t, api.VerifyCode500JSONResponse{}, resp)
}

func TestVerify_BadRequest(t *testing.T) {
	s := newSvc(&fakeHandler{verifyErr: errors.New("bad")})
	resp, err := s.verify(context.Background(), api.VerifyCodeRequestObject{})
	assert.NoError(t, err)
	assert.IsType(t, api.VerifyCode400JSONResponse{}, resp)
}

func TestHandlerImpl_SendCode_MissingParams(t *testing.T) {
	h := newHandlerImpl(logrus.NewEntry(logrus.New()))
	sent, _, err := h.SendCode(api.SendCodeRequestObject{})
	assert.False(t, sent)
	assert.Error(t, err)
}

func TestHandlerImpl_Verify_MissingParams(t *testing.T) {
	h := newHandlerImpl(logrus.NewEntry(logrus.New()))
	ret, err := h.Verify(api.VerifyCodeRequestObject{})
	assert.Nil(t, ret)
	assert.Error(t, err)
}
