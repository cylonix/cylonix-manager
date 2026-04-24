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

type fakeOtpHandler struct {
	err    error
	sent   bool
	result *models.OneTimeCodeSendResult
	ret    *string
}

func (f *fakeOtpHandler) SendCode(api.SendCodeRequestObject) (bool, *models.OneTimeCodeSendResult, error) {
	return f.sent, f.result, f.err
}
func (f *fakeOtpHandler) Verify(api.VerifyCodeRequestObject) (*string, error) {
	return f.ret, f.err
}

func newOtpSvc(h *fakeOtpHandler) *OTPService {
	return &OTPService{
		handler: h,
		logger:  logrus.NewEntry(logrus.New()),
	}
}

func TestOTPService_MetaAndRegister(t *testing.T) {
	s := NewService(logrus.NewEntry(logrus.New()))
	assert.Equal(t, "OTP api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
	d := &api.StrictServer{}
	assert.NoError(t, s.Register(d))
	assert.NotNil(t, d.SendCodeHandler)
	assert.NotNil(t, d.VerifyCodeHandler)
}

func TestOTPService_SendCode_Branches(t *testing.T) {
	result := &models.OneTimeCodeSendResult{}
	// Success: sent == true.
	s := newOtpSvc(&fakeOtpHandler{err: nil, sent: true, result: result})
	resp, _ := s.sendCode(context.Background(), api.SendCodeRequestObject{})
	assert.IsType(t, api.SendCode200JSONResponse{}, resp)

	// Success but not sent -> 202.
	s = newOtpSvc(&fakeOtpHandler{err: nil, sent: false, result: result})
	resp, _ = s.sendCode(context.Background(), api.SendCodeRequestObject{})
	assert.IsType(t, api.SendCode202JSONResponse{}, resp)

	// 500.
	s = newOtpSvc(&fakeOtpHandler{err: common.ErrInternalErr, result: result})
	resp, _ = s.sendCode(context.Background(), api.SendCodeRequestObject{})
	assert.IsType(t, api.SendCode500JSONResponse{}, resp)

	// 400.
	s = newOtpSvc(&fakeOtpHandler{err: errors.New("x"), result: result})
	resp, _ = s.sendCode(context.Background(), api.SendCodeRequestObject{})
	assert.IsType(t, api.SendCode400JSONResponse{}, resp)
}

func TestOTPService_Verify_Branches(t *testing.T) {
	val := "ok"

	// Success with value.
	s := newOtpSvc(&fakeOtpHandler{ret: &val})
	resp, _ := s.verify(context.Background(), api.VerifyCodeRequestObject{})
	assert.IsType(t, api.VerifyCode200TextResponse(""), resp)

	// Success with nil ret.
	s = newOtpSvc(&fakeOtpHandler{})
	resp, _ = s.verify(context.Background(), api.VerifyCodeRequestObject{})
	assert.IsType(t, api.VerifyCode200TextResponse(""), resp)

	// 500.
	s = newOtpSvc(&fakeOtpHandler{err: common.ErrInternalErr})
	resp, _ = s.verify(context.Background(), api.VerifyCodeRequestObject{})
	assert.IsType(t, api.VerifyCode500JSONResponse{}, resp)

	// 400.
	s = newOtpSvc(&fakeOtpHandler{err: errors.New("x")})
	resp, _ = s.verify(context.Background(), api.VerifyCodeRequestObject{})
	assert.IsType(t, api.VerifyCode400JSONResponse{}, resp)
}
