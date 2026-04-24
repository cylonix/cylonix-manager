// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/optional"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakeLoginHandler struct {
	addErr                                 error
	confirmErr                             error
	delProvErr                             error
	logoutErr, logoutRedirect              error
	refreshErr                             error
	addProviderErr                         error
	addTokenErr                            error
	directErr                              error
	redirectConfig                         *models.RedirectURLConfig
	loginSuccess                           *models.LoginSuccess
	approvalState                          *models.ApprovalState
	additionalAuth                         *models.AdditionalAuthInfo
	oauthLogins                            []models.LoginType
	oauthLoginsErr                         error
	oauthRedirectURLErr                    error
	oauthCallbackErr, oauthCallbackPostErr error
	listProvidersErr                       error
	listProvidersTotal                     int
	listProviders                          []models.OauthProvider
	logoutRedirectCfg                      *models.RedirectURLConfig
}

func (f *fakeLoginHandler) AddLogin(_ interface{}, _ api.AddLoginRequestObject) error {
	return f.addErr
}
func (f *fakeLoginHandler) AddOauthProvider(_ interface{}, _ api.AddOauthProviderRequestObject) (*models.RedirectURLConfig, error) {
	return f.redirectConfig, f.addProviderErr
}
func (f *fakeLoginHandler) AddOauthToken(_ interface{}, _ api.AddOauthTokenRequestObject) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	return f.loginSuccess, f.redirectConfig, f.approvalState, f.addTokenErr
}
func (f *fakeLoginHandler) ConfirmSession(_ interface{}, _ api.ConfirmSessionRequestObject) error {
	return f.confirmErr
}
func (f *fakeLoginHandler) DeleteOauthProviders(_ interface{}, _ api.DeleteOauthProvidersRequestObject) error {
	return f.delProvErr
}
func (f *fakeLoginHandler) DirectLogin(_ interface{}, _ api.LoginRequestObject) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, *models.AdditionalAuthInfo, error) {
	return f.loginSuccess, f.redirectConfig, f.approvalState, f.additionalAuth, f.directErr
}
func (f *fakeLoginHandler) ListOauthProviders(_ interface{}, _ api.ListOauthProvidersRequestObject) (int, []models.OauthProvider, error) {
	return f.listProvidersTotal, f.listProviders, f.listProvidersErr
}
func (f *fakeLoginHandler) Logout(_ interface{}, _ api.LogoutRequestObject) (*models.RedirectURLConfig, error) {
	return f.logoutRedirectCfg, f.logoutErr
}
func (f *fakeLoginHandler) OauthLogins() ([]models.LoginType, error) {
	return f.oauthLogins, f.oauthLoginsErr
}
func (f *fakeLoginHandler) OauthRedirectURL(_ interface{}, _ api.GetOauthRedirectURLRequestObject) (*models.RedirectURLConfig, error) {
	return f.redirectConfig, f.oauthRedirectURLErr
}
func (f *fakeLoginHandler) OauthCallback(_ interface{}, _ api.OauthCallbackRequestObject) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	return f.loginSuccess, f.redirectConfig, f.approvalState, f.oauthCallbackErr
}
func (f *fakeLoginHandler) OauthCallbackPost(_ interface{}, _ api.OauthCallbackPostRequestObject) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	return f.loginSuccess, f.redirectConfig, f.approvalState, f.oauthCallbackPostErr
}
func (f *fakeLoginHandler) RefreshToken(_ interface{}, _ api.RefreshTokenRequestObject) (*models.LoginSuccess, error) {
	return f.loginSuccess, f.refreshErr
}

func newLoginSvc(h *fakeLoginHandler) *LoginService {
	return &LoginService{handler: h, logger: logrus.NewEntry(logrus.New())}
}

func TestLoginService_Meta(t *testing.T) {
	s := NewService(logrus.NewEntry(logrus.New()))
	assert.Equal(t, "login api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
	d := &api.StrictServer{}
	assert.NoError(t, s.Register(d))
	assert.NotNil(t, d.LoginHandler)
	assert.NotNil(t, d.LogoutHandler)
}

func TestAddLogin_Branches(t *testing.T) {
	s := newLoginSvc(&fakeLoginHandler{})
	resp, _ := s.addLogin(context.Background(), api.AddLoginRequestObject{})
	assert.IsType(t, api.AddLogin200JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{addErr: common.ErrInternalErr})
	resp, _ = s.addLogin(context.Background(), api.AddLoginRequestObject{})
	assert.IsType(t, api.AddLogin500JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{addErr: common.ErrModelUnauthorized})
	resp, _ = s.addLogin(context.Background(), api.AddLoginRequestObject{})
	assert.IsType(t, api.AddLogin401Response{}, resp)

	s = newLoginSvc(&fakeLoginHandler{addErr: errors.New("x")})
	resp, _ = s.addLogin(context.Background(), api.AddLoginRequestObject{})
	assert.IsType(t, api.AddLogin400JSONResponse{}, resp)
}

func TestConfirmSession_Branches(t *testing.T) {
	s := newLoginSvc(&fakeLoginHandler{})
	resp, _ := s.confirmSession(context.Background(), api.ConfirmSessionRequestObject{})
	assert.IsType(t, api.ConfirmSession200TextResponse(""), resp)

	s = newLoginSvc(&fakeLoginHandler{confirmErr: common.ErrInternalErr})
	resp, _ = s.confirmSession(context.Background(), api.ConfirmSessionRequestObject{})
	assert.IsType(t, api.ConfirmSession500JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{confirmErr: common.ErrModelUnauthorized})
	resp, _ = s.confirmSession(context.Background(), api.ConfirmSessionRequestObject{})
	assert.IsType(t, api.ConfirmSession401Response{}, resp)

	s = newLoginSvc(&fakeLoginHandler{confirmErr: errors.New("x")})
	resp, _ = s.confirmSession(context.Background(), api.ConfirmSessionRequestObject{})
	assert.IsType(t, api.ConfirmSession400JSONResponse{}, resp)
}

func TestOauthRedirectURL_Branches(t *testing.T) {
	cfg := &models.RedirectURLConfig{EncodedRedirectURL: optional.StringP("u")}
	s := newLoginSvc(&fakeLoginHandler{redirectConfig: cfg})
	resp, _ := s.oauthRedirectURL(context.Background(), api.GetOauthRedirectURLRequestObject{})
	assert.IsType(t, api.GetOauthRedirectURL200JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{oauthRedirectURLErr: common.ErrInternalErr})
	resp, _ = s.oauthRedirectURL(context.Background(), api.GetOauthRedirectURLRequestObject{})
	assert.IsType(t, api.GetOauthRedirectURL500JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{oauthRedirectURLErr: common.ErrModelUnauthorized})
	resp, _ = s.oauthRedirectURL(context.Background(), api.GetOauthRedirectURLRequestObject{})
	assert.IsType(t, api.GetOauthRedirectURL401Response{}, resp)

	s = newLoginSvc(&fakeLoginHandler{oauthRedirectURLErr: errors.New("x")})
	resp, _ = s.oauthRedirectURL(context.Background(), api.GetOauthRedirectURLRequestObject{})
	assert.IsType(t, api.GetOauthRedirectURL400JSONResponse{}, resp)
}

func TestOauthLogins_Branches(t *testing.T) {
	s := newLoginSvc(&fakeLoginHandler{oauthLogins: []models.LoginType{models.LoginType("g")}})
	resp, _ := s.oauthLogins(context.Background(), api.OauthLoginsRequestObject{})
	assert.IsType(t, api.OauthLogins200JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{oauthLoginsErr: errors.New("x")})
	resp, _ = s.oauthLogins(context.Background(), api.OauthLoginsRequestObject{})
	assert.IsType(t, api.OauthLogins500JSONResponse{}, resp)
}

func TestRefreshToken_Branches(t *testing.T) {
	ls := &models.LoginSuccess{APIKey: "k"}
	s := newLoginSvc(&fakeLoginHandler{loginSuccess: ls})
	resp, _ := s.refreshToken(context.Background(), api.RefreshTokenRequestObject{})
	assert.IsType(t, api.RefreshToken200JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{refreshErr: common.ErrInternalErr})
	resp, _ = s.refreshToken(context.Background(), api.RefreshTokenRequestObject{})
	assert.IsType(t, api.RefreshToken500JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{refreshErr: common.ErrModelUnauthorized})
	resp, _ = s.refreshToken(context.Background(), api.RefreshTokenRequestObject{})
	assert.IsType(t, api.RefreshToken401Response{}, resp)

	s = newLoginSvc(&fakeLoginHandler{refreshErr: errors.New("x")})
	resp, _ = s.refreshToken(context.Background(), api.RefreshTokenRequestObject{})
	assert.IsType(t, api.RefreshToken400JSONResponse{}, resp)
}

func TestListOauthProviders_Branches(t *testing.T) {
	s := newLoginSvc(&fakeLoginHandler{listProvidersTotal: 2, listProviders: []models.OauthProvider{{}, {}}})
	resp, _ := s.listOauthProviders(context.Background(), api.ListOauthProvidersRequestObject{})
	assert.IsType(t, api.ListOauthProviders200JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{listProvidersErr: common.ErrModelUnauthorized})
	resp, _ = s.listOauthProviders(context.Background(), api.ListOauthProvidersRequestObject{})
	assert.IsType(t, api.ListOauthProviders401Response{}, resp)

	s = newLoginSvc(&fakeLoginHandler{listProvidersErr: errors.New("x")})
	resp, _ = s.listOauthProviders(context.Background(), api.ListOauthProvidersRequestObject{})
	assert.IsType(t, api.ListOauthProviders500JSONResponse{}, resp)
}

func TestDeleteOauthProviders_Branches(t *testing.T) {
	s := newLoginSvc(&fakeLoginHandler{})
	resp, _ := s.deleteOauthProviders(context.Background(), api.DeleteOauthProvidersRequestObject{})
	assert.IsType(t, api.DeleteOauthProviders200TextResponse(""), resp)

	s = newLoginSvc(&fakeLoginHandler{delProvErr: common.ErrInternalErr})
	resp, _ = s.deleteOauthProviders(context.Background(), api.DeleteOauthProvidersRequestObject{})
	assert.IsType(t, api.DeleteOauthProviders500JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{delProvErr: common.ErrModelUnauthorized})
	resp, _ = s.deleteOauthProviders(context.Background(), api.DeleteOauthProvidersRequestObject{})
	assert.IsType(t, api.DeleteOauthProviders401Response{}, resp)

	s = newLoginSvc(&fakeLoginHandler{delProvErr: errors.New("x")})
	resp, _ = s.deleteOauthProviders(context.Background(), api.DeleteOauthProvidersRequestObject{})
	assert.IsType(t, api.DeleteOauthProviders400JSONResponse{}, resp)
}

func TestLogout_Branches(t *testing.T) {
	cfg := &models.RedirectURLConfig{EncodedRedirectURL: optional.StringP("x")}
	s := newLoginSvc(&fakeLoginHandler{logoutRedirectCfg: cfg})
	resp, _ := s.logout(context.Background(), api.LogoutRequestObject{})
	assert.IsType(t, api.Logout200JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{logoutErr: common.ErrInternalErr})
	resp, _ = s.logout(context.Background(), api.LogoutRequestObject{})
	assert.IsType(t, api.Logout500JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{logoutErr: common.ErrModelUnauthorized})
	resp, _ = s.logout(context.Background(), api.LogoutRequestObject{})
	assert.IsType(t, api.Logout401Response{}, resp)

	s = newLoginSvc(&fakeLoginHandler{logoutErr: errors.New("x")})
	resp, _ = s.logout(context.Background(), api.LogoutRequestObject{})
	assert.IsType(t, api.Logout400JSONResponse{}, resp)
}

func TestDirectLogin_Branches(t *testing.T) {
	// Success with login
	s := newLoginSvc(&fakeLoginHandler{loginSuccess: &models.LoginSuccess{APIKey: "k"}})
	resp, _ := s.directLogin(context.Background(), api.LoginRequestObject{})
	assert.IsType(t, api.Login200JSONResponse{}, resp)

	// Success with approval
	state := models.ApprovalState(models.ApprovalStatePending)
	s = newLoginSvc(&fakeLoginHandler{approvalState: &state})
	resp, _ = s.directLogin(context.Background(), api.LoginRequestObject{})
	assert.IsType(t, api.Login303JSONResponse{}, resp)

	// Success with redirect
	cfg := &models.RedirectURLConfig{EncodedRedirectURL: optional.StringP("u")}
	s = newLoginSvc(&fakeLoginHandler{redirectConfig: cfg})
	resp, _ = s.directLogin(context.Background(), api.LoginRequestObject{})
	assert.IsType(t, api.Login307Response{}, resp)

	// Success with additional auth
	info := &models.AdditionalAuthInfo{}
	s = newLoginSvc(&fakeLoginHandler{additionalAuth: info})
	resp, _ = s.directLogin(context.Background(), api.LoginRequestObject{})
	assert.IsType(t, api.Login428JSONResponse{}, resp)

	// Error branches
	s = newLoginSvc(&fakeLoginHandler{directErr: common.ErrInternalErr})
	resp, _ = s.directLogin(context.Background(), api.LoginRequestObject{})
	assert.IsType(t, api.Login500JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{directErr: common.ErrModelUnauthorized})
	resp, _ = s.directLogin(context.Background(), api.LoginRequestObject{})
	assert.IsType(t, api.Login401Response{}, resp)

	s = newLoginSvc(&fakeLoginHandler{directErr: errors.New("x")})
	resp, _ = s.directLogin(context.Background(), api.LoginRequestObject{})
	assert.IsType(t, api.Login400JSONResponse{}, resp)
}

func TestAddOauthProvider_Branches(t *testing.T) {
	cfg := &models.RedirectURLConfig{EncodedRedirectURL: optional.StringP("u")}
	s := newLoginSvc(&fakeLoginHandler{redirectConfig: cfg})
	resp, _ := s.addOauthProvider(context.Background(), api.AddOauthProviderRequestObject{})
	assert.IsType(t, api.AddOauthProvider200TextResponse(""), resp)

	s = newLoginSvc(&fakeLoginHandler{addProviderErr: common.ErrInternalErr})
	resp, _ = s.addOauthProvider(context.Background(), api.AddOauthProviderRequestObject{})
	assert.IsType(t, api.AddOauthProvider500JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{addProviderErr: common.ErrModelUnauthorized})
	resp, _ = s.addOauthProvider(context.Background(), api.AddOauthProviderRequestObject{})
	assert.IsType(t, api.AddOauthProvider401Response{}, resp)

	s = newLoginSvc(&fakeLoginHandler{addProviderErr: errors.New("x")})
	resp, _ = s.addOauthProvider(context.Background(), api.AddOauthProviderRequestObject{})
	assert.IsType(t, api.AddOauthProvider400JSONResponse{}, resp)
}

func TestAddOauthToken_Branches(t *testing.T) {
	ls := &models.LoginSuccess{APIKey: "k"}
	s := newLoginSvc(&fakeLoginHandler{loginSuccess: ls})
	resp, _ := s.addOauthToken(context.Background(), api.AddOauthTokenRequestObject{})
	assert.IsType(t, api.AddOauthToken200JSONResponse{}, resp)

	// Approval state
	state := models.ApprovalState(models.ApprovalStatePending)
	s = newLoginSvc(&fakeLoginHandler{approvalState: &state})
	resp, _ = s.addOauthToken(context.Background(), api.AddOauthTokenRequestObject{})
	assert.IsType(t, api.AddOauthToken303JSONResponse{}, resp)

	// Redirect
	cfg := &models.RedirectURLConfig{EncodedRedirectURL: optional.StringP("u")}
	s = newLoginSvc(&fakeLoginHandler{redirectConfig: cfg, loginSuccess: ls})
	resp, _ = s.addOauthToken(context.Background(), api.AddOauthTokenRequestObject{})
	assert.IsType(t, api.AddOauthToken302JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{addTokenErr: common.ErrInternalErr})
	resp, _ = s.addOauthToken(context.Background(), api.AddOauthTokenRequestObject{})
	assert.IsType(t, api.AddOauthToken500JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{addTokenErr: common.ErrModelUnauthorized})
	resp, _ = s.addOauthToken(context.Background(), api.AddOauthTokenRequestObject{})
	assert.IsType(t, api.AddOauthToken401Response{}, resp)

	s = newLoginSvc(&fakeLoginHandler{addTokenErr: errors.New("x")})
	resp, _ = s.addOauthToken(context.Background(), api.AddOauthTokenRequestObject{})
	assert.IsType(t, api.AddOauthToken400JSONResponse{}, resp)
}

func TestOauthCallback_Branches(t *testing.T) {
	ls := &models.LoginSuccess{APIKey: "k"}
	s := newLoginSvc(&fakeLoginHandler{loginSuccess: ls})
	resp, _ := s.oauthCallback(context.Background(), api.OauthCallbackRequestObject{})
	assert.IsType(t, api.OauthCallback200JSONResponse{}, resp)

	state := models.ApprovalState(models.ApprovalStatePending)
	s = newLoginSvc(&fakeLoginHandler{approvalState: &state})
	resp, _ = s.oauthCallback(context.Background(), api.OauthCallbackRequestObject{})
	assert.IsType(t, api.OauthCallback303JSONResponse{}, resp)

	cfg := &models.RedirectURLConfig{EncodedRedirectURL: optional.StringP("u")}
	s = newLoginSvc(&fakeLoginHandler{redirectConfig: cfg, loginSuccess: ls})
	resp, _ = s.oauthCallback(context.Background(), api.OauthCallbackRequestObject{})
	assert.IsType(t, api.OauthCallback302JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{oauthCallbackErr: common.ErrInternalErr})
	resp, _ = s.oauthCallback(context.Background(), api.OauthCallbackRequestObject{})
	assert.IsType(t, api.OauthCallback303JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{oauthCallbackErr: common.ErrModelUnauthorized})
	resp, _ = s.oauthCallback(context.Background(), api.OauthCallbackRequestObject{})
	assert.IsType(t, api.OauthCallback303JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{oauthCallbackErr: errors.New("x")})
	resp, _ = s.oauthCallback(context.Background(), api.OauthCallbackRequestObject{})
	assert.IsType(t, api.OauthCallback303JSONResponse{}, resp)
}

func TestOauthCallbackPost_Branches(t *testing.T) {
	ls := &models.LoginSuccess{APIKey: "k"}
	s := newLoginSvc(&fakeLoginHandler{loginSuccess: ls})
	resp, _ := s.oauthCallbackPost(context.Background(), api.OauthCallbackPostRequestObject{})
	assert.IsType(t, api.OauthCallbackPost200JSONResponse{}, resp)

	state := models.ApprovalState(models.ApprovalStatePending)
	s = newLoginSvc(&fakeLoginHandler{approvalState: &state})
	resp, _ = s.oauthCallbackPost(context.Background(), api.OauthCallbackPostRequestObject{})
	assert.IsType(t, api.OauthCallbackPost303JSONResponse{}, resp)

	cfg := &models.RedirectURLConfig{EncodedRedirectURL: optional.StringP("u")}
	s = newLoginSvc(&fakeLoginHandler{redirectConfig: cfg, loginSuccess: ls})
	resp, _ = s.oauthCallbackPost(context.Background(), api.OauthCallbackPostRequestObject{})
	assert.IsType(t, api.OauthCallbackPost302JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{oauthCallbackPostErr: common.ErrInternalErr})
	resp, _ = s.oauthCallbackPost(context.Background(), api.OauthCallbackPostRequestObject{})
	assert.IsType(t, api.OauthCallbackPost303JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{oauthCallbackPostErr: common.ErrModelUnauthorized})
	resp, _ = s.oauthCallbackPost(context.Background(), api.OauthCallbackPostRequestObject{})
	assert.IsType(t, api.OauthCallbackPost303JSONResponse{}, resp)

	s = newLoginSvc(&fakeLoginHandler{oauthCallbackPostErr: errors.New("x")})
	resp, _ = s.oauthCallbackPost(context.Background(), api.OauthCallbackPostRequestObject{})
	assert.IsType(t, api.OauthCallbackPost303JSONResponse{}, resp)
}

func TestSeeOtherJSONResponseHelper(t *testing.T) {
	r := seeOtherJSONResponse("http://a")
	assert.Equal(t, "http://a", r.Headers.Location)
}

func TestLoginSuccessToJSONResponse(t *testing.T) {
	ttl := 60
	ls := &models.LoginSuccess{APIKey: "k", VpnAPIKey: optional.StringP("v"), APIKeyTTL: &ttl}
	resp := loginSuccessToJSONResponse(ls)
	assert.Equal(t, "k", resp.Body.APIKey)
	assert.NotEmpty(t, resp.Headers.SetCookie)
}

func TestLoginSuccessToJSONResponse_DefaultTTL(t *testing.T) {
	ls := &models.LoginSuccess{APIKey: "k"}
	resp := loginSuccessToJSONResponse(ls)
	assert.NotEmpty(t, resp.Headers.SetCookie)
}
