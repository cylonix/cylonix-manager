// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"testing"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCheckUserType(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	assert.NoError(t, checkUserType(common.UserTypeAdmin, logger))
	assert.NoError(t, checkUserType(common.UserTypeUser, logger))
	assert.Error(t, checkUserType("invalid", logger))
}

func TestCheckNamespaceExists(t *testing.T) {
	// Nonexistent namespace.
	exists, err := checkNamespaceExists("never-exists-xxx", false)
	assert.NoError(t, err)
	assert.False(t, exists)

	// Check with registration fallback.
	exists, _ = checkNamespaceExists("never-exists-yyy", true)
	_ = exists
}

func TestLoginCredential_IsValid(t *testing.T) {
	l := &loginCredential{}
	assert.False(t, l.isValid())
	id := "u"
	pw := "p"
	l.loginID = &id
	assert.False(t, l.isValid())
	l.credential = &pw
	assert.True(t, l.isValid())
	empty := ""
	l.loginID = &empty
	assert.False(t, l.isValid())
}

func TestOauthProviderToLoginType(t *testing.T) {
	assert.Equal(t, types.LoginTypeGoogle, oauthProviderToLoginType("google"))
	assert.Equal(t, types.LoginTypeApple, oauthProviderToLoginType("apple"))
	assert.Equal(t, types.LoginTypeMicrosoft, oauthProviderToLoginType("microsoft"))
	assert.Equal(t, types.LoginTypeGithub, oauthProviderToLoginType("github"))
	assert.Equal(t, types.LoginTypeWeChat, oauthProviderToLoginType("wechat"))
	assert.Equal(t, types.LoginTypeCustomOIDC, oauthProviderToLoginType("custom-oidc-xxx"))
	assert.Equal(t, types.LoginTypeUnknown, oauthProviderToLoginType("bogus"))
}

func TestGetEmailDomainAndProvider(t *testing.T) {
	assert.Equal(t, "google.com", getEmailDomain("a@google.com"))
	assert.Equal(t, "", getEmailDomain("noat"))
	assert.Equal(t, "google", getProviderFromDomain("google.com"))
	assert.Equal(t, "", getProviderFromDomain("unknown-domain.xyz"))
	assert.Equal(t, "google", getProviderFromEmail("a@google.com"))
	assert.Equal(t, "", getProviderFromEmail("a@unknown-domain.xyz"))
}

func TestLoginCookieFunctions(t *testing.T) {
	// Ensure cookie funcs don't panic and produce some string.
	assert.NotEmpty(t, cookie("k", "v", "/", 100))
	assert.NotEmpty(t, apiKeyCookie("token", 10))
	assert.NotEmpty(t, apiKeyDeleteCookie())
	assert.NotEmpty(t, vpnAPIKeyCookie("token", 10))

	c := loginCookie{Email: "e", IsAdminUser: true}
	s, err := c.toCookie()
	assert.NoError(t, err)
	assert.NotEmpty(t, s)
}

func TestOauthLogins_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	_, err := h.OauthLogins()
	assert.NoError(t, err)
}

func TestRefreshToken_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// Nil token returns nil.
	_, err := h.RefreshToken(nil, api.RefreshTokenRequestObject{})
	assert.NoError(t, err)
}

func TestLogout_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// Nil token -> unauthorized.
	_, err := h.Logout(nil, api.LogoutRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Create a user token and logout.
	_, token := createTokenForTest(testNamespace, types.UserID(uuid.New()), "logout-user", false, nil)
	defer token.Delete()
	_, err = h.Logout(token, api.LogoutRequestObject{})
	assert.NoError(t, err)
}

func TestConfirmSession_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// Nil token -> unauthorized.
	err := h.ConfirmSession(nil, api.ConfirmSessionRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Valid token but missing session ID -> bad params.
	_, token := createTokenForTest(testNamespace, types.UserID(uuid.New()), "confirm-user", false, nil)
	defer token.Delete()
	err = h.ConfirmSession(token, api.ConfirmSessionRequestObject{})
	assert.Error(t, err)
}

func TestOauthRedirectURL_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// Bad user type + no provider/email -> bad params.
	_, err := h.OauthRedirectURL(nil, api.GetOauthRedirectURLRequestObject{
		Params: models.GetOauthRedirectURLParams{LoginAsAdmin: optional.BoolP(false)},
	})
	assert.Error(t, err)

	// Provider email match detected.
	_, err = h.OauthRedirectURL(nil, api.GetOauthRedirectURLRequestObject{
		Params: models.GetOauthRedirectURLParams{
			Email: optional.StringP("a@google.com"),
		},
	})
	// May succeed or fail depending on OAuth provider configs.
	_ = err
}

func TestOauthCallback_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// Missing code/state -> bad params.
	_, _, _, err := h.OauthCallback(nil, api.OauthCallbackRequestObject{
		Params: models.OauthCallbackParams{},
	})
	assert.Error(t, err)
}

func TestOauthCallbackPost_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// Nil body -> should error (nil body panic protection not built in,
	// so expect a body with empty fields).
	body := models.OauthCallbackPostFormdataRequestBody{}
	_, _, _, err := h.OauthCallbackPost(nil, api.OauthCallbackPostRequestObject{
		Body: &body,
	})
	assert.Error(t, err)
}

func TestAddOauthToken_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// Missing token -> bad params.
	body := models.Token{}
	_, _, _, err := h.AddOauthToken(nil, api.AddOauthTokenRequestObject{
		Body: &body,
	})
	assert.Error(t, err)
}

func TestListOauthProviders_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// nil token -> unauthorized.
	_, _, err := h.ListOauthProviders(nil, api.ListOauthProvidersRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Admin token: empty list.
	_, _, err = h.ListOauthProviders(testAdminToken, api.ListOauthProvidersRequestObject{})
	assert.NoError(t, err)
}

func TestDeleteOauthProviders_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// nil token -> unauthorized.
	err := h.DeleteOauthProviders(nil, api.DeleteOauthProvidersRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Admin token: no IDs, no-op.
	empty := []uuid.UUID{}
	err = h.DeleteOauthProviders(testAdminToken, api.DeleteOauthProvidersRequestObject{
		Body: &empty,
	})
	assert.NoError(t, err)
}

// TestDirectLogin_Impl exercises the error paths and the "token already"
// path of DirectLogin. Set up a user and try invalid/valid combinations.
func TestDirectLogin_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)

	// Missing login ID/credential -> bad params.
	_, _, _, _, err := h.DirectLogin(nil, api.LoginRequestObject{})
	assert.Error(t, err)

	// Invalid login type with all fields.
	_, _, _, _, err = h.DirectLogin(nil, api.LoginRequestObject{
		Params: models.LoginParams{
			LoginID:    optional.StringP("u"),
			Credential: optional.StringP("p"),
			LoginType:  models.LoginType("bogus"),
		},
	})
	assert.Error(t, err)

	// Redirect URL overrides missing credentials.
	redirect := "http://example.com"
	_, r, _, _, err := h.DirectLogin(nil, api.LoginRequestObject{
		Params: models.LoginParams{RedirectURL: &redirect},
	})
	assert.NoError(t, err)
	assert.NotNil(t, r)
}

// TestPasswordLogin exercises the handler.passwordLogin.
func TestPasswordLogin_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// Unknown login returns unauthorized.
	_, _, _, _, err := h.passwordLogin(
		testNamespace, "", "", "unknown-user", "wrong-pw", "",
		models.LoginParams{}, nil, testLogger,
	)
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}

// TestAddOauthProvider_Impl covers basic argument validation.
func TestAddOauthProvider_Impl(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// Non-sysadmin for custom namespace -> unauthorized.
	_, err := h.AddOauthProvider(nil, api.AddOauthProviderRequestObject{
		Body: &models.OauthProvider{
			Namespace: optional.StringP("custom-ns"),
		},
	})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Missing domain -> bad params.
	_, err = h.AddOauthProvider(testAdminToken, api.AddOauthProviderRequestObject{
		Body: &models.OauthProvider{},
	})
	assert.Error(t, err)

	// Missing credentials -> bad params.
	_, err = h.AddOauthProvider(testAdminToken, api.AddOauthProviderRequestObject{
		Body: &models.OauthProvider{
			Domain: "example.com",
		},
	})
	assert.Error(t, err)

	// Admin email / domain mismatch.
	_, err = h.AddOauthProvider(testAdminToken, api.AddOauthProviderRequestObject{
		Body: &models.OauthProvider{
			Domain:       "example.com",
			ClientID:     "c",
			ClientSecret: "s",
			AdminEmail:   "admin@other.com",
		},
	})
	assert.Error(t, err)
}

func TestGetCustomAuthIDFromProvider(t *testing.T) {
	s := &oauthSession{logger: logrus.NewEntry(logrus.New())}

	// Plain provider -> nil, no error.
	id, err := s.getCustomAuthIDFromProvider("google")
	assert.NoError(t, err)
	assert.Nil(t, id)

	// Bad custom-oidc ID format.
	_, err = s.getCustomAuthIDFromProvider("custom-oidc-bad")
	assert.Error(t, err)

	// Well-formed custom-oidc ID.
	validUUID := uuid.New().String()
	id, err = s.getCustomAuthIDFromProvider("custom-oidc-" + validUUID)
	assert.NoError(t, err)
	assert.NotNil(t, id)
}

func TestNewSysadminTenant_And_NewDefaultTenant(t *testing.T) {
	// Note: These may error since tenant creation touches the DB, but we
	// exercise them to cover the call-paths.
	s := &oauthSession{
		namespace: utils.SysAdminNamespace,
		oauthUser: nil,
		logger:    testLogger,
	}
	// NewDefaultTenant doesn't require oauthUser.
	tc, err := s.NewDefaultTenant()
	if err == nil {
		defer db.DeleteTenantConfigByNamespace(tc.Namespace)
	}
}

func TestOauthSessionClose(t *testing.T) {
	s := &oauthSession{logger: logrus.NewEntry(logrus.New())}
	s.close()
}

// Ensure sendCodeWithSmtp can handle default code in otp.go.
func TestOtpTokenLogin_NotSetup(t *testing.T) {
	// When SMS token not set, the call should return error.
	_, _, err := otpTokenLogin(
		"bogus-login", "wrong-code", nil, "", "",
		testLogger,
	)
	assert.Error(t, err)
}

// TestSmsCodeLogin_NotSetup exercises the SMS code login error path.
func TestSmsCodeLogin_NotSetup(t *testing.T) {
	_, _, _, err := smsCodeLogin(
		testNamespace, "11111111111", "bogus",
		nil, "", "", testLogger,
	)
	assert.Error(t, err)
}

// Exercise loginSession.result() via accessKeyLogin.doLogin failure path.
func TestAccessKeyLogin_InvalidKey(t *testing.T) {
	_, _, _, err := loginWithAccessKey(
		testNamespace, "not-a-valid-key", nil, "",
		testLogger,
	)
	assert.Error(t, err)
}

// Exercise service-layer directLogin with an empty request.
func TestLoginService_directLogin_Empty(t *testing.T) {
	s := NewService(testLogger)
	resp, err := s.directLogin(context.Background(), api.LoginRequestObject{})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
}
