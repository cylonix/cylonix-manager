// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"cylonix/sase/pkg/test/fixtures"
	"testing"
	"time"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestLoginHandler_Logout(t *testing.T) {
	h := newHandlerImpl(testLogger)
	// Nil auth -> passthrough.
	_, _ = h.Logout(nil, api.LogoutRequestObject{})
}

func TestLoginHandler_ListOauthProviders_Branches(t *testing.T) {
	h := newHandlerImpl(testLogger)

	// No token -> unauthorized.
	_, _, err := h.ListOauthProviders(nil, api.ListOauthProvidersRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Non-admin token.
	uid, _ := types.NewID()
	tok := &utils.UserTokenData{
		Token:     "t",
		Namespace: "ns-list-oauth",
		UserID:    uid.UUID(),
	}
	_, _, err = h.ListOauthProviders(tok, api.ListOauthProvidersRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Admin token.
	tokAdmin := &utils.UserTokenData{
		Token:       "t",
		Namespace:   "ns-list-oauth",
		UserID:      uid.UUID(),
		IsAdminUser: true,
	}
	_, _, _ = h.ListOauthProviders(tokAdmin, api.ListOauthProvidersRequestObject{})
}

func TestLoginHandler_DeleteOauthProviders_Branches(t *testing.T) {
	h := newHandlerImpl(testLogger)

	// No token -> unauthorized.
	err := h.DeleteOauthProviders(nil, api.DeleteOauthProvidersRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Admin token with empty body.
	uid, _ := types.NewID()
	tokAdmin := &utils.UserTokenData{
		Token:       "t",
		Namespace:   "ns-del-oauth",
		UserID:      uid.UUID(),
		IsAdminUser: true,
	}
	body := []uuid.UUID{}
	_ = h.DeleteOauthProviders(tokAdmin, api.DeleteOauthProvidersRequestObject{
		Body: &body,
	})
}

func TestLoginHandler_AddLogin_BadAuth(t *testing.T) {
	h := newHandlerImpl(testLogger)

	// No auth -> needs token.
	err := h.AddLogin(nil, api.AddLoginRequestObject{})
	assert.Error(t, err)
}

// PasswordLogin with a real user + valid/invalid password.
func TestPasswordLogin_WithFixtures(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	// Create a new login with a known password for the existing user.
	newUsername := "pwtest-" + s.Namespace
	newPassword := "StrongPass123!"

	// Add a username/password login attached to the user.
	login, err := types.NewUsernameLogin(s.Namespace, newUsername, newPassword, "", "")
	if !assert.NoError(t, err) {
		return
	}
	login.UserID = s.User.ID
	err = db.CreateUserLogin(login)
	if !assert.NoError(t, err) {
		return
	}

	h := newHandlerImpl(testLogger)

	// Unknown username -> unauthorized.
	_, _, _, _, err = h.passwordLogin(
		s.Namespace, "", "", "nope", "whatever", "",
		models.LoginParams{}, nil, testLogger,
	)
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Wrong password.
	_, _, _, _, err = h.passwordLogin(
		s.Namespace, "", "", newUsername, "wrong", "",
		models.LoginParams{}, nil, testLogger,
	)
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Correct password.
	ls, _, _, _, err := h.passwordLogin(
		s.Namespace, "", "", newUsername, newPassword, "",
		models.LoginParams{}, nil, testLogger,
	)
	_ = ls
	_ = err
}

// exerciseDirectLoginInvalid drives the DirectLogin error paths.
func TestDirectLogin_Invalid(t *testing.T) {
	withFakeHeadscale(t)
	h := newHandlerImpl(testLogger)

	// Missing login id + credential + no redirect URL -> bad params.
	_, _, _, _, err := h.DirectLogin(nil, api.LoginRequestObject{
		Params: models.LoginParams{},
	})
	assert.Error(t, err)

	// Invalid access point id -> bad params.
	_, _, _, _, err = h.DirectLogin(nil, api.LoginRequestObject{
		Params: models.LoginParams{
			LoginID:     optional.StringP("x"),
			Credential:  optional.StringP("y"),
			LoginType:   models.LoginTypeUsername,
			AccessPoint: optional.StringP("not-a-uuid"),
		},
	})
	assert.Error(t, err)

	// Unknown login type -> bad params.
	_, _, _, _, err = h.DirectLogin(nil, api.LoginRequestObject{
		Params: models.LoginParams{
			LoginID:    optional.StringP("x"),
			Credential: optional.StringP("y"),
			LoginType:  models.LoginType("bogus"),
		},
	})
	assert.Error(t, err)
}

func TestAccessKeyLogin_ValidKey_WithFixtures(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	exp := time.Now().Add(time.Hour).Unix() // not expired
	scope := []string{"user"}
	note := "test"
	akey, err := db.CreateAccessKey(s.Namespace, s.User.ID, "u", &note, &scope, &exp)
	if !assert.NoError(t, err) {
		return
	}
	defer db.DeleteAccessKey(s.Namespace, akey.ID.String())

	// Using the key ID as the access key (what CheckAccessKey actually looks up).
	ls, _, state, err := loginWithAccessKey(s.Namespace, akey.ID.String(), nil, "", testLogger)
	assert.NoError(t, err)
	assert.Nil(t, state)
	assert.NotNil(t, ls)
}

func TestDirectLogin_AccessKey_WithFixtures(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	exp := time.Now().Add(time.Hour).Unix()
	scope := []string{"user"}
	note := "test"
	akey, err := db.CreateAccessKey(s.Namespace, s.User.ID, "u", &note, &scope, &exp)
	if !assert.NoError(t, err) {
		return
	}
	defer db.DeleteAccessKey(s.Namespace, akey.ID.String())

	h := newHandlerImpl(testLogger)
	loginSuccess, _, _, _, err := h.DirectLogin(nil, api.LoginRequestObject{
		Params: models.LoginParams{
			Namespace:  &s.Namespace,
			LoginID:    optional.StringP("u"),
			Credential: optional.StringP(akey.ID.String()),
			LoginType:  models.LoginTypeAccessKey,
		},
	})
	assert.NoError(t, err)
	_ = loginSuccess
}

func TestDirectLogin_Token(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(testLogger)

	// Using an existing token (loginSuccessFromUserToken path).
	// Set the login type so the token maps to the seeded username login.
	s.UserToken.LoginType = string(types.LoginTypeUsername)
	ls, _, _, _, err := h.DirectLogin(s.UserToken, api.LoginRequestObject{
		Params: models.LoginParams{},
	})
	assert.NoError(t, err)
	_ = ls
}

func TestOauthRedirectURL_BadParams(t *testing.T) {
	h := newHandlerImpl(testLogger)

	// No namespace, no provider, no email -> bad params.
	_, err := h.OauthRedirectURL(nil, api.GetOauthRedirectURLRequestObject{
		Params: models.GetOauthRedirectURLParams{},
	})
	assert.Error(t, err)

	// Unknown namespace -> unauthorized.
	_, err = h.OauthRedirectURL(nil, api.GetOauthRedirectURLRequestObject{
		Params: models.GetOauthRedirectURLParams{
			Namespace: optional.StringP("unknown-namespace"),
			Provider:  optional.StringP("google"),
		},
	})
	assert.Error(t, err)
}

func TestRefreshToken_Nil(t *testing.T) {
	h := newHandlerImpl(testLogger)
	ls, err := h.RefreshToken(nil, api.RefreshTokenRequestObject{})
	assert.NoError(t, err)
	assert.Nil(t, ls)
}

func TestAddOauthToken_NilToken(t *testing.T) {
	h := newHandlerImpl(testLogger)
	_, _, _, err := h.AddOauthToken(nil, api.AddOauthTokenRequestObject{
		Body: &models.Token{},
	})
	assert.Error(t, err)
}

func TestPasswordLogin_BadUser(t *testing.T) {
	h := newHandlerImpl(testLogger)
	_, _, _, _, err := h.passwordLogin(
		"ns", "", "", "nouser", "nopass", "", models.LoginParams{}, nil, testLogger,
	)
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}

func TestConfirmSession_MissingSession(t *testing.T) {
	h := newHandlerImpl(testLogger)
	_, err := db.CreateUserTier(&types.UserTier{
		Name:           "tier-confirm",
		MaxUserCount:   1,
		MaxDeviceCount: 1,
	})
	if err == nil {
		defer db.DeleteUserTierByName("tier-confirm")
	}

	// Call with a valid token but no session ID.
	uid, _ := types.NewID()
	tok := &utils.UserTokenData{
		Token:     "t",
		Namespace: "ns-confirm",
		UserID:    uid.UUID(),
		LoginType: string(types.LoginTypeUsername),
	}
	err = h.ConfirmSession(tok, api.ConfirmSessionRequestObject{
		Params: models.ConfirmSessionParams{},
	})
	assert.Error(t, err)

	// Missing token entirely -> unauthorized.
	err = h.ConfirmSession(nil, api.ConfirmSessionRequestObject{
		Params: models.ConfirmSessionParams{SessionID: "x"},
	})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}

func TestNewLoginSuccess_AccessKeyFlow(t *testing.T) {
	// Exercise the accessKeyLogin struct's newLoginSuccess + setUser.
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	exp := time.Now().Add(time.Hour).Unix()
	scope := []string{"user"}
	akey, err := db.CreateAccessKey(s.Namespace, s.User.ID, "u", nil, &scope, &exp)
	if !assert.NoError(t, err) {
		return
	}
	defer db.DeleteAccessKey(s.Namespace, akey.ID.String())

	al, err := newAccessKeyLogin(s.Namespace, akey.ID.String(), nil, "", testLogger)
	if !assert.NoError(t, err) {
		return
	}
	assert.NoError(t, al.setUser())
	ls := al.newLoginSuccess()
	assert.NotNil(t, ls)

	// doLogin uses setUser + newLoginSuccess.result().
	ok, _, err := al.doLogin()
	assert.NoError(t, err)
	assert.NotNil(t, ok)
}

func TestOauthPasswordLoginFlow_BadParams(t *testing.T) {
	// Calling OauthPasswordLogin directly with bad params exercises the
	// error path.
	_, _, _, err := OauthPasswordLogin("bogus", common.UserTypeUser, "ns-none", "", "", nil, testLogger)
	assert.Error(t, err)
}

func TestOauthIDTokenLogin_Invalid(t *testing.T) {
	_, _, _, err := oauthIDTokenLogin("google", common.UserTypeUser, "ns", "notatoken", nil, testLogger)
	assert.Error(t, err)
}

// Exercise the happy path of otpTokenLogin using a real OTP token whose
// state points at an admin user token.
func TestOtpTokenLogin_AdminFlow(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	// Promote the admin token to "approved device".
	s.AdminToken.FromApprovedDevice = true

	// Create an OTP token whose state contains the admin's api key.
	otp := &utils.OtpToken{Token: utils.New6DigitCode()}
	code := utils.New6DigitCode()
	assert.NoError(t, otp.Set(s.AdminToken.Token, code, false))

	ls, _, err := otpTokenLogin(
		otp.Token, code, nil, "", "", testLogger,
	)
	_ = ls
	_ = err
}

// Drive getUser's sysadmin + approval branches.
func TestGetUser_Branches(t *testing.T) {
	// Unknown sysadmin login -> error.
	login := &types.UserLogin{
		Namespace: "ns-getuser",
		LoginName: "never-exists",
		LoginType: types.LoginTypeUsername,
	}
	_, _, _, err := getUser(true, login, "", "", nil, nil, nil, testLogger)
	assert.Error(t, err)

	// Custom namespace new user -> should create a pending approval.
	login2 := &types.UserLogin{
		Namespace: "ns-getuser",
		LoginName: "new@example.com",
		LoginType: types.LoginTypeUsername,
	}
	loginOut, user, state, err := getUser(false, login2, "", "", nil, nil, nil, testLogger)
	_ = loginOut
	_ = user
	if err == nil {
		if assert.NotNil(t, state) {
			assert.Equal(t, types.ApprovalStatePending, *state)
		}
	}
}
