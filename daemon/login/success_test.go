// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"testing"

	"github.com/cylonix/utils"
	"github.com/stretchr/testify/assert"
)

func TestLoginSession_Cookie(t *testing.T) {
	s := &loginSession{
		user: &types.User{
			UserBaseInfo: types.UserBaseInfo{
				CompanyName: "Acme",
				Email:       optional.StringP("a@b.com"),
				ProfilePicURL: "pic",
			},
			IsAdminUser: optional.BoolP(true),
		},
		logger: testLogger,
	}
	cookieStr, err := s.cookie()
	assert.NoError(t, err)
	assert.NotEmpty(t, cookieStr)
}

func TestLoginSession_Success_NoTokenData(t *testing.T) {
	// success() panics or errors without user and tokenData. Cover the
	// path that returns if token fields are set manually.
	s := &loginSession{
		namespace: "ns",
		login:     &types.UserLogin{LoginName: "u", LoginType: types.LoginTypeUsername},
		user: &types.User{
			Model:       types.Model{ID: types.UUIDToID(newUUID())},
			UserBaseInfo: types.UserBaseInfo{LoginName: "u"},
		},
		tokenData: &utils.UserTokenData{Token: "k"},
		logger:    testLogger,
	}
	result, err := s.success()
	assert.NoError(t, err)
	if assert.NotNil(t, result) {
		assert.Equal(t, "k", result.APIKey)
	}
}

func TestLoginSession_Result_NoRedirect(t *testing.T) {
	// Without tokenData, setNewUserToken fails due to missing headscale auth.
	// We set tokenData so the path to success() is taken directly.
	s := &loginSession{
		namespace: "ns",
		login:     &types.UserLogin{LoginName: "u", LoginType: types.LoginTypeUsername},
		user:      &types.User{UserBaseInfo: types.UserBaseInfo{LoginName: "u"}},
		tokenData: &utils.UserTokenData{Token: "k"},
		logger:    testLogger,
	}
	ls, redirect, err := s.result()
	assert.NoError(t, err)
	assert.NotNil(t, ls)
	assert.Nil(t, redirect)
}

func TestLoginSession_Result_WithRedirect(t *testing.T) {
	redirectURL := "http://example.com/next"
	s := &loginSession{
		namespace:   "ns",
		login:       &types.UserLogin{LoginName: "u", LoginType: types.LoginTypeUsername},
		user:        &types.User{UserBaseInfo: types.UserBaseInfo{LoginName: "u"}},
		tokenData:   &utils.UserTokenData{Token: "k"},
		redirectURL: &redirectURL,
		logger:      testLogger,
	}
	_, redirect, err := s.result()
	assert.NoError(t, err)
	if assert.NotNil(t, redirect) {
		assert.Equal(t, redirectURL, *redirect.EncodedRedirectURL)
	}
}

func TestLoginCookie_toCookie(t *testing.T) {
	c := loginCookie{
		IsAdminUser: true,
		Email:       "a@b.com",
	}
	s, err := c.toCookie()
	assert.NoError(t, err)
	assert.NotEmpty(t, s)
}

func TestSuccess_UserFields(t *testing.T) {
	// Sanity check: building models from types.User works.
	u := &types.User{
		UserBaseInfo: types.UserBaseInfo{LoginName: "u"},
		IsAdminUser:  optional.BoolP(true),
		IsSysAdmin:   optional.BoolP(true),
	}
	m := u.ToModel()
	assert.NotNil(t, m)
	_ = models.User{}.Logins
}

// newUUID helper to avoid importing the uuid package in many tests.
func newUUID() (uid [16]byte) { copy(uid[:], []byte{1}); return }
