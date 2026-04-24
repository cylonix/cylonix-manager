// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"cylonix/sase/pkg/test/fixtures"
	hs_test "cylonix/sase/pkg/test/headscale"
	vpnpkg "cylonix/sase/pkg/vpn"
	"testing"

	"github.com/cylonix/utils"
	"github.com/stretchr/testify/assert"
)

func withFakeHeadscale(t *testing.T) *hs_test.Client {
	t.Helper()
	fake := hs_test.New()
	vpnpkg.SetHeadscaleForTest(true)
	vpnpkg.SetHsClient(fake)
	t.Cleanup(func() {
		vpnpkg.SetHeadscaleForTest(false)
		vpnpkg.SetHsClient(nil)
	})
	return fake
}

func TestNewLoginSession_WithFixtures(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	// Valid tenant, login by username: session is built successfully.
	login := &types.UserLogin{
		Namespace: s.Namespace,
		LoginName: s.Login.LoginName,
		LoginType: types.LoginTypeUsername,
	}
	session, state, err := newLoginSession(s.Namespace, nil, login, "", "", testLogger)
	assert.NoError(t, err)
	assert.Nil(t, state)
	if assert.NotNil(t, session) {
		assert.Equal(t, s.Namespace, session.namespace)
	}
}

func TestLoginSession_Result_FullFlow(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	login := &types.UserLogin{
		Namespace: s.Namespace,
		LoginName: s.Login.LoginName,
		LoginType: types.LoginTypeUsername,
	}
	session, _, err := newLoginSession(s.Namespace, nil, login, "", "", testLogger)
	if !assert.NoError(t, err) {
		return
	}

	// result() ends up calling setNewUserToken which calls vpn.CreateApiKey.
	// With fake headscale, this succeeds.
	ls, redirect, err := session.result()
	assert.NoError(t, err)
	assert.NotNil(t, ls)
	assert.Nil(t, redirect)
}

func TestLoginSuccessFromUserToken_FullFlow(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	// Build a token that matches the seeded user login.
	tok := &utils.UserTokenData{
		Token:     "test",
		Namespace: s.Namespace,
		UserID:    s.User.ID.UUID(),
		LoginType: string(types.LoginTypeUsername),
		VpnApiKey: "reuse-key",
	}
	ls, _, state, err := loginSuccessFromUserToken(tok, true, nil, "", "", testLogger)
	assert.NoError(t, err)
	assert.Nil(t, state)
	if assert.NotNil(t, ls) {
		assert.Equal(t, "test", ls.APIKey)
	}
}

func TestOauthLogins_WithFixtures(t *testing.T) {
	withFakeHeadscale(t)
	h := newHandlerImpl(testLogger)
	list, err := h.OauthLogins()
	assert.NoError(t, err)
	_ = list
}

func TestOauthProviderToLoginType_Comprehensive(t *testing.T) {
	cases := []struct {
		in  string
		out types.LoginType
	}{
		{"google", types.LoginTypeGoogle},
		{"apple", types.LoginTypeApple},
		{"microsoft", types.LoginTypeMicrosoft},
		{"github", types.LoginTypeGithub},
		{"wechat", types.LoginTypeWeChat},
		{"custom-oidc-foo", types.LoginTypeCustomOIDC},
		{"unrecognized", types.LoginTypeUnknown},
	}
	for _, c := range cases {
		assert.Equal(t, c.out, oauthProviderToLoginType(c.in), c.in)
	}
}

// Additional branches in handler_impl.AddLogin exercised through a real user.
func TestAddLogin_Impl_WithFixtures(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(testLogger)

	// Missing body -> bad params.
	_ = s
	s.UserToken.UserID = s.User.ID.UUID() // ensure token matches user
	err = h.AddLogin(s.UserToken, api.AddLoginRequestObject{})
	assert.Error(t, err)
}

var _ = optional.StringP
