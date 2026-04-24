// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

import (
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/cylonix/utils"
	"github.com/stretchr/testify/assert"
)

func TestSmsCodeLogin_InvalidCode(t *testing.T) {
	// Invalid code when no sms token set -> invalid sms code or similar.
	_, _, _, err := smsCodeLogin("ns", "5551234567", "000000", nil, "", "", testLogger)
	assert.Error(t, err)
}

func TestSmsCodeLogin_ValidCodeNoTenant(t *testing.T) {
	// Set code token so CheckSmsCode passes, then login fails because
	// tenant doesn't exist.
	phone := utils.New11DigitCode()
	code := utils.New6DigitCode()
	token := utils.NewSmsToken(phone)
	assert.NoError(t, token.Set("", code, false))

	_, _, _, err := smsCodeLogin("no-such-ns", phone, code, nil, "", "", testLogger)
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}

func TestNewLoginSession_TenantNotExists(t *testing.T) {
	login := &types.UserLogin{Namespace: "nope", LoginName: "x"}
	_, _, err := newLoginSession("nope", nil, login, "", "", testLogger)
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}

func TestNewLoginSession_WithInviteCode(t *testing.T) {
	// Need a tenant and an invite.
	namespace := "login-invite-ns"
	defer db.DeleteTenantConfigByNamespace(namespace)
	tier, err := db.CreateUserTier(&types.UserTier{
		Name:           "test-tier-for-invite",
		Description:    "test",
		MaxUserCount:   10,
		MaxDeviceCount: 10,
	})
	if !assert.NoError(t, err) {
		return
	}
	defer db.DeleteUserTierByName("test-tier-for-invite")

	uid, _ := types.NewID()
	err = db.NewTenant(&types.TenantConfig{
		Namespace:  namespace,
		UserTierID: &tier.ID,
		TenantSetting: types.TenantSetting{
			MaxUser:       10,
			MaxDevice:     10,
			NetworkDomain: "", // empty so invite-code fetch path runs
		},
	}, uid, "creator", namespace)
	assert.NoError(t, err)

	// Invalid invite code -> bad params.
	login := &types.UserLogin{Namespace: namespace, LoginName: "x"}
	_, _, err = newLoginSession(namespace, nil, login, "", "no-such-code", testLogger)
	assert.Error(t, err)
}

func TestLoginSuccessFromUserToken_NoLogin(t *testing.T) {
	// Token with no matching user login in db -> error.
	uid, _ := types.NewID()
	tok := &utils.UserTokenData{
		Token:     "x",
		Namespace: "ns-not-exists",
		UserID:    uid.UUID(),
		LoginType: string(types.LoginTypeUsername),
	}
	_, _, _, err := loginSuccessFromUserToken(tok, false, nil, "", "", testLogger)
	assert.Error(t, err)
}

func TestNewUserApproval(t *testing.T) {
	login := &types.UserLogin{Namespace: "ns", LoginName: "u", LoginType: types.LoginTypeUsername}
	ret := newUserApproval(login, []string{"role1"})
	assert.Equal(t, "ns", ret.Namespace)
	assert.Equal(t, "u", ret.Login.Login)
}

func TestLoginSession_SetForSessionDetails_NoSession(t *testing.T) {
	s := loginSession{logger: testLogger}
	assert.NoError(t, s.setForSessionDetails(nil))
}

func TestLoginService_Stop(t *testing.T) {
	s := NewService(testLogger)
	s.Stop() // should not panic
}

func TestAccessKeyLogin_InvalidNamespace(t *testing.T) {
	// Reasonably exercise the newAccessKeyLogin with namespace not in db.
	_, err := newAccessKeyLogin("never", "akey", nil, "", testLogger)
	assert.Error(t, err)
}
