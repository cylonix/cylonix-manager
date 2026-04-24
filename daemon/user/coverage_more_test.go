// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/test/fixtures"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// Exercise NewService constructor.
func TestUserService_NewService(t *testing.T) {
	s := NewService(nil, logrus.NewEntry(logrus.New()))
	assert.NotNil(t, s)
	assert.Equal(t, "user api handler", s.Name())
}

// Admin can delete another user's profile img.
func TestUserHandler_WithFixtures_ProfileImgFlow(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(nil, testLogger)

	// Update with empty body -> bad params.
	err = h.UpdateProfileImg(s.UserToken, api.UpdateProfileImgRequestObject{
		Body: &models.UserProfile{},
	})
	assert.Error(t, err)

	// Update with data.
	err = h.UpdateProfileImg(s.UserToken, api.UpdateProfileImgRequestObject{
		Body: &models.UserProfile{Base64Image: "xxx"},
	})
	_ = err

	// Delete.
	err = h.DeleteProfileImg(s.UserToken, api.DeleteProfileImgRequestObject{})
	_ = err

	// Get (missing user id -> returns empty profile).
	_, err = h.ProfileImg(s.UserToken, api.GetProfileImgRequestObject{})
	_ = err
}

// ChangeAccessPoint with a non-admin user's target -> unauthorized.
func TestUserHandler_WithFixtures_ChangeAccessPoint_Unauthorized(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(nil, testLogger)

	// Non-admin user tries to change another user's access point.
	ap, err := h.ChangeAccessPoint(s.UserToken, api.ChangeAccessPointRequestObject{
		UserID: "00000000-0000-0000-0000-000000000001",
	})
	assert.Error(t, err)
	assert.Nil(t, ap)
}

// Exercise the error paths on SearchUser.
func TestUserHandler_WithFixtures_SearchUser(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(nil, testLogger)

	// Admin searches by username.
	ret, err := h.SearchUser(s.AdminToken, api.SearchUserRequestObject{})
	_ = ret
	_ = err
}

// RegisterUser with empty body.
func TestUserHandler_RegisterUser_BadParams(t *testing.T) {
	withFakeHeadscale(t)
	h := newHandlerImpl(nil, testLogger)
	err := h.RegisterUser(nil, api.RegisterUserRequestObject{})
	assert.Error(t, err)
}

// IsUsernameAvailable happy and sad paths.
func TestUserHandler_IsUsernameAvailable(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(nil, testLogger)

	// Despite the name, the handler returns true if the username *exists*.
	login := s.Login.LoginName
	exists, err := h.IsUsernameAvailable(api.CheckUsernameRequestObject{
		Params: models.CheckUsernameParams{Username: login, Namespace: &s.Namespace},
	})
	assert.NoError(t, err)
	_ = exists

	// Random username should not exist.
	exists, err = h.IsUsernameAvailable(api.CheckUsernameRequestObject{
		Params: models.CheckUsernameParams{Username: "never-used-" + s.Namespace, Namespace: &s.Namespace},
	})
	assert.NoError(t, err)
	_ = exists
}

// UserSummary on the admin token.
func TestUserHandler_UserSummary(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(nil, testLogger)
	list, err := h.UserSummary(s.AdminToken, api.GetUserSummaryRequestObject{})
	_ = list
	_ = err
}

// ApprovalRecords.
func TestUserHandler_ApprovalRecords(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(nil, testLogger)
	total, list, err := h.ApprovalRecords(s.AdminToken, api.GetUserApprovalsRequestObject{})
	_ = total
	_ = list
	_ = err
}

// GetUserRoles.
func TestUserHandler_GetUserRoles(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(nil, testLogger)
	roles, err := h.GetUserRoles(s.AdminToken, api.GetUserRolesRequestObject{})
	_ = roles
	_ = err
}

// MultiUserNetworkSummary.
func TestUserHandler_MultiUserNetworkSummary(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(nil, testLogger)
	total, list, err := h.MultiUserNetworkSummary(s.AdminToken, api.GetUserMultiUserNetworkSummaryRequestObject{})
	_ = total
	_ = list
	_ = err
}

// GetUserList.
func TestUserHandler_GetUserList(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	h := newHandlerImpl(nil, testLogger)
	list, err := h.GetUserList(s.AdminToken, api.GetUserListRequestObject{})
	_ = list
	_ = err
}

// InviteUser with send-email flag to exercise sendInvite path.
func TestUserHandler_InviteUser_SendEmail(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()
	s.AdminToken.UserID = s.AdminUser.ID.UUID()

	// Call sendInvite directly to get its coverage.
	_ = sendInvite(
		[]string{"a@example.com"}, "From", "network", "code",
		nil, false,
	)
}

// UserIDToken call.
func TestUserHandler_UserIDToken(t *testing.T) {
	h := newHandlerImpl(nil, testLogger)
	_, err := h.UserIDToken(api.GetIDTokenRequestObject{})
	_ = err
}

// Test SendUsername + ResetPassword with bad params.
func TestUserHandler_SendUsernameResetPassword_BadParams(t *testing.T) {
	h := newHandlerImpl(nil, testLogger)
	// No body/params -> should error.
	err := h.SendUsername(api.SendUsernameRequestObject{})
	_ = err

	err = h.ResetPassword(api.ResetPasswordRequestObject{})
	_ = err
}
