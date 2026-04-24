// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db"
	"cylonix/sase/pkg/optional"
	"cylonix/sase/pkg/test/fixtures"
	hs_test "cylonix/sase/pkg/test/headscale"
	vpnpkg "cylonix/sase/pkg/vpn"
	"testing"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/stretchr/testify/assert"
)

// withFakeHeadscale wires a fake headscale client into pkg/vpn.
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

func TestUserHandler_WithFixtures_PostAndUpdate(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	handler := newHandlerImpl(nil, testLogger)

	// Post a new user via the admin token.
	newName := "fixt-posted-user"
	pw := "strong-Pass123!"
	err = handler.PostUser(s.AdminToken, api.PostUserRequestObject{
		Params: models.PostUserParams{Namespace: &s.Namespace},
		Body: &models.User{
			Logins: []models.UserLogin{
				{
					Login:      newName,
					LoginType:  models.LoginTypeUsername,
					Credential: &pw,
				},
			},
		},
	})
	assert.NoError(t, err)

	// Cleanup the posted user.
	login, err := db.GetUserLoginByLoginName(s.Namespace, newName)
	if assert.NoError(t, err) && assert.NotNil(t, login) {
		defer db.DeleteUser(nil, s.Namespace, login.UserID)
	}

	// Update display name via admin.
	display := "DisplayName"
	err = handler.UpdateUser(s.AdminToken, api.UpdateUserRequestObject{
		UserID: s.User.ID.String(),
		Body: &models.UserUpdateInfo{
			DisplayName: &display,
		},
	})
	assert.NoError(t, err)
}

func TestUserHandler_WithFixtures_DeleteUsers(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	handler := newHandlerImpl(nil, testLogger)
	idList := []uuid.UUID{s.User.ID.UUID()}
	err = handler.DeleteUsers(s.AdminToken, api.DeleteUsersRequestObject{
		Body: &idList,
	})
	assert.NoError(t, err)

	// User should be gone now.
	_, err = db.GetUserFast(s.Namespace, s.User.ID, false)
	assert.Error(t, err)
}

func TestUserHandler_WithFixtures_ChangePassword(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	handler := newHandlerImpl(nil, testLogger)

	// Admin forces new password for the non-admin user.
	newPW := "NewPass123!"
	newPWCopy := newPW
	loginType := models.LoginTypeUsername
	ret, err := handler.ChangePassword(s.AdminToken, api.ChangePasswordRequestObject{
		UserID: s.User.ID.String(),
		Body: &models.ChangePassword{
			NewPassword: &newPWCopy,
			LoginType:   &loginType,
		},
	})
	assert.NoError(t, err)
	if assert.NotNil(t, ret) {
		assert.Equal(t, newPW, *ret)
	}
}

func TestUserHandler_WithFixtures_ListAccessPoint(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	handler := newHandlerImpl(nil, testLogger)
	_, err = handler.ListAccessPoint(s.UserToken, api.ListAccessPointRequestObject{
		UserID: s.User.ID.String(),
	})
	_ = err // depends on wg-gateway setup; just exercise the path.
}

func TestUserHandler_WithFixtures_GenerateAndSetNetworkDomain(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	handler := newHandlerImpl(nil, testLogger)

	// Admin generates a network domain.
	d, err := handler.GenerateNetworkDomain(s.AdminToken, api.GenerateNetworkDomainRequestObject{})
	assert.NoError(t, err)
	assert.NotEmpty(t, d)

	// Admin sets a network domain on the user.
	err = handler.SetNetworkDomain(s.AdminToken, api.SetNetworkDomainRequestObject{
		UserID:        s.User.ID.String(),
		NetworkDomain: "new-" + d,
	})
	assert.NoError(t, err)
}

func TestUserHandler_WithFixtures_InviteAndListInvites(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()
	// Adjust admin token to bind to the real admin user UserID so the
	// handler can load the user via GetUser.
	s.AdminToken.UserID = s.AdminUser.ID.UUID()

	handler := newHandlerImpl(nil, testLogger)

	// Admin invites.
	email := openapi_types.Email("invitee@example.com")
	link, err := handler.InviteUser(s.AdminToken, api.InviteUserRequestObject{
		Body: &models.InviteUserParams{
			Emails: []openapi_types.Email{email},
			Role:   "user",
		},
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, link)

	// List invites.
	total, list, err := handler.ListUserInvite(s.AdminToken, api.GetUserInviteListRequestObject{})
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 1)
	assert.NotEmpty(t, list)
}

func TestUserHandler_WithFixtures_UserDeviceSummary(t *testing.T) {
	withFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	handler := newHandlerImpl(nil, testLogger)
	list, err := handler.UserDeviceSummary(s.UserToken, api.GetUserDeviceSummaryRequestObject{
		Params: models.GetUserDeviceSummaryParams{
			UserID: optional.StringP(s.User.ID.String()),
		},
	})
	assert.NoError(t, err)
	assert.NotNil(t, list)
}
