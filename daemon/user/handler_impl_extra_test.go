// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	dbt "cylonix/sase/pkg/test/db"
	"testing"

	"github.com/cylonix/utils"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// TestSearchUser verifies SearchUser handler.
func TestSearchUser_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-search-user"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	// Unauthorized if no token.
	_, err = handler.SearchUser(nil, api.SearchUserRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Search with no matching user - may return ErrUserLoginNotExists
	// mapped to internal error depending on implementation. Just exercise.
	_, _ = handler.SearchUser(adminToken, api.SearchUserRequestObject{
		Params: models.SearchUserParams{Username: optional.StringP("does-not-exist")},
	})

	// Add a user and search it.
	username := "search-me"
	user, err := addUser(namespace, username)
	if assert.NoError(t, err) {
		defer db.DeleteUser(nil, namespace, user.ID)
		info, err := handler.SearchUser(adminToken, api.SearchUserRequestObject{
			Params: models.SearchUserParams{Username: &username},
		})
		assert.NoError(t, err)
		assert.NotNil(t, info)
	}

	// No params -> bad params or empty result.
	_, _ = handler.SearchUser(adminToken, api.SearchUserRequestObject{})
}

func TestIsUsernameAvailable_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-username-available"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	// Unused login: should return false (available).
	exists, err := handler.IsUsernameAvailable(api.CheckUsernameRequestObject{
		Params: models.CheckUsernameParams{
			Username:  "never-used-xyz",
			Namespace: &namespace,
		},
	})
	assert.NoError(t, err)
	assert.False(t, exists)

	// Add user with username then check.
	username := "already-exists"
	user, err := addUser(namespace, username)
	if assert.NoError(t, err) {
		defer db.DeleteUser(nil, namespace, user.ID)
		exists, err = handler.IsUsernameAvailable(api.CheckUsernameRequestObject{
			Params: models.CheckUsernameParams{
				Username:  username,
				Namespace: &namespace,
			},
		})
		assert.NoError(t, err)
		assert.True(t, exists)
	}

	// Default namespace when not specified.
	_, _ = handler.IsUsernameAvailable(api.CheckUsernameRequestObject{
		Params: models.CheckUsernameParams{Username: "x"},
	})
}

func TestSendUsername_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	// Missing params -> bad params error.
	err := handler.SendUsername(api.SendUsernameRequestObject{})
	assert.Error(t, err)
	err = handler.SendUsername(api.SendUsernameRequestObject{
		Params: models.SendUsernameParams{Email: optional.StringP("a@b"), Namespace: optional.StringP("ns")},
	})
	// User does not exist -> nil return (not an error).
	assert.NoError(t, err)
}

func TestMultiUserNetworkSummary_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	// Non-sysadmin token -> unauthorized.
	fakeToken := &utils.UserTokenData{Token: "fake-token"}
	_, _, err := handler.MultiUserNetworkSummary(fakeToken, api.GetUserMultiUserNetworkSummaryRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Sysadmin: succeeds with 0 results.
	sysToken := &utils.UserTokenData{Token: "sys", IsSysAdmin: true, Namespace: "anyns"}
	count, users, err := handler.MultiUserNetworkSummary(sysToken, api.GetUserMultiUserNetworkSummaryRequestObject{})
	assert.NoError(t, err)
	assert.Equal(t, 0, count)
	assert.NotNil(t, users)
}

func TestUserIDToken_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)

	// Non-existent token -> unauthorized.
	_, err := handler.UserIDToken(api.GetIDTokenRequestObject{Code: "no-such-token"})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Create a token bound to a real user and look it up.
	namespace := "ns-uit"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.NoError(t, err) {
		return
	}
	user, err := addUser(namespace, "uit-user")
	if !assert.NoError(t, err) {
		return
	}
	defer db.DeleteUser(nil, namespace, user.ID)

	tok := utils.NewOauthCodeToken(namespace)
	data := &utils.OauthCodeTokenData{
		Namespace: namespace,
		UserID:    user.ID.UUID(),
	}
	assert.NoError(t, tok.Create(data))

	got, err := handler.UserIDToken(api.GetIDTokenRequestObject{Code: tok.Token})
	assert.NoError(t, err)
	assert.NotNil(t, got)

	// Second lookup fails because UserIDToken deletes the token on success.
	_, err = handler.UserIDToken(api.GetIDTokenRequestObject{Code: tok.Token})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}

func TestGetUserRoles_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-get-roles"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	// Non-admin -> unauthorized.
	fakeToken := &utils.UserTokenData{Token: "fake", Namespace: namespace}
	_, err = handler.GetUserRoles(fakeToken, api.GetUserRolesRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Admin of regular namespace -> loads labels.
	_, err = handler.GetUserRoles(adminToken, api.GetUserRolesRequestObject{})
	assert.NoError(t, err)

	// Admin of sysadmin namespace with keycloak not provisioned -> empty list.
	sysAdminToken := &utils.UserTokenData{
		Token:       "sys",
		Namespace:   utils.SysAdminNamespace,
		IsAdminUser: true,
		IsSysAdmin:  true,
	}
	_, err = handler.GetUserRoles(sysAdminToken, api.GetUserRolesRequestObject{})
	assert.NoError(t, err)
}

func TestGenerateNetworkDomain_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	// Non-admin user token (not network admin) -> unauthorized after fetching user.
	namespace := "ns-gen-nd"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	// Admin path: succeeds.
	d, err := handler.GenerateNetworkDomain(adminToken, api.GenerateNetworkDomainRequestObject{
		Params: models.GenerateNetworkDomainParams{WantWordsBased: false},
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, d)

	d, err = handler.GenerateNetworkDomain(adminToken, api.GenerateNetworkDomainRequestObject{
		Params: models.GenerateNetworkDomainParams{WantWordsBased: true},
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, d)

	// nil token -> unauthorized.
	_, err = handler.GenerateNetworkDomain(nil, api.GenerateNetworkDomainRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}

func TestSetNetworkDomain_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-set-nd"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}

	user, err := addTestUser(namespace, "set-nd-user", false, true, false, nil)
	if !assert.NoError(t, err) {
		return
	}
	defer db.DeleteUser(nil, namespace, user.ID)

	// Admin: set new domain.
	err = handler.SetNetworkDomain(adminToken, api.SetNetworkDomainRequestObject{
		UserID:        user.ID.String(),
		NetworkDomain: "newdomain.test.org",
	})
	assert.NoError(t, err)

	// Empty domain -> bad params.
	err = handler.SetNetworkDomain(adminToken, api.SetNetworkDomainRequestObject{
		UserID:        user.ID.String(),
		NetworkDomain: "",
	})
	assert.Error(t, err)

	// Nil token -> unauthorized.
	err = handler.SetNetworkDomain(nil, api.SetNetworkDomainRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}

func TestInviteUser_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-invite-user"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}

	// Admin must exist as a real user in db.
	adminUser, err := addAdminUser(namespace)
	if !assert.NoError(t, err) {
		return
	}
	defer db.DeleteUser(nil, namespace, adminUser.ID)
	adminToken.UserID = adminUser.ID.UUID()

	// sysadmin cannot invite.
	sysToken := &utils.UserTokenData{Token: "s", IsSysAdmin: true, Namespace: utils.SysAdminNamespace}
	_, err = handler.InviteUser(sysToken, api.InviteUserRequestObject{Body: &models.InviteUserParams{}})
	assert.Error(t, err)

	// nil token -> unauthorized.
	_, err = handler.InviteUser(nil, api.InviteUserRequestObject{Body: &models.InviteUserParams{}})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Admin invites: succeeds (no email).
	link, err := handler.InviteUser(adminToken, api.InviteUserRequestObject{
		Body: &models.InviteUserParams{
			Emails: []openapi_types.Email{"a@b.com"},
			Role:   "user",
		},
	})
	assert.NoError(t, err)
	assert.NotEmpty(t, link)
}

func TestDeleteUserInvite_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-del-invite"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	// nil token -> unauthorized.
	err = handler.DeleteUserInvite(nil, api.DeleteUserInviteRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Empty body -> bad params.
	err = handler.DeleteUserInvite(adminToken, api.DeleteUserInviteRequestObject{})
	assert.Error(t, err)

	// Non-existent IDs -> silently succeeds (no-op).
	idList := []uuid.UUID{uuid.New()}
	err = handler.DeleteUserInvite(adminToken, api.DeleteUserInviteRequestObject{Body: &idList})
	assert.NoError(t, err)
}

func TestListUserInvite_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-list-invite"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	// nil token -> unauthorized.
	_, _, err = handler.ListUserInvite(nil, api.GetUserInviteListRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Admin path: empty list.
	total, list, err := handler.ListUserInvite(adminToken, api.GetUserInviteListRequestObject{})
	assert.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Empty(t, list)

	// Sys admin with different namespace filter.
	sysToken := &utils.UserTokenData{Token: "s", IsSysAdmin: true, Namespace: utils.SysAdminNamespace, IsAdminUser: true}
	_, _, err = handler.ListUserInvite(sysToken, api.GetUserInviteListRequestObject{})
	assert.NoError(t, err)
}

func TestGetUserInvite_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-get-invite"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	// nil token -> unauthorized.
	_, err = handler.GetUserInvite(nil, api.GetUserInviteRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Non-existent code -> bad params.
	_, err = handler.GetUserInvite(adminToken, api.GetUserInviteRequestObject{
		Params: models.GetUserInviteParams{InviteCode: "nope"},
	})
	assert.Error(t, err)
}

func TestUpdateUserInvite_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-update-invite"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	// nil token -> unauthorized.
	err = handler.UpdateUserInvite(nil, api.UpdateUserInviteRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Non-existent invite code -> bad params.
	err = handler.UpdateUserInvite(adminToken, api.UpdateUserInviteRequestObject{
		Params: models.UpdateUserInviteParams{InviteCode: "nope"},
	})
	assert.Error(t, err)
}

func TestSendUserInvite_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-send-invite"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	// nil token -> unauthorized.
	err = handler.SendUserInvite(nil, api.SendUserInviteRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	// Non-existent invite ID -> bad params.
	err = handler.SendUserInvite(adminToken, api.SendUserInviteRequestObject{ID: uuid.New()})
	assert.Error(t, err)
}

// Exercise ChangeAccessPoint branches.
func TestChangeAccessPoint_Impl(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-change-ap"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	user, err := addUser(namespace, "ap-user")
	if !assert.NoError(t, err) {
		return
	}
	defer db.DeleteUser(nil, namespace, user.ID)

	_, userToken := dbt.CreateTokenForTest(namespace, user.ID, "ap-user", false, nil)
	defer userToken.Delete()

	// Non-admin trying to change other user's ap -> unauthorized.
	_, err = handler.ChangeAccessPoint(userToken, api.ChangeAccessPointRequestObject{
		UserID: types.NilID.String(),
	})
	assert.Error(t, err)

	// Admin changing for specific user but bad format UserID -> bad params.
	_, err = handler.ChangeAccessPoint(adminToken, api.ChangeAccessPointRequestObject{
		UserID: "not-a-uuid",
	})
	assert.Error(t, err)
}

// TestUpdateUser_AdditionalBranches exercises more UpdateUser branches.
func TestUpdateUser_AdditionalBranches(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "ns-update-user-extra"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}

	// Missing body/invalid user ID.
	err = handler.UpdateUser(adminToken, api.UpdateUserRequestObject{
		UserID: "bad-uuid",
		Body:   &models.UserUpdateInfo{},
	})
	assert.Error(t, err)

	// User doesn't exist -> error.
	err = handler.UpdateUser(adminToken, api.UpdateUserRequestObject{
		UserID: uuid.New().String(),
		Body:   &models.UserUpdateInfo{},
	})
	assert.Error(t, err)
}
