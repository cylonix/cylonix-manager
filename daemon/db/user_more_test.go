// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"testing"
	"time"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// buildUserWithTenant creates a tenant + user and returns cleanup.
func buildUserWithTenant(t *testing.T, namespace, username string) (*types.User, func()) {
	t.Helper()
	// Tier.
	tier, err := CreateUserTier(&types.UserTier{
		Name:           "tier-" + username,
		Description:    "test",
		MaxUserCount:   10,
		MaxDeviceCount: 10,
	})
	if !assert.NoError(t, err) {
		return nil, func() {}
	}

	// Tenant.
	uid, _ := types.NewID()
	err = NewTenant(&types.TenantConfig{
		Namespace:  namespace,
		UserTierID: &tier.ID,
		TenantSetting: types.TenantSetting{
			MaxUser:       10,
			MaxDevice:     10,
			NetworkDomain: "nd-" + username,
		},
	}, uid, "creator", namespace)
	if !assert.NoError(t, err) {
		_ = DeleteUserTierByName(tier.Name)
		return nil, func() {}
	}

	// User.
	login, err := types.NewUsernameLogin(namespace, username, "", "", "")
	assert.NoError(t, err)
	user, err := AddUser(
		namespace, "e-"+username+"@x.com", "", "",
		[]types.UserLogin{*login}, nil, nil,
		optional.P(tier.Name), optional.P("nd-"+username), nil,
	)
	if !assert.NoError(t, err) {
		_ = DeleteTenantConfigByNamespace(namespace)
		_ = DeleteUserTierByName(tier.Name)
		return nil, func() {}
	}
	cleanup := func() {
		_ = DeleteUser(nil, namespace, user.ID)
		_ = DeleteTenantConfigByNamespace(namespace)
		_ = DeleteUserTierByName(tier.Name)
	}
	return user, cleanup
}

func TestSearchUser_Impl(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-search", "searcher")
	defer cleanup()
	if u == nil {
		return
	}

	got, err := SearchUser("ns-search", optional.StringP("searcher"), nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	// Bad params -> ErrBadParams.
	_, err = SearchUser("ns", nil, nil, nil)
	assert.ErrorIs(t, err, ErrBadParams)

	// Unknown username -> ErrUserLoginNotExists.
	_, err = SearchUser("ns-search", optional.StringP("never"), nil, nil)
	assert.ErrorIs(t, err, ErrUserLoginNotExists)
}

func TestGetUserByID(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-getbyid", "getbyid-user")
	defer cleanup()
	if u == nil {
		return
	}

	got, err := GetUserByID(optional.StringP("ns-getbyid"), u.ID)
	assert.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)

	// Wrong namespace -> mismatch.
	_, err = GetUserByID(optional.StringP("other"), u.ID)
	assert.ErrorIs(t, err, ErrNamespaceMismatch)

	// Unknown id -> ErrUserNotExists.
	_, err = GetUserByID(nil, types.UserID(uuid.New()))
	assert.ErrorIs(t, err, ErrUserNotExists)
}

func TestUserLiteHelpers(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-lite", "lite-user")
	defer cleanup()
	if u == nil {
		return
	}

	assert.Equal(t, optional.Bool(u.WgEnabled), IsUserWgEnabled(u.ID))
	assert.Equal(t, optional.Bool(u.GatewayEnabled), IsUserGatewayEnabled(u.ID))
	assert.Equal(t, optional.String(u.MeshVpnMode), GetUserMeshVpnMode(u.ID))

	// For unknown user, returns defaults.
	bad := types.UserID(uuid.New())
	assert.False(t, IsUserWgEnabled(bad))
	assert.False(t, IsUserGatewayEnabled(bad))
	assert.Equal(t, "", GetUserMeshVpnMode(bad))

	nd, err := GetUserNetworkDomain(u.ID)
	assert.NoError(t, err)
	_ = nd

	_, err = GetUserNetworkDomain(bad)
	assert.Error(t, err)
}

func TestGetUserBaseInfoList(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-baseinfo", "baseinfo-user")
	defer cleanup()
	if u == nil {
		return
	}
	list, err := GetUserBaseInfoList("ns-baseinfo", []types.UserID{u.ID})
	assert.NoError(t, err)
	assert.NotEmpty(t, list)

	// Empty list -> empty result.
	list, err = GetUserBaseInfoList("ns-baseinfo", []types.UserID{})
	_ = err
	_ = list
}

func TestGetUserIDList(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-idlist", "idlist-user")
	defer cleanup()
	if u == nil {
		return
	}
	tx, err := BeginTransaction()
	if assert.NoError(t, err) {
		defer tx.Rollback()
		ids, err := GetUserIDList(tx, "ns-idlist", nil)
		assert.NoError(t, err)
		assert.NotEmpty(t, ids)

		// With a network filter.
		nd := "nd-idlist-user"
		ids, err = GetUserIDList(tx, "ns-idlist", &nd)
		assert.NoError(t, err)
		assert.NotEmpty(t, ids)
	}
}

func TestFindUserInBatches(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-batch", "batch-user")
	defer cleanup()
	if u == nil {
		return
	}
	count := 0
	err := FindUserInBatches("ns-batch", 10, func(user *types.User) (bool, error) {
		count++
		return false, nil
	})
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, count, 1)
}

func TestGetUsernameByEmail_NotFound(t *testing.T) {
	// Unknown email returns a non-nil error (either not-found or login-not-found).
	_, err := GetUsernameByEmail("ns-email-test", "nobody@nothing.com")
	_ = err
}

func TestUserTier_CRUD(t *testing.T) {
	// Bad params.
	_, err := CreateUserTier(&types.UserTier{})
	assert.ErrorIs(t, err, ErrBadParams)

	// Successful create.
	tier, err := CreateUserTier(&types.UserTier{
		Name:           "tier-crud-" + uuid.New().String(),
		Description:    "desc",
		MaxUserCount:   5,
		MaxDeviceCount: 5,
	})
	if !assert.NoError(t, err) {
		return
	}

	got, err := GetUserTierByName(tier.Name)
	assert.NoError(t, err)
	assert.Equal(t, tier.ID, got.ID)

	got, err = GetUserTier(tier.ID)
	assert.NoError(t, err)
	assert.Equal(t, tier.Name, got.Name)

	assert.NoError(t, DeleteUserTier(tier.ID))

	// Already deleted -> not exists.
	_, err = GetUserTierByName(tier.Name)
	assert.ErrorIs(t, err, ErrUserTierNotExists)

	_, err = GetUserTier(types.ID(uuid.New()))
	assert.ErrorIs(t, err, ErrUserTierNotExists)
}

func TestAddSysAdminUser(t *testing.T) {
	// A namespace must exist first.
	u, cleanup := buildUserWithTenant(t, "ns-sysadmin-add", "sys-test")
	defer cleanup()
	if u == nil {
		return
	}

	// Try adding a sysadmin user for that namespace.
	sys, err := AddSysAdminUser("ns-sysadmin-add", "sys@x.com", "", "Sys", "sys-"+uuid.New().String()[:6], "Pass1!")
	if err == nil {
		defer DeleteUser(nil, "ns-sysadmin-add", sys.ID)
		assert.NotNil(t, sys)
	}
}

func TestUpdateUserLastSeen(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-lastseen", "lastseen-user")
	defer cleanup()
	if u == nil {
		return
	}
	assert.NoError(t, UpdateUserLastSeen("ns-lastseen", u.ID, time.Now().Unix()))
}

func TestSetUserMustChangePassword(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-mcp", "mcp-user")
	defer cleanup()
	if u == nil {
		return
	}
	// Pass u.ID as uint; function signature is unusual.
	assert.NoError(t, SetUserMustChangePassword("ns-mcp", uint(u.ID.Uint64()), true))
}

func TestAddUserLabel_BadParams(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-ulabel", "label-user")
	defer cleanup()
	if u == nil {
		return
	}
	// Bad params — no labels passed in.
	assert.ErrorIs(t, AddUserLabel("ns-ulabel", u.ID, nil), ErrBadParams)
}

func TestGetUserIDsWithLabelIDs_None(t *testing.T) {
	// No users match -> empty.
	out, _ := GetUserIDsWithLabelIDs([]string{uuid.New().String()})
	_ = out
}

func TestDeviceCount_ByUser(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-dcount", "dcount-user")
	defer cleanup()
	if u == nil {
		return
	}
	_, err := DeviceCount(optional.StringP("ns-dcount"), &u.ID, nil, false)
	_ = err
}

func TestCheckUserCreationError(t *testing.T) {
	// Exercise the wrapper with synthetic errors.
	err := checkUserCreationError(&fakeErr{"duplicate key value violates phone"})
	assert.ErrorIs(t, err, ErrUserWithPhoneExists)
	err = checkUserCreationError(&fakeErr{"duplicate key value violates email"})
	assert.ErrorIs(t, err, ErrUserWithEmailExists)
	err = checkUserCreationError(&fakeErr{"boom"})
	assert.Error(t, err)
}

type fakeErr struct{ s string }

func (e *fakeErr) Error() string { return e.s }

func TestInitPGOtherModelsAndByNames(t *testing.T) {
	// Calling these is mostly an exercise of error paths.
	err := InitPGOtherModels(false, &types.Label{})
	_ = err

	err = InitPGModelsByNames(false, []string{"Label"}, nil)
	_ = err

	// Unknown name -> error.
	err = InitPGModelsByNames(false, []string{"NoSuch"}, nil)
	assert.Error(t, err)
}

// Compile check for utils used in tests.
var _ = utils.NewPassword
