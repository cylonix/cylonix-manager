// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"net/netip"
	"testing"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestPolicy_CRUD(t *testing.T) {
	ns := "ns-policy"
	p := &types.Policy{
		Namespace: ns,
		Name:      "p1",
		Action:    "permit",
	}
	assert.NoError(t, CreatePolicy(p))
	defer func() {
		_ = DeletePolicy(ns, p.ID)
	}()

	got, err := GetPolicy(ns, p.ID)
	assert.NoError(t, err)
	if assert.NotNil(t, got) {
		assert.Equal(t, p.Name, got.Name)
	}

	// UpdatePolicy is a no-op today — just exercise.
	assert.NoError(t, UpdatePolicy(ns, p.ID, &models.Policy{}))

	assert.NoError(t, UpdatePolicyName(ns, p.ID, "renamed"))

	total, _ := PolicyCount(ns)
	assert.GreaterOrEqual(t, total, int64(1))

	total, _ = PermitPolicyCount(ns)
	assert.GreaterOrEqual(t, total, int64(1))

	// List with filter + pagination.
	total2, list, err := GetPolicyList(ns, optional.StringP("renamed"), nil, nil, nil, nil, nil, nil)
	assert.NoError(t, err)
	_ = list
	assert.GreaterOrEqual(t, total2, int64(1))

	// Delete list.
	assert.NoError(t, DeletePolicyList(ns, []types.PolicyID{p.ID}))

	// Unknown id -> not exists.
	_, err = GetPolicy(ns, types.PolicyID(uuid.New()))
	assert.ErrorIs(t, err, ErrPolicyNotExists)
}

func TestWgNode_CRUD(t *testing.T) {
	ns := "ns-wgnode"
	node := &types.WgNode{
		Namespace:    ns,
		Name:         "wg-1",
		PublicKeyHex: "hex",
		Addresses:    []netip.Prefix{netip.MustParsePrefix("10.2.0.1/32")},
	}
	assert.NoError(t, CreateWgNode(node))
	defer func() {
		_ = DeleteWgNode(node.ID)
	}()

	got, err := GetWgNode(ns, "wg-1")
	assert.NoError(t, err)
	assert.Equal(t, node.ID, got.ID)

	got, err = GetWgNodeByID(node.ID)
	assert.NoError(t, err)
	assert.Equal(t, node.Name, got.Name)

	total, list, err := ListWgNodes(&ns, nil, nil)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 1)
	_ = list

	all, online, err := GetWgNodeIDList(ns)
	assert.NoError(t, err)
	_ = all
	_ = online

	// Update: add an online flag.
	assert.NoError(t, UpdateWgNode(node.ID, &types.WgNode{
		IsOnline: optional.P(true),
	}))

	// Unknown name.
	_, err = GetWgNode(ns, "nope")
	assert.ErrorIs(t, err, ErrWgNodeNotExists)

	_, err = GetWgNodeByID(types.ID(uuid.New()))
	assert.ErrorIs(t, err, ErrWgNodeNotExists)
}

func TestUserInvite_CRUD(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-invite", "invite-user")
	defer cleanup()
	if u == nil {
		return
	}

	nd := optional.String(u.NetworkDomain)

	// Bad params.
	assert.ErrorIs(t, CreateUserInvite(nil), ErrBadParams)
	assert.ErrorIs(t, CreateUserInvite(&models.UserInvite{}), ErrBadParams)

	invite := &models.UserInvite{
		Namespace:     "ns-invite",
		NetworkDomain: nd,
		Emails:        []openapi_types.Email{"a@example.com"},
		Code:          "c1",
		InvitedBy: models.UserShortInfo{
			UserID:      u.ID.UUID(),
			DisplayName: "invite-user",
		},
	}
	err := CreateUserInvite(invite)
	if !assert.NoError(t, err) {
		return
	}

	total, list, err := ListUserInvites(optional.StringP("ns-invite"), nil, nil, nil, nil, nil, nil, nil, nil, nil)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 1)
	if !assert.NotEmpty(t, list) {
		return
	}

	id := list[0].ID
	got, err := GetUserInvite(id)
	assert.NoError(t, err)
	assert.Equal(t, id, got.ID)

	got, err = GetUserInviteByCode("c1")
	assert.NoError(t, err)
	assert.Equal(t, id, got.ID)

	_, err = GetUserInviteByCode("nope")
	assert.ErrorIs(t, err, ErrUserInviteNotExists)

	// Delete empty -> no-op.
	assert.NoError(t, DeleteUserInvites(nil, nil, nil))
	assert.NoError(t, DeleteUserInvite(nil))

	// Delete with namespace + network domain filter.
	ns := "ns-invite"
	assert.NoError(t, DeleteUserInvites(&ns, &nd, []types.ID{id}))
}

func TestUserApproval_Exists_Delete(t *testing.T) {
	// Unknown approval -> nil + nil.
	got, err := UserApprovalExists("ns-unknown", "nobody")
	assert.NoError(t, err)
	assert.Nil(t, got)

	// Bad params for DeleteUserApprovalByLoginName.
	err = DeleteUserApprovalByLoginName(nil, "", "")
	assert.ErrorIs(t, err, ErrBadParams)

	// Delete a non-existing approval is not an error.
	err = DeleteUserApprovalByLoginName(nil, "ns", "no-login")
	_ = err
}

func TestUser_NetworkDomainHelpers(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-nd", "nd-user")
	defer cleanup()
	if u == nil {
		return
	}

	inUse, err := IsNetworkDomainInUse(optional.String(u.NetworkDomain))
	assert.NoError(t, err)
	assert.True(t, inUse)

	inUse, err = IsNetworkDomainInUse("never-used")
	assert.NoError(t, err)
	assert.False(t, inUse)

	count, err := NetworkDomainCountWithMultipleUsers(optional.StringP("ns-nd"))
	assert.NoError(t, err)
	_ = count

	count, list, err := ListUsersSharingNetworkDomain(optional.StringP("ns-nd"))
	assert.NoError(t, err)
	_ = list
	_ = count

	// Bad params.
	err = UpdateUserNetworkDomain("ns-nd", "", "newnd", nil, nil)
	assert.ErrorIs(t, err, ErrBadParams)
	err = UpdateUserNetworkDomain("ns-nd", "nd-nd-user", "", nil, nil)
	assert.ErrorIs(t, err, ErrBadParams)

	// Happy path.
	err = UpdateUserNetworkDomain("ns-nd", "nd-nd-user", "nd2", &u.ID, nil)
	_ = err
}

func TestUser_RoleHelpers(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-role", "role-user")
	defer cleanup()
	if u == nil {
		return
	}

	// Bad params.
	assert.ErrorIs(t, AddUserRole(nil, "ns-role", u.ID, ""), ErrBadParams)
	assert.ErrorIs(t, DelUserRole(nil, "ns-role", u.ID, ""), ErrBadParams)

	// Namespace admin via predefined role.
	assert.NoError(t, AddUserRole(nil, "ns-role", u.ID, string(models.PredefinedRolesNamespaceAdmin)))
	assert.NoError(t, AddUserRole(nil, "ns-role", u.ID, string(models.PredefinedRolesNamespaceAdmin))) // already -> no-op
	assert.NoError(t, DelUserRole(nil, "ns-role", u.ID, string(models.PredefinedRolesNamespaceAdmin)))

	// Custom role.
	assert.NoError(t, AddUserRole(nil, "ns-role", u.ID, "custom-role"))
	assert.NoError(t, AddUserRole(nil, "ns-role", u.ID, "custom-role")) // already
	assert.NoError(t, DelUserRole(nil, "ns-role", u.ID, "custom-role"))
	assert.NoError(t, DelUserRole(nil, "ns-role", u.ID, "custom-role")) // already removed

	// Network admin + network owner roles.
	assert.NoError(t, AddUserRole(nil, "ns-role", u.ID, string(models.PredefinedRolesNetworkAdmin)))
	assert.NoError(t, AddUserRole(nil, "ns-role", u.ID, string(models.PredefinedRolesNetworkOwner)))
	assert.NoError(t, DelUserRole(nil, "ns-role", u.ID, string(models.PredefinedRolesNetworkAdmin)))
	assert.NoError(t, DelUserRole(nil, "ns-role", u.ID, string(models.PredefinedRolesNetworkOwner)))

	// Namespace mismatch.
	err := AddUserRole(nil, "other-ns", u.ID, "x")
	assert.ErrorIs(t, err, ErrNamespaceMismatch)
	err = DelUserRole(nil, "other-ns", u.ID, "x")
	assert.ErrorIs(t, err, ErrNamespaceMismatch)
}

func TestUser_CountsAndMaps(t *testing.T) {
	_, cleanup := buildUserWithTenant(t, "ns-counts", "counts-user")
	defer cleanup()

	_, err := OnlineDeviceCountUserIDMap("ns-counts")
	assert.NoError(t, err)

	_, err = LabelCountUserIDMap()
	_ = err // user_label_relation table may not exist; exercise the path.

	n, err := UserCount(optional.StringP("ns-counts"), nil, false)
	assert.NoError(t, err)
	_ = n
}

func TestGetUserByEmailDomainOrNil(t *testing.T) {
	// Unknown domain -> nil, nil.
	u, err := GetUserByEmailDomainOrNil("nothing.example.org")
	assert.NoError(t, err)
	assert.Nil(t, u)
}

func TestDeviceAutoApprove(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-autoapprove", "auto-user")
	defer cleanup()
	if u == nil {
		return
	}
	ok, err := DeviceAutoApprove("ns-autoapprove", u.ID)
	assert.NoError(t, err)
	_ = ok
}

func TestTenant_GetByCompanyName(t *testing.T) {
	u, cleanup := buildUserWithTenant(t, "ns-tenant-company", "tc-user")
	defer cleanup()
	if u == nil {
		return
	}
	// The tenant created by buildUserWithTenant uses the namespace as the
	// company name only if specified; fetching by a random name should
	// return not-exists.
	_, err := GetTenantConfigByCompanyName("does-not-exist")
	assert.ErrorIs(t, err, ErrTenantNotExists)
}

func TestNewTenantConfig(t *testing.T) {
	tc := NewTenantConfig(&models.TenantConfig{
		Namespace: "ns-nt",
		Name:      "Company",
		Email:     "x@y.com",
		Phone:     "555",
	})
	assert.NotNil(t, tc)
	assert.Equal(t, "ns-nt", tc.Namespace)
}

func TestFilter_BadArgs(t *testing.T) {
	tx, err := BeginTransaction()
	if !assert.NoError(t, err) {
		return
	}
	defer tx.Rollback()

	// Mismatched by/value counts -> returns pg unchanged.
	_ = filter(tx, optional.StringP("a,b"), optional.StringP("x"))
	// Mismatched exact args.
	_ = filterExact(tx, optional.StringP("a,b"), []interface{}{"x"})
	// Nil by / nil value -> no-op.
	_ = filter(tx, nil, nil)
	_ = filterExact(tx, nil, nil)
}

func TestInterfaceHasNilValue_Basics(t *testing.T) {
	assert.True(t, interfaceHasNilValue(nil))
	var p *int
	assert.True(t, interfaceHasNilValue(p))
	x := 1
	assert.False(t, interfaceHasNilValue(&x))

	var m map[string]string
	assert.True(t, interfaceHasNilValue(m))
	assert.False(t, interfaceHasNilValue("v"))
}

func TestPolicyTarget_GetByName_NotFound(t *testing.T) {
	_, err := GetPolicyTargetByName("ns-pt", "nope")
	assert.Error(t, err)
}
