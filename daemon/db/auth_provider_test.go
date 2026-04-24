// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeAuthProviderDomain(t *testing.T) {
	assert.Equal(t, "example.com", normalizeAuthProviderDomain("  Example.COM  "))
}

func TestAuthProvider_CRUD(t *testing.T) {
	namespace := "test-auth-provider-ns"

	// Missing namespace/domain -> bad params.
	err := CreateAuthProvider(&types.AuthProvider{})
	assert.ErrorIs(t, err, ErrBadParams)

	ap := &types.AuthProvider{
		Namespace:    namespace,
		Domain:       "Example.COM",
		IssuerURL:    "https://example.com/oidc",
		ClientID:     "cid",
		ClientSecret: "cs",
		AdminEmail:   "admin@example.com",
	}
	assert.NoError(t, CreateAuthProvider(ap))

	// Creating again -> exists error.
	assert.ErrorIs(t, CreateAuthProvider(ap), ErrAuthProviderExists)

	// GetAuthProviderByDomain.
	got, err := GetAuthProviderByDomain(namespace, "example.com")
	assert.NoError(t, err)
	assert.Equal(t, ap.ID, got.ID)

	// Wrong namespace -> mismatch.
	_, err = GetAuthProviderByDomain("other", "example.com")
	assert.Error(t, err)

	// Unknown domain -> not exists.
	_, err = GetAuthProviderByDomain(namespace, "no-such.com")
	assert.ErrorIs(t, err, ErrAuthProviderNotExists)

	// GetAuthProviderByID.
	got, err = GetAuthProviderByID(namespace, ap.ID)
	assert.NoError(t, err)
	assert.Equal(t, "example.com", got.Domain)

	// UpdateAuthProvider.
	assert.ErrorIs(t, UpdateAuthProvider(types.NilID, ap), ErrBadParams)
	updated := &types.AuthProvider{
		Model:      types.Model{ID: ap.ID},
		ClientID:   "new-cid",
		Provider:   "new-provider",
	}
	assert.NoError(t, UpdateAuthProvider(ap.ID, updated))

	// List.
	total, list, err := ListAuthProviders(namespace, nil, nil, nil, nil, nil, nil)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 1)
	assert.NotEmpty(t, list)

	// Delete.
	assert.NoError(t, DeleteAuthProviders(namespace, []types.ID{ap.ID}))
	_, err = GetAuthProviderByID(namespace, ap.ID)
	assert.ErrorIs(t, err, ErrAuthProviderNotExists)
}

func TestGetLoginsByLoginNameLike(t *testing.T) {
	// Empty login name -> empty result.
	out, err := GetLoginsByLoginNameLike(nil, "")
	assert.NoError(t, err)
	assert.Empty(t, out)

	// Unmatched -> empty.
	ns := "no-such-ns"
	out, err = GetLoginsByLoginNameLike(&ns, "unknown")
	assert.NoError(t, err)
	assert.Empty(t, out)
}
