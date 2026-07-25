// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db_test

import (
	"testing"

	. "cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	dbt "cylonix/sase/pkg/test/db"

	"github.com/stretchr/testify/assert"
)

// TestGetUserLoginByIdpID verifies the stable-identity lookup used by the
// oauth login path: a login must be found by its idp_id regardless of the
// login_name (which is derived from the mutable email claim), and when
// duplicates share an idp_id the OLDEST row (the original identity) wins.
func TestGetUserLoginByIdpID(t *testing.T) {
	namespace := "test-login-idp-namespace"
	idpID := "custom-oidc-test-provider-sub123"

	user, err := dbt.CreateUserForTest(namespace, "251")
	if !assert.Nil(t, err) || !assert.NotNil(t, user) {
		return
	}
	userID := user.ID
	defer func() {
		assert.Nil(t, DeleteUser(nil, namespace, userID))
	}()

	dupUser, err := dbt.CreateUserForTest(namespace, "252")
	if !assert.Nil(t, err) || !assert.NotNil(t, dupUser) {
		return
	}
	dupUserID := dupUser.ID
	defer func() {
		assert.Nil(t, DeleteUser(nil, namespace, dupUserID))
	}()

	// Empty idp_id must not match anything.
	_, err = GetUserLoginByIdpID(namespace, "")
	assert.ErrorIs(t, err, ErrUserLoginNotExists)

	_, err = GetUserLoginByIdpID(namespace, idpID)
	assert.ErrorIs(t, err, ErrUserLoginNotExists)

	// Original login keyed by email.
	original := &types.UserLogin{
		LoginName: "idp-user@example.com",
		LoginType: types.LoginTypeCustomOIDC,
		UserID:    userID,
		Namespace: namespace,
		IdpID:     idpID,
		Email:     "idp-user@example.com",
	}
	assert.Nil(t, CreateUserLogin(original))

	got, err := GetUserLoginByIdpID(namespace, idpID)
	if assert.Nil(t, err) && assert.NotNil(t, got) {
		assert.Equal(t, original.LoginName, got.LoginName)
		assert.Equal(t, userID, got.UserID)
	}

	// A newer duplicate (pseudo login_name minted when the email claim went
	// missing) must NOT shadow the original.
	dup := &types.UserLogin{
		LoginName: "850487c5d437@custom-oidc-test-provider",
		LoginType: types.LoginTypeCustomOIDC,
		UserID:    dupUserID,
		Namespace: namespace,
		IdpID:     idpID,
	}
	assert.Nil(t, CreateUserLogin(dup))

	got, err = GetUserLoginByIdpID(namespace, idpID)
	if assert.Nil(t, err) && assert.NotNil(t, got) {
		assert.Equal(t, original.LoginName, got.LoginName)
		assert.Equal(t, userID, got.UserID)
	}
}
