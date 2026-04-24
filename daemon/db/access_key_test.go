// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestAccessKey_CRUD(t *testing.T) {
	namespace := "test-access-key-ns"
	userID := types.UserID(uuid.New())
	note := "note"
	scope := []string{"scope1"}
	exp := time.Now().Add(time.Hour).Unix()

	// Create
	key, err := CreateAccessKey(namespace, userID, "u", &note, &scope, &exp)
	if !assert.NoError(t, err) || !assert.NotNil(t, key) {
		return
	}
	defer DeleteAccessKey(namespace, key.ID.String())

	// Get
	got, err := GetAccessKey(namespace, key.ID.String())
	assert.NoError(t, err)
	assert.Equal(t, key.ID, got.ID)

	// Unknown key.
	_, err = GetAccessKey(namespace, uuid.New().String())
	assert.Error(t, err)

	// CheckAccessKey (uses ID here since the impl uses key ID as the etcd key)
	uid, sc, err := CheckAccessKey(namespace, key.ID.String())
	assert.NoError(t, err)
	assert.Equal(t, userID, *uid)
	assert.Equal(t, []string{"scope1"}, *sc)

	// Different namespace -> invalid.
	_, _, err = CheckAccessKey("other", key.ID.String())
	assert.Error(t, err)

	// UpdateAccessKeyAccessAt.
	assert.NoError(t, UpdateAccessKeyAccessAt(namespace, key))

	// List.
	total, m, err := ListAccessKey(namespace, &userID, nil, nil, nil, nil, nil, nil, nil)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, 1)
	assert.NotNil(t, m)

	// Delete
	assert.NoError(t, DeleteAccessKey(namespace, key.ID.String()))
	_, err = GetAccessKey(namespace, key.ID.String())
	assert.Error(t, err)

	// Delete bad ID.
	assert.Error(t, DeleteAccessKey(namespace, "not-a-uuid"))
}

func TestCheckAccessKey_Expired(t *testing.T) {
	namespace := "test-access-key-expired"
	userID := types.UserID(uuid.New())
	past := time.Now().Add(-time.Hour).Unix()
	key, err := CreateAccessKey(namespace, userID, "u", nil, nil, &past)
	if !assert.NoError(t, err) {
		return
	}
	defer DeleteAccessKey(namespace, key.ID.String())

	_, _, err = CheckAccessKey(namespace, key.ID.String())
	assert.ErrorIs(t, err, ErrAccessKeyInvalid)
}

func TestCheckAccessKey_Invalid(t *testing.T) {
	_, _, err := CheckAccessKey("ns", "not-found-key")
	assert.Error(t, err)
}
