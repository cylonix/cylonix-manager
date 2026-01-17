// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	tu "cylonix/sase/pkg/test/user"
	"testing"

	"github.com/cylonix/utils"
	"github.com/stretchr/testify/assert"
)

func TestCheckUserOneTimeCode(t *testing.T) {
	namespace, username := "test-namespace", "test-user-name"
	code, email, phone := "123456", "fake@fake.com", "4087778888"

	su, err := CheckUserOneTimeCode(namespace, types.NilID, nil, nil, nil)
	if assert.NotNil(t, err) {
		assert.Nil(t, su)
		assert.ErrorIs(t, err, ErrInternalErr)
	}
	u, err := tu.New(namespace, username, phone)
	if !assert.Nil(t, err) || !assert.NotNil(t, u) {
		t.Fatalf("Failed to create new user: %v", err)
	}
	userID := u.ID
	defer tu.Delete(namespace, userID)
	userID = u.UserID
	su, err = CheckUserOneTimeCode(namespace, userID, nil, nil, nil)
	if assert.NotNil(t, err) {
		assert.Nil(t, su)
		assert.ErrorIs(t, err, ErrModelBadParameters)
	}
	su, err = CheckUserOneTimeCode(namespace, userID, &code, &email, nil)
	if assert.NotNil(t, err) {
		assert.Nil(t, su)
		assert.ErrorIs(t, err, ErrModelBadParameters)
	}
	su, err = CheckUserOneTimeCode(namespace, userID, &code, nil, &phone)
	if assert.NotNil(t, err) {
		assert.Nil(t, su)
		assert.ErrorIs(t, err, ErrModelInvalidSmsCode)
	}
	token := utils.NewSmsToken(phone)
	if assert.NotNil(t, token) && assert.Nil(t, token.Set("", code, false)) {
		su, err = CheckUserOneTimeCode(namespace, userID, &code, nil, &phone)
		if assert.Nil(t, err) {
			assert.NotNil(t, su)
		}
	}
}

func TestNewSysAdminTenant(t *testing.T) {
	_, err := NewSysadminTenant(utils.DefaultNamespace, "test", "")
	assert.NotNil(t, err)
	namespace := "test-new-sysadmin-namespace"
	_, err = NewSysadminTenant(namespace, "test", "")
	assert.Nil(t, err)
	_, err = NewSysadminTenant(namespace, "test", "")
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, db.ErrTenantExists)
	}
}