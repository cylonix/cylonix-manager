// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db_test

import (
	. "cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	dbt "cylonix/sase/pkg/test/db"
	"testing"

	pw "github.com/cylonix/utils/password"
	"github.com/stretchr/testify/assert"
)

func TestLoginDB(t *testing.T) {
	namespace := "test-login-user-namespace"
	loginName := "test-username"

	user, err := dbt.CreateUserForTest(namespace, "151")
	if !assert.Nil(t, err) || !assert.NotNil(t, user) {
		return
	}
	userID := user.ID
	defer func() {
		err := DeleteUser(nil, namespace, userID)
		assert.Nil(t, err)
	}()

	login := &types.UserLogin{
		LoginName:  loginName,
		LoginType:  types.LoginTypeUsername,
		Credential: "123455",
		UserID:     userID,
		Namespace:  namespace,
	}

	available, err := IsLoginAvailable(namespace, loginName, types.LoginTypeUsername)
	assert.Nil(t, err)
	assert.True(t, available)

	userLoginExists, err := UserLoginExists(namespace, []string{loginName})
	assert.Nil(t, err)
	assert.False(t, userLoginExists)

	_, err = GetUserLoginByUserIDAndLoginType(namespace, userID, types.LoginTypeUsername)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserLoginNotExists)
	}

	_, err = GetUserLoginByUserID(namespace, userID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserLoginNotExists)
	}

	_, err = GetUserLoginByUserIDFast(namespace, userID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserLoginNotExists)
	}

	_, err = LoginNameToUserID(namespace, loginName)
	assert.NotNil(t, err)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserLoginNotExists)
	}

	approvalState, err := LoginRegistrationState(namespace, loginName)
	assert.Nil(t, err)
	assert.Nil(t, approvalState)

	// Create user login.
	err = CreateUserLogin(login)
	assert.Nil(t, err)

	// Create the same user login should fail due to conflict check.
	err = CreateUserLogin(login)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserLoginExists)
	}

	userLoginExists, err = UserLoginExists(namespace, []string{loginName})
	assert.Nil(t, err)
	assert.True(t, userLoginExists)

	loginResult, err := GetUserLoginByUserIDAndLoginType(namespace, userID, types.LoginTypeUsername)
	if assert.Nil(t, err) {
		assert.Equal(t, loginResult.LoginName, loginName)
	}

	result, err := GetUserLogin(namespace, login.ID)
	if assert.Nil(t, err) {
		assert.NotNil(t, result)
		assert.Equal(t, result.Namespace, namespace)
	}

	password := "567891"
	err = UpdateLoginUsernamePassword(nil, login, "", password)
	assert.Nil(t, err)

	newResult, err := GetUserLogin(namespace, login.ID)
	if assert.Nil(t, err) {
		assert.Nil(t, pw.CompareToHash(password, newResult.Credential))
		assert.Equal(t, newResult.ID, login.ID)
		assert.Equal(t, newResult.LoginName, loginName)
		assert.Equal(t, newResult.UserID, userID)
		assert.Equal(t, newResult.Namespace, namespace)
		assert.Equal(t, newResult.LoginType, login.LoginType)
	}

	fastResult, err := GetUserLoginFast(namespace, login.ID)
	assert.Nil(t, err)
	if assert.NotNil(t, fastResult) {
		assert.Equal(t, fastResult.LoginName, loginName)
	}
	_, err = GetUserLoginCacheOnly(namespace, login.ID)
	assert.Nil(t, err)

	err = DeleteUserLogin(nil, namespace, userID, fastResult)
	assert.Nil(t, err)
	_, err = GetUserLogin(namespace, login.ID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserLoginNotExists)
	}
	_, err = GetUserLoginCacheOnly(namespace, login.ID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserLoginNotExists)
	}
	_, err = GetUserLoginFast(namespace, login.ID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserLoginNotExists)
	}

	// Delete non existing login is not an error.
	_, err = GetUserLoginByUserIDFast(namespace, userID)
	assert.ErrorIs(t, err, ErrUserLoginNotExists)
	err = DeleteUserLoginByUserID(namespace, userID)
	assert.Nil(t, err)

	// Delete non existing login with user ID check should generate error.
	_, err = GetUserLoginByLoginName(namespace, loginName)
	assert.ErrorIs(t, err, ErrUserLoginNotExists)
	err = DeleteUserLoginCheckUserID(nil, namespace, userID, loginName)
	assert.ErrorIs(t, err, ErrUserLoginNotExists)

	err = DeleteUserLoginCheckUserID(nil, namespace, types.NilID, loginName)
	assert.ErrorIs(t, err, ErrUserLoginNotExists)

	email, err := GetUserEmailOrPhone(namespace, userID, false)
	assert.Nil(t, err)
	assert.Nil(t, email)

	emailLoginName := "123@abc.com"
	emailLoginUser := types.UserLogin{
		LoginName:  emailLoginName,
		LoginType:  types.LoginTypeEmail,
		UserID:     userID,
		Namespace:  namespace,
	}

	phoneLoginName := "13415"
	phoneLoginUser := types.UserLogin{
		LoginName:  phoneLoginName,
		LoginType:  types.LoginTypePhone,
		UserID:     userID,
		Namespace:  namespace,
	}
	err = CreateUserLogin(&emailLoginUser)
	assert.Nil(t, err)
	err = CreateUserLogin(&phoneLoginUser)
	assert.Nil(t, err)

	email, err = GetUserEmailOrPhone(namespace, userID, false)
	assert.Nil(t, err)
	if assert.NotNil(t, email) {
		assert.Equal(t, *email, emailLoginName)
	}
	phone, err := GetUserEmailOrPhone(namespace, userID, true)
	assert.Nil(t, err)
	if assert.NotNil(t, phone) {
		assert.Equal(t, *phone, phoneLoginName)
	}
	loginResult, err = GetUserLoginByUserIDAndLoginType(namespace, userID, types.LoginTypeEmail)
	if assert.Nil(t, err) {
		assert.Equal(t, loginResult.LoginName, emailLoginName)
	}
	loginResult, err = GetUserLoginByUserIDAndLoginType(namespace, userID, types.LoginTypePhone)
	if assert.Nil(t, err) {
		assert.Equal(t, loginResult.LoginName, phoneLoginName)
	}

	err = DeleteUserLoginCheckUserID(nil, namespace, types.NilID, phoneLoginName)
	assert.NotNil(t, err)
	err = DeleteUserLoginCheckUserID(nil, namespace, userID, phoneLoginName)
	assert.Nil(t, err)

	ret, err := GetLoginName(namespace, userID)
	assert.Nil(t, err)
	assert.Equal(t, emailLoginName, ret)

	// Bad non-existing login deletion is not an error.
	badID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	err = DeleteUserLoginByUserID(namespace, badID)
	assert.Nil(t, err)

	err = DeleteUserLoginByUserID(namespace, userID)
	assert.Nil(t, err)

	err = CreateUserLogin(&phoneLoginUser)
	assert.Nil(t, err)
}
