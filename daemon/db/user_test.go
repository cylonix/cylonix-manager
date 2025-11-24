// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"testing"

	pw "github.com/cylonix/utils/password"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func newMobileUserForTest(namespace, mobile, displayName string) (*types.User, error) {
	tier, err := createUserTierForTest()
	if err != nil {
		return nil, err
	}
	_, err = NewTenantForNamespace(
		namespace, namespace, uuid.New().String(), uuid.New().String(), nil,
		&types.TenantSetting{
			MaxUser:       200,
			MaxDevice:     1000,
			NetworkDomain: namespace + "test.org",
		}, &tier.ID, true /* update if exists */,
	)
	if err != nil {
		return nil, err
	}
	login := types.NewPhoneLogin(namespace, mobile, displayName, "")
	login.ID, err = types.NewID()
	if err != nil {
		return nil, err
	}
	loginSlice := []types.UserLogin{*login}
	return AddUser(namespace, "", mobile, displayName, loginSlice, nil, nil, nil, nil, nil)
}

func newUsernameLoginUserForTest(namespace, username, password, displayName, phone string) (*types.User, error) {
	tier, err := createUserTierForTest()
	if err != nil {
		return nil, err
	}
	_, err = NewTenantForNamespace(
		namespace, namespace, uuid.New().String(), uuid.New().String(), nil,
		&types.TenantSetting{
			MaxUser:       200,
			MaxDevice:     1000,
			NetworkDomain: namespace + "test.org",
		}, &tier.ID, true /* update if exists */,
	)
	if err != nil {
		return nil, err
	}
	login, err := types.NewUsernameLogin(namespace, username, password, displayName, "")
	if err != nil {
		return nil, err
	}
	login.ID, err = types.NewID()
	if err != nil {
		return nil, err
	}
	loginSlice := []types.UserLogin{*login}
	return AddUser(namespace, "", phone, "", loginSlice, nil, nil, nil, nil, nil)
}

func TestUserDB(t *testing.T) {
	namespace := "user_test"
	username := "test-user-1"
	phone := "1234567890"
	defer DeleteTenantConfigByNamespace(namespace)

	su, err := newUsernameLoginUserForTest(namespace, username, "", "", phone)
	assert.Nil(t, err)
	if !assert.NotNil(t, su) {
		return
	}
	userID := su.ID
	defer func() {
		assert.Nil(t, DeleteUser(nil, namespace, userID))
		assert.Nil(t, DeleteTenantConfigByNamespace(namespace))
	}()
	su, err = GetUserFast(namespace, userID, false)
	assert.Nil(t, err)
	assert.NotNil(t, su)
	label := types.Label{
		Name:      "label-name",
		Namespace: namespace,
	}
	label2 := types.Label{
		Name:      "label-name",
		Namespace: namespace,
	}

	err = AddUserLabel(namespace, userID, []types.Label{label})
	assert.Nil(t, err)
	userLabels, err := GetUserLabelList(namespace, userID)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(userLabels))

	err = UpdateUserLabels(namespace, userID, []types.Label{label2}, true)
	assert.Nil(t, err)
	userLabels, err = GetUserLabelList(namespace, userID)
	assert.Nil(t, err)
	if assert.Equal(t, 1, len(userLabels)) {
		label2.ID = userLabels[0].ID
	}

	err = DeleteLabel(namespace, nil, label2.ID)
	assert.Nil(t, err)
	userLabels, err = GetUserLabelList(namespace, userID)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(userLabels))

	userLogin2 := types.NewPhoneLogin(namespace, phone, username, "")
	userLogin2.UserID = userID
	userLogin2.ID, err = types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	err = CreateUserLogin(userLogin2)
	assert.Nil(t, err)

	userLogins, err := GetUserLoginByUserIDFast(namespace, userID)
	if assert.Nil(t, err) {
		assert.Equal(t, 2, len(userLogins))
	}

	userLogin3 := types.NewWeChatLogin(namespace, "13521545406", username, "", "")
	userLogin3.UserID = userID
	userLogin3.ID, err = types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	err = CreateUserLogin(userLogin3)
	if !assert.Nil(t, err) {
		return
	}
	userLogins, err = GetUserLoginByUserIDFast(namespace, userID)
	assert.Nil(t, err)
	assert.Equal(t, 3, len(userLogins))

	err = DeleteUserLogin(nil, namespace, userID, userLogin2.ID)
	assert.Nil(t, err)
	userLogins, err = GetUserLoginByUserIDFast(namespace, userID)
	if assert.Nil(t, err) {
		assert.Equal(t, 2, len(userLogins))
	}

	userList, total, err := GetUserList(&namespace, nil, false, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, len(userList))
		assert.Equal(t, int(total), len(userList))
	}
	user, err := GetUserByLoginName(namespace, username)
	if assert.Nil(t, err) {
		assert.Equal(t, user.ID, user.UserBaseInfo.UserID)
	}

	// Create.
	username2 := "test-username-2"
	password := "testPassW0rd!"
	login, err := types.NewUsernameLogin(namespace, username2, password, "", "")
	if assert.Nil(t, err) && assert.NotNil(t, login) {
		login.ID, err = types.NewID()
		if !assert.Nil(t, err) {
			return
		}
		phoneLogin := types.NewPhoneLogin(namespace, "456", "", "")
		phoneLogin.ID, err = types.NewID()
		if !assert.Nil(t, err) {
			return
		}
		paramUserLogins := []types.UserLogin{
			*login,
			*phoneLogin,
		}
		displayName := "John Doe"
		user, err = AddUser(namespace, "fake@abc.com", "", displayName, paramUserLogins, nil, nil, nil, nil, nil)
		if assert.Nil(t, err) {
			login, err := GetUserLoginFast(namespace, user.UserLogins[0].ID)
			assert.Nil(t, err)
			assert.NotNil(t, login)
			userLogins, err = GetUserLoginByUserIDFast(namespace, user.ID)
			if assert.Nil(t, err) {
				assert.Equal(t, 2, len(userLogins))
				assert.Nil(t, pw.CompareToHash(password, login.Credential))
			}
			baseUser, err := GetUserWithBaseInfoFast(namespace, user.ID)
			assert.Nil(t, err)
			assert.Equal(t, displayName, baseUser.UserBaseInfo.DisplayName)
		}
	}

	// Update.
	mode := models.MeshVpnModeSingle
	accept := true
	update := &models.UserUpdateInfo{
		MeshVpnMode:           &mode,
		AdvertiseDefaultRoute: &accept,
	}
	err = UpdateUser(nil, namespace, userID, update)
	if assert.Nil(t, err) {
		user, err := GetUserFast(namespace, userID, true)
		if assert.Nil(t, err) && assert.NotNil(t, user) {
			assert.Equal(t, string(models.MeshVpnModeSingle), optional.String(user.MeshVpnMode))
		}
	}

	// Delete.
	err = DeleteUser(nil, namespace, user.ID)
	if assert.Nil(t, err) {
		_, err := GetUserFast(namespace, user.ID, true)
		assert.NotNil(t, err)
	}

	// Models API.
	defaultUser1 := types.User{Namespace: namespace}
	defaultUser2 := types.User{Namespace: namespace}
	defaultUser3 := types.User{Namespace: namespace, Roles: []string{"test-role"}}
	userSlice := []types.User{defaultUser1, defaultUser2, defaultUser3}
	modelsUserList := types.UserSlice(userSlice).ToModel()
	su = su.FromModel(namespace, modelsUserList[2])
	assert.NotNil(t, su)
	assert.Equal(t, defaultUser3.Roles[0], su.Roles[0])

	defaultDeviceList := types.DeviceList{
		types.Device{Namespace: namespace, Name: "10.0.0.1"},
		types.Device{Namespace: namespace, Name: "10.0.0.2"},
		types.Device{Namespace: namespace, Name: "10.0.0.3"},
	}
	list := defaultDeviceList.ToModel()
	assert.NotNil(t, list)
	if assert.Equal(t, 3, len(list)) {
		assert.Equal(t, defaultDeviceList[2].Name, list[2].Name)
	}

	// TODO: more testing on cache as the cleanup may not be complete
	// TODO: in various create/update/delete operations.
}

func TestUserBaseInfo(t *testing.T) {
	namespace, username := "user_info_test", "test-username"
	mobile, password, displayName := "1234", "123456", "Test user"

	defer DeleteTenantConfigByNamespace(namespace)

	// Create
	user, err := newUsernameLoginUserForTest(namespace, username, password,
		displayName, mobile)
	if !assert.Nil(t, err) {
		return
	}
	userID := user.ID

	result := &types.UserBaseInfo{}
	err = GetUserBaseInfo(namespace, userID, result)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, result.Namespace, user.Namespace)

	// Update
	update := types.UserBaseInfo{DisplayName: "2222"}
	err = UpdateUserBaseInfo(namespace, userID, &update)
	assert.Nil(t, err)

	err = GetUserBaseInfo(namespace, userID, result)
	if assert.Nil(t, err) {
		assert.Equal(t, result.DisplayName, "2222")
	}

	// Cache
	fastResult, err := GetUserBaseInfoFast(namespace, userID)
	assert.Nil(t, err)
	if assert.NotNil(t, fastResult) {
		assert.Equal(t, fastResult.UserID, userID)
	}
	_, err = GetUserBaseInfoCacheOnly(namespace, userID)
	assert.Nil(t, err)

	// Mobile login
	login := &types.UserLogin{
		LoginType: types.LoginTypePhone,
		UserID:    userID,
		LoginName: mobile,
		Namespace: namespace,
	}
	err = CreateUserLogin(login)
	assert.Nil(t, err)

	newMobile := "5678"
	err = UpdateLoginPhone(login, newMobile)
	assert.Nil(t, err)

	updateLoginUser, err := GetUserLoginFast(namespace, login.ID)
	if assert.Nil(t, err) {
		assert.Equal(t, updateLoginUser.LoginName, newMobile)
	}
	err = GetUserBaseInfo(namespace, userID, result)
	if assert.Nil(t, err) {
		assert.Equal(t, optional.String(result.Mobile), newMobile)
	}

	// Delete
	err = DeleteUserBaseInfo(namespace, userID)
	assert.Nil(t, err)
	err = GetUserBaseInfo(namespace, userID, result)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserNotExists)
	}
	_, err = GetUserBaseInfoCacheOnly(namespace, userID)
	assert.ErrorIs(t, err, ErrUserNotExists)
	_, err = GetUserBaseInfoFast(namespace, userID)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserNotExists)
	}
}

func TestUserTier(t *testing.T) {
	namespace, username := "user_tier_test", "test-tier-username"
	mobile, password, displayName := "1234", "123456", "Test user"

	defer DeleteTenantConfigByNamespace(namespace)

	user, err := newUsernameLoginUserForTest(namespace, username, password,
		displayName, mobile)
	if !assert.Nil(t, err) {
		return
	}
	userID := user.ID
	defer func() {
		err := DeleteUser(nil, namespace, userID)
		if err != nil {
			assert.ErrorIs(t, err, ErrUserNotExists)
		}
	}()

	// User tier cannot be deleted if there is a user refers to it.
	if !assert.NotNil(t, DeleteUserTier(*user.UserTierID)) {
		if assert.Nil(t, GetUser(userID, &user)) {
			v, _ := json.Marshal(user)
			t.Errorf("user=%v", string(v))
		}
	}

	// Deleting user shouldn't delete the user tier or set is content to NULL.
	assert.Nil(t, DeleteUser(nil, namespace, userID))
	tier, err := GetUserTier(*user.UserTierID)
	if assert.Nil(t, err) && assert.NotNil(t, tier) {
		assert.NotZero(t, tier.MaxUserCount)
		assert.NotZero(t, tier.MaxDeviceCount)
	}
}
