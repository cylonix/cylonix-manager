// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testBase64Image    = "Test Base64 image"
	testBase64ImageNew = "Test Base64 image update"
	testUserProfile    = &models.UserProfile{
		Base64Image: testBase64Image,
	}
	testUserProfileNew = &models.UserProfile{
		Base64Image: testBase64ImageNew,
	}
)

func TestUserProfileDB(t *testing.T) {
	namespace := "user_profile_namespace"
	userID := "user_profile_user_id"
	_, err := GetUserProfile(namespace, userID)
	assert.ErrorIs(t, err, ErrUserProfilePicNotExists)

	profile, err := AddUserProfile(namespace, userID, testUserProfile)
	if assert.Nil(t, err) {
		assert.Equal(t, testBase64Image, profile.Base64Image)
	}
	profile, err = GetUserProfile(namespace, userID)
	if assert.Nil(t, err) {
		if assert.NotNil(t, profile.Base64Image) {
			assert.Equal(t, testUserProfile.Base64Image, profile.Base64Image)
		}
	}
	_, err = AddUserProfile(namespace, userID, profile)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrUserProfilePicExists)
	}
	_, err = AddUserProfile(namespace, userID, nil)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, ErrBadParams)
	}

	err = UpdateUserProfile(namespace, userID, testUserProfileNew)
	assert.Nil(t, err)
	profile, err = GetUserProfile(namespace, userID)
	if assert.Nil(t, err) && assert.NotNil(t, profile) && assert.NotNil(t, profile.Base64Image) {
		assert.Equal(t, testUserProfileNew.Base64Image, profile.Base64Image)

	}

	err = DeleteUserProfile(namespace, userID)
	assert.Nil(t, err)
	profile, err = GetUserProfile(namespace, userID)
	if assert.NotNil(t, err) {
		assert.Nil(t, profile)
	}
}
