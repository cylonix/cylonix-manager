// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/optional"
	dbt "cylonix/sase/pkg/test/db"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestFriend(t *testing.T) {
	namespace := "friend-namespace"
	username1 := "friend-name-1"
	username2 := "friend-name-2"
	username3 := "friend-name-3"

	user, err := dbt.CreateUserForTest(namespace, "3134")
	assert.Nil(t, err)
	if !assert.NotNil(t, user) {
		return
	}
	userID1 := user.ID
	user, err = dbt.CreateUserForTest(namespace, "243134")
	if !assert.NotNil(t, user) {
		return
	}
	userID2 := user.ID
	assert.Nil(t, err)
	user, err = dbt.CreateUserForTest(namespace, "2243134")
	assert.Nil(t, err)
	if !assert.NotNil(t, user) {
		return
	}
	userID3 := user.ID

	_, user1Token := dbt.CreateTokenForTest(namespace, userID1, username1, false, nil)
	assert.NotNil(t, user1Token)
	_, user2Token := dbt.CreateTokenForTest(namespace, userID2, username2, false, nil)
	assert.NotNil(t, user2Token)
	_, user3Token := dbt.CreateTokenForTest(namespace, userID3, username3, false, nil)
	assert.NotNil(t, user3Token)
	createRequestParam := api.CreateFriendRequestRequestObject{
		Body: &models.FriendRequest{
			Note:       optional.StringP("abc"),
			ToUserID:   userID1.UUIDP(),
			ToUsername: &username1,
		},
	}
	handler := newFriendHandlerImpl(testLogger)

	err = handler.CreateRequest(user2Token, createRequestParam)
	assert.Nil(t, err)

	err = handler.CreateRequest(user3Token, createRequestParam)
	assert.Nil(t, err)

	err = handler.CreateRequest(user3Token, createRequestParam)
	assert.ErrorIs(t, err, common.ErrModelFriendRequestExists)

	listRequestParams := api.ListFriendRequestsRequestObject{
		Params: models.ListFriendRequestsParams{
			Contain: optional.StringP(userID2.String()),
		},
	}
	listRequest, err := handler.ListRequests(user1Token, listRequestParams)
	if assert.Nil(t, err) &&
		assert.Equal(t, 1, len(listRequest)) &&
		assert.NotNil(t, listRequest[0].FromUserID) {
		assert.Equal(t, userID2.UUID(), *listRequest[0].FromUserID)
	} else {
		return
	}
	user2RequestID := listRequest[0].ID

	listRequestParams = api.ListFriendRequestsRequestObject{}
	listRequest, err = handler.ListRequests(user1Token, listRequestParams)
	if assert.Nil(t, err) &&
		assert.Equal(t, 2, len(listRequest)) &&
		assert.NotNil(t, listRequest[1].FromUserID) {
		assert.Equal(t, userID3.UUID(), *listRequest[1].FromUserID)
	} else {
		return
	}
	user3RequestID := listRequest[1].ID

	note := "approved by user 1"
	state := models.ApprovalStateApproved
	UpdateParams := api.UpdateFriendRequestsRequestObject{
		Body: &models.UpdateFriendRequestsJSONRequestBody{
			Update: models.FriendRequest{
				Note: &note,
				State: &state,
				ToUserID: userID1.UUIDP(),
			},
			IDList: []uuid.UUID{
				*user2RequestID,
			},
		},
	}
	err = handler.UpdateRequests(user1Token, UpdateParams)
	assert.Nil(t, err)
	user1Friends, err := handler.List(user1Token, api.ListFriendRequestObject{})
	if assert.Nil(t, err) && assert.Equal(t, 1, len(*user1Friends.FriendList)) {
		assert.Equal(t, userID2.UUID(), (*user1Friends.FriendList)[0].UserID)
	}

	user2Friends, err := handler.List(user2Token, api.ListFriendRequestObject{})
	if assert.Nil(t, err) && assert.Equal(t, 1, len(*user2Friends.FriendList)) {
		assert.Equal(t, userID1.UUID(), (*user2Friends.FriendList)[0].UserID)
	}

	user3Friends, err := handler.List(user3Token, api.ListFriendRequestObject{})
	assert.Nil(t, err)
	if assert.NotNil(t, user3Friends) {
		assert.Zero(t, len(*user3Friends.FriendList))
	}

	// Unfriend user2 from user1. User2 still friends with user1 unilaterally.
	idList := []uuid.UUID{userID2.UUID()}
	params := api.DeleteFriendsRequestObject{
		Body: &idList,
	}
	err = handler.Delete(user1Token, params)
	assert.Nil(t, err)
	user1Friends, err = handler.List(user1Token, api.ListFriendRequestObject{})
	assert.Nil(t, err)
	if assert.NotNil(t, user1Friends) {
		assert.Zero(t, len(*user1Friends.FriendList))
	}
	user2Friends, err = handler.List(user2Token, api.ListFriendRequestObject{})
	assert.Nil(t, err)
	if assert.NotNil(t, user2Friends) {
		assert.Equal(t, 1, len(*user2Friends.FriendList))
	}

	// Unfriend user1 from user2.
	idList = []uuid.UUID{userID1.UUID()}
	params = api.DeleteFriendsRequestObject{
		Body: &idList,
	}
	err = handler.Delete(user2Token, params)
	assert.Nil(t, err)
	user2Friends, err = handler.List(user2Token, api.ListFriendRequestObject{})
	assert.Nil(t, err)
	if assert.NotNil(t, user2Friends) {
		assert.Zero(t, len(*user2Friends.FriendList))
	}

	idList = []uuid.UUID{*user2RequestID}
	deleteRequestParam := api.DeleteFriendRequestsRequestObject{
		Body: &idList,
	}
	err = handler.DeleteRequests(user1Token, deleteRequestParam)
	assert.Nil(t, err)
	listRequestParams = api.ListFriendRequestsRequestObject{}
	listRequest, err = handler.ListRequests(user1Token, listRequestParams)
	if assert.Nil(t, err) &&
		assert.Equal(t, 1, len(listRequest)) &&
		assert.NotNil(t, listRequest[0].FromUserID) {
		assert.Equal(t, userID3.UUID(), *listRequest[0].FromUserID)
	}

	idList = []uuid.UUID{*user3RequestID}
	deleteRequestParam = api.DeleteFriendRequestsRequestObject{
		Body: &idList,
	}
	err = handler.DeleteRequests(user1Token, deleteRequestParam)
	assert.Nil(t, err)

	listRequest, err = handler.ListRequests(user1Token, listRequestParams)
	assert.Nil(t, err)
	assert.Zero(t, len(listRequest))
}
