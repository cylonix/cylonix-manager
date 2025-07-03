package db

import (
	"cylonix/sase/daemon/db/types"
	"fmt"
	"testing"

	"github.com/cylonix/utils/redis"
	"github.com/stretchr/testify/assert"
)

func TestUserFriend(t *testing.T) {
	namespace := "test-user-friend"
	username := "test-user-1"
	friendName := "ubuntu"

	defer DeleteTenantConfigByNamespace(namespace)
	user1, err := newMobileUserForTest(namespace, "12345", username)
	if !assert.Nil(t, err) {
		return
	}
	userID := user1.ID
	defer DeleteUser(namespace, userID)
	user2, err := newMobileUserForTest(namespace, "34567", friendName)
	if !assert.Nil(t, err) {
		return
	}
	friendID := user2.ID
	defer DeleteUser(namespace, friendID)

	isFriend, err := IsFriend(namespace, userID, friendID)
	assert.Nil(t, err)
	assert.False(t, isFriend)

	err = MakeFriend(namespace, userID, friendID)
	assert.Nil(t, err)

	v, err := IsFriend(namespace, userID, friendID)
	assert.Nil(t, err)
	assert.True(t, v)
	v, err = IsFriend(namespace, friendID, userID)
	assert.Nil(t, err)
	assert.True(t, v)

	ret, err := GetUserFriendsFast(namespace, userID)
	if assert.Nil(t, err) && assert.Equal(t, len(ret), 1) {
		assert.Equal(t, ret[0], friendID)
	}

	friendStr, err := redis.Get(namespace, redis.ObjTypeUserFriends, userID.String())
	assert.NotEqual(t, friendStr, "")
	assert.Nil(t, err)

	err = DeleteFriends(namespace, userID, []types.UserID{friendID})
	assert.Nil(t, err)
	_, err = redis.Get(namespace, redis.ObjTypeUserFriends, userID.String())
	assert.ErrorIs(t, err, redis.ErrRedisNil)

	err = MakeFriend(namespace, userID, friendID)
	assert.Nil(t, err)

	err = DeleteUserFriend(namespace, userID, friendID)
	assert.Nil(t, err)
	v, err = IsFriend(namespace, userID, friendID)
	assert.Nil(t, err)
	assert.False(t, v)
	v, err = IsFriend(namespace, friendID, userID)
	assert.Nil(t, err)
	assert.False(t, v)

	// Insert friend only from the userID side.
	err = InsertUserFriend(namespace, friendID, userID)
	assert.Nil(t, err)
	v, err = IsFriend(namespace, userID, friendID)
	assert.Nil(t, err)
	assert.True(t, v)
	v, err = IsFriend(namespace, friendID, userID)
	assert.Nil(t, err)
	assert.False(t, v)
	err = InsertUserFriend(namespace, userID, friendID)
	assert.Nil(t, err)
	v, err = IsFriend(namespace, friendID, userID)
	assert.Nil(t, err)
	assert.True(t, v)

	err = DeleteUserFriend(namespace, userID, types.NilID)
	assert.ErrorIs(t, err, ErrBadParams)

	err = DeleteUserFriend(namespace, types.NilID, userID)
	assert.ErrorIs(t, err, ErrBadParams)
}

func setupFriendRequestTest(namespace string) ([]string, []types.UserID, error) {
	ids := make([]types.UserID, 10)
	names := make([]string, 10)
	for i := 0; i < 10; i++ {
		phone := fmt.Sprintf("phone-num-%v", i)
		names[i] = fmt.Sprintf("test-user-%v", i)
		user, err := newMobileUserForTest(namespace, phone, names[i])
		if err != nil {
			return nil, nil, err
		}
		ids[i] = user.ID
	}
	return names, ids, nil
}

func cleanupFriendRequestTest(namespace string, ids []types.UserID) error {
	for _, id := range ids {
		if err := DeleteUser(namespace, id); err != nil {
			return err
		}
	}
	if err := DeleteTenantConfigByNamespace(namespace); err != nil {
		return err
	}
	return nil
}

func TestInsertFriendRequest(t *testing.T) {
	var (
		namespace = "test-friend-request"
		names []string
		ids []types.UserID
		err error
	)
	defer func() {
		assert.Nil(t, cleanupFriendRequestTest(namespace, ids))
	}()
	names, ids, err = setupFriendRequestTest(namespace)
	if !assert.Nil(t, err) {
		return
	}

	t.Run("insert", func(t *testing.T) {
		userID := ids[0]
		defer func() {
			assert.Nil(t, DeleteFriendRequests(namespace, userID, nil))
		}()
		assert.False(t, FriendRequestExists(namespace, userID, ids[1]))
		note := "user 1 requests to be friend with user 0"
		err = InsertFriendRequest(namespace, ids[1], userID, names[1], names[0], note)
		assert.Nil(t, err)
		assert.True(t, FriendRequestExists(namespace, userID, ids[1]))

		// Inserting the same request fails.
		err = InsertFriendRequest(namespace, ids[1], userID, names[1], names[0], "friend-1")
		assert.NotNil(t, err)

		friendReqList, err := GetUserFriendRequestsFast(namespace, ids[0])
		if assert.Nil(t, err) && assert.Equal(t, len(friendReqList), 1) {
			assert.Equal(t, friendReqList[0].FromUserID, ids[1])
			assert.Equal(t, note, friendReqList[0].Note)
		}
	})

	t.Run("list", func(t *testing.T) {
		userID := ids[0]
		defer func() {
			assert.Nil(t, DeleteFriendRequests(namespace, userID, nil))
		}()
		for i:= 1; i <= 3; i++ {
			err = InsertFriendRequest(namespace, ids[i], userID, names[i], names[0], "add")
			assert.Nil(t, err)
			assert.True(t, FriendRequestExists(namespace, userID, ids[i]))
		}
		for i:= 1; i <= 3; i++ {
			list, err := GetFriendRequests(namespace, userID, &ids[i], nil)
			assert.Nil(t, err)
			assert.Equal(t, 1, len(list))
		}

		list, err := GetFriendRequests(namespace, userID, nil, nil)
		assert.Nil(t, err)
		assert.Equal(t, 3, len(list))
	})
	t.Run("update", func(t *testing.T) {
		userID := ids[0]
		defer func() {
			assert.Nil(t, DeleteFriendRequests(namespace, userID, nil))
		}()
		for i:= 1; i <= 3; i++ {
			err = InsertFriendRequest(namespace, ids[i], userID, names[i], names[0], "add")
			assert.Nil(t, err)
			assert.True(t, FriendRequestExists(namespace, userID, ids[i]))
		}
		list, err := GetUserFriendRequestsFast(namespace, userID)
		if assert.Nil(t, err) && assert.Equal(t, len(list), 3) {
			assert.Equal(t, list[0].FromUserID, ids[1])
		}

		update := types.FriendRequest{Note: "update"}
		err = UpdateFriendRequests(namespace, nil, &userID, []types.FriendRequestID{list[0].ID}, update)
		assert.Nil(t, err)
		_, err = redis.Get(namespace, redis.ObjTypeUserFriendRequests, userID.String())
		assert.ErrorIs(t, err, redis.ErrRedisNil) // Cache should have been cleared.

		update = types.FriendRequest{Note: "approve", State: types.ApprovalStateApproved}
		err = UpdateFriendRequests(namespace, nil, &userID, []types.FriendRequestID{list[1].ID, list[2].ID}, update)
		assert.Nil(t, err)
		_, err = redis.Get(namespace, redis.ObjTypeUserFriendRequests, userID.String())
		assert.ErrorIs(t, err, redis.ErrRedisNil) // Cache should have been cleared.
		v, err := IsFriend(namespace, userID, ids[2])
		assert.Nil(t, err)
		assert.True(t, v)
		v, err = IsFriend(namespace, ids[2], userID)
		assert.Nil(t, err)
		assert.True(t, v)
	})
	t.Run("delete", func(t *testing.T) {
		userID1 := ids[0]
		userID2 := ids[1]
		defer func() {
			assert.Nil(t, DeleteFriendRequests(namespace, userID1, nil))
			assert.Nil(t, DeleteFriendRequests(namespace, userID2, nil))
		}()
		for i:= 3; i < 8; i++ {
			err = InsertFriendRequest(namespace, ids[i], userID1, names[i], names[0], "add")
			assert.Nil(t, err)
			assert.True(t, FriendRequestExists(namespace, userID1, ids[i]))
			err = InsertFriendRequest(namespace, ids[i], userID2, names[i], names[0], "add")
			assert.Nil(t, err)
			assert.True(t, FriendRequestExists(namespace, userID2, ids[i]))
		}
		list, err := GetFriendRequests(namespace, userID1, nil, nil)
		assert.Nil(t, err)
		if !assert.Equal(t, 5, len(list)) {
			return
		}
		var requestIDs []types.FriendRequestID
		for _, v := range list {
			requestIDs = append(requestIDs, v.ID)
		}
		list, err = GetFriendRequests(namespace, userID2, nil, nil)
		assert.Nil(t, err)
		if !assert.Equal(t, 5, len(list)) {
			return
		}
		for _, v := range list {
			requestIDs = append(requestIDs, v.ID)
		}

		// Delete the first two request and check results.
		err = DeleteFriendRequests(namespace, userID1, requestIDs[0:2])
		assert.Nil(t, err)
		_, err = redis.Get(namespace, redis.ObjTypeUserFriendRequests, userID1.String())
		assert.ErrorIs(t, err, redis.ErrRedisNil) // Cache should have been cleared.
		list, err = GetFriendRequests(namespace, userID1, nil, nil)
		assert.Nil(t, err)
		assert.Equal(t, 3, len(list))
		for i:= 3; i < 5; i++ {
			assert.False(t, FriendRequestExists(namespace, userID1, ids[i]))
		}
		for i:= 6; i < 8; i++ {
			assert.True(t, FriendRequestExists(namespace, userID1, ids[i]))
		}
		for i:= 3; i < 8; i++ {
			assert.True(t, FriendRequestExists(namespace, userID2, ids[i]))
		}
	})
}
