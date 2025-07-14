// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cylonix/utils/postgres"
	"github.com/cylonix/utils/redis"
	"gorm.io/gorm"
)

// Only returns error if it is not due to entry not existing.
func invalidateRedisFriend(namespace string, userID string, caller string) error {
	if namespace == "" || userID == "" {
		return nil
	}
	err := redis.Delete(namespace, redis.ObjTypeUserFriends, userID)
	if err != nil && !errors.Is(err, redis.ErrRedisNil) {
		return fmt.Errorf("failed to invalidate redis friend entry when %v: %w", caller, err)
	}
	return nil
}

// Only returns error if it is not due to entry not existing.
func invalidateRedisFriendRequest(namespace string, userID string, caller string) error {
	if namespace == "" || userID == "" {
		return nil
	}
	err := redis.Delete(namespace, redis.ObjTypeUserFriendRequests, userID)
	if err != nil && !errors.Is(err, redis.ErrRedisNil) {
		return fmt.Errorf("failed to invalidate redis friend request entry when %v: %w", caller, err)
	}
	return nil
}

// Add friend ID to the friends list of user with userID
func InsertUserFriend(namespace string, friendID, userID types.UserID) error {
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	user := &types.User{Model: types.Model{ID: userID}, Namespace: namespace}
	friend := &types.User{Model: types.Model{ID: friendID}}
	if err = tx.Model(user).Association("Friends").Append(friend); err != nil {
		return err
	}

	if err = invalidateRedisFriend(namespace, userID.String(), "adding"); err != nil {
		return err
	}
	return tx.Commit().Error
}

func DeleteUserFriend(namespace string, userID, friendID types.UserID) error {
	if userID == types.NilID || friendID == types.NilID {
		return ErrBadParams
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	user := types.User{Model: types.Model{ID: userID}, Namespace: namespace}
	friend := types.User{Model: types.Model{ID: friendID}, Namespace: namespace}
	if err = tx.Model(&user).Association("Friends").Delete(&friend); err != nil {
		return err
	}
	if err = tx.Model(&friend).Association("Friends").Delete(&user); err != nil {
		return err
	}
	if err = invalidateRedisFriend(namespace, userID.String(), "deleting"); err != nil {
		return err
	}
	if err = invalidateRedisFriend(namespace, friendID.String(), "deleting"); err != nil {
		return err
	}
	return tx.Commit().Error
}

// Return list of userIDs of the friends.
// Redis entry is not updated with this call. It will be updated when caller
// calls the redis API.
func GetUserFriendIDs(namespace string, userID types.UserID) ([]types.UserID, error) {
	ret := &types.User{}
	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	db := pg.Model(ret).Where("id = ?", userID).
		Preload("Friends", func(db *gorm.DB) *gorm.DB {
			return db.Select("id")
		})
	err = db.Find(ret, "namespace = ?", namespace).Error

	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = ErrUserNotExists
	}
	if err != nil {
		return nil, err
	}
	var list []types.UserID
	for _, v := range ret.Friends {
		list = append(list, v.ID)
	}
	return list, nil
}
func InsertFriendRequest(namespace string, friendID, userID types.UserID, friendName, username, note string) error {
	req := types.FriendRequest{
		Namespace:    namespace,
		FromUserID:   friendID,
		ToUserID:     userID,
		FromUsername: friendName,
		ToUsername:   username,
		Note:         note,
	}
	if err := req.Model.SetIDIfNil(); err != nil {
		return err
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()
	if err := tx.Create(&req).Error; err != nil {
		return err
	}
	if err := invalidateRedisFriendRequest(namespace, userID.String(), "adding"); err != nil {
		return err
	}
	return tx.Commit().Error
}

func UpdateFriendRequests(namespace string, fromUserID *types.UserID, toUserID *types.UserID, idList []types.FriendRequestID, update types.FriendRequest) error {
	if fromUserID == nil && toUserID == nil && len(idList) <= 0 {
		return ErrBadParams
	}

	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	tx = tx.
		Model(&types.FriendRequest{}).
		Where(&types.FriendRequest{Namespace: namespace})
	if fromUserID != nil {
		tx = tx.Where(&types.FriendRequest{FromUserID: *fromUserID})
	}
	if toUserID != nil {
		tx = tx.Where(&types.FriendRequest{ToUserID: *toUserID})
	}
	if len(idList) == 1 {
		tx = tx.Where(&types.FriendRequest{Model: types.Model{ID: idList[0]}})
	}
	// Only allow update state and note.
	up := types.FriendRequest{
		Note: update.Note,
		State: update.State,
	}
	if len(idList) > 1 {
		tx = tx.Where("id in ?", idList)
	}
	if err := tx.Updates(&up).Error; err != nil {
		return fmt.Errorf("failed to update friend requests: %w ", err)
	}
	if err = invalidateRedisFriendRequest(namespace, toUserID.String(), "updating"); err != nil {
		return err
	}
	if up.State == types.ApprovalStateApproved {
		requests := []types.FriendRequest{}
		if err := tx.Select("FromUserID", "ToUserID").Find(&requests).Error; err != nil {
			return err
		}
		var users []*types.User
		var friends []*types.User
		for _, v := range requests {
			friends = append(friends, &types.User{Model: types.Model{ID: v.FromUserID}})
			users = append(users, &types.User{Model: types.Model{ID: v.ToUserID}})
		}
		// Add friend to user's "Friends" association.
		if err := tx.Model(&users).Association("Friends").Append(toEmptyInterfaceSlice(friends)...); err != nil {
			return err
		}
		// Add user to each friend's "Friends" association.
		if err := tx.Model(&friends).Association("Friends").Append(toEmptyInterfaceSlice(users)...); err != nil {
			return err
		}
		if err = invalidateRedisFriendRequest(namespace, "*", "batch adding friends"); err != nil {
			return err
		}
	}
	return tx.Commit().Error
}
func DeleteFriendRequests(namespace string, userID types.UserID, requestIDList []types.ID) error {
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	request := types.FriendRequest{
		Namespace: namespace,
		ToUserID: userID,
	}
	tx = tx.Model(&types.FriendRequest{}).Where(&request)
	if len(requestIDList) == 1 {
		value := types.FriendRequest{
			Model: types.Model{ID: requestIDList[0]},
		}
		tx = tx.Where(value)
	} else if len(requestIDList) > 1 {
		tx = tx.Where("id in ?", requestIDList)
	}
	err = tx.Delete(&types.FriendRequest{}).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	if err = invalidateRedisFriendRequest(namespace, userID.String(), "deleting"); err != nil {
		return err
	}
	return tx.Commit().Error
}
func FriendRequestExists(namespace string, userID, friendID types.UserID) bool {
	ret := types.FriendRequest{}
	err := postgres.SelectFirst(&ret, &types.FriendRequest{
		Namespace:  namespace,
		ToUserID:   userID,
		FromUserID: friendID,
	})
	return err == nil
}
func GetFriendRequests(namespace string, userID types.UserID, friendID *types.UserID, contain *string) ([]*types.FriendRequest, error) {
	ret := []*types.FriendRequest{}
	var err error
	if contain != nil && *contain != "" && friendID == nil {
		c := like(*contain)
		c1 := like(strings.ToUpper(strings.ReplaceAll(*contain, "-", "")))
		err = postgres.SelectByModel(
			&types.FriendRequest{}, &ret,
			"namespace = ? and to_user_id = ? and " +
			"(hex(to_user_id) like ? or hex(from_user_id) like ? or " + 
			" to_username like ? or from_username like ? or note like ?)",
			namespace, userID, c1, c1, c, c, c,
		)
	} else {
		query := types.FriendRequest{
			Namespace:  namespace,
			ToUserID:   userID,
		}
		if friendID != nil {
			query.FromUserID = *friendID
		}
		err = postgres.SelectByModel(&types.FriendRequest{}, &ret, &query)
	}
	if errors.Is(err, gorm.ErrRecordNotFound) || len(ret) == 0 {
		err = ErrUserFriendRequestNotExists
	}
	return ret, err
}

func DeleteFriends(namespace string, userID types.UserID, friendIDs []types.UserID) error {
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	user := types.User{Model: types.Model{ID: userID}, Namespace: namespace}
	var friends []types.User
	for _, v := range friendIDs {
		friends = append(friends, types.User{Model: types.Model{ID: v}})
	}
	if err = tx.Model(&user).Association("Friends").Delete(&friends); err != nil {
		return err
	}
	if err = invalidateRedisFriend(namespace, userID.String(), "deleting"); err != nil {
		return err
	}
	return tx.Commit().Error
}

// Add friends to the user.
func MakeFriend(namespace string, userID, friendID types.UserID) error {
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	user := types.User{Model: types.Model{ID: userID}, Namespace: namespace}
	friend := types.User{Model: types.Model{ID: friendID}, Namespace: namespace}
	if err = tx.Model(&user).Association("Friends").Append(&friend); err != nil {
		return err
	}
	if err = tx.Model(&friend).Association("Friends").Append(&user); err != nil {
		return err
	}

	if err = invalidateRedisFriend(namespace, friendID.String(), "adding"); err != nil {
		return err
	}
	if err = invalidateRedisFriend(namespace, userID.String(), "adding"); err != nil {
		return err
	}
	return tx.Commit().Error
}

func IsFriend(namespace string, userID, friendID types.UserID) (bool, error) {
	list, err := GetUserFriendIDs(namespace, userID)
	if err != nil {
		return false, err
	}
	return slices.Contains(list, friendID), nil
}
