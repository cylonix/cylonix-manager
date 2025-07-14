// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"encoding/json"
	"errors"

	"github.com/cylonix/utils/redis"
)

// We use redis for fast read access. Do NOT use it for complex lookup, write
// or delete operations. If there is no entry in redis, we will read it from
// postgres. if there is no entry in postgres either, we will add one empty
// record into redis with a shorter timeout value than valid entries.

func GetUserFriendsFast(namespace string, userID types.UserID) ([]types.UserID, error) {
	value, err := redis.Get(namespace, redis.ObjTypeUserFriends, userID.String())
	if err != nil {
		if errors.Is(err, redis.ErrRedisNil) {
			return fetchUserFriends(namespace, userID)
		}
		return nil, err
	}
	if value == "" {
		return nil, ErrUserFriendNotExists
	}
	var ret []types.UserID
	err = json.Unmarshal([]byte(value), &ret)
	return ret, err
}

func fetchUserFriends(namespace string, userID types.UserID) ([]types.UserID, error) {
	friends, err := GetUserFriendIDs(namespace, userID)
	value := ""
	expiration := redis.ShortExpiration
	if err != nil && err != ErrUserFriendNotExists {
		return nil, err
	}
	if err == nil {
		b, err := json.Marshal(friends)
		if err != nil {
			return nil, err
		}
		value = string(b)
		expiration = redis.LongExpiration
	}
	redis.PutWithExpiration(namespace, redis.ObjTypeUserFriends, userID.String(), value, expiration)
	return friends, err
}

func GetUserFriendRequestsFast(namespace string, userID types.UserID) ([]*types.FriendRequest, error) {
	value, err := redis.Get(namespace, redis.ObjTypeUserFriendRequests, userID.String())
	if err != nil {
		if errors.Is(err, redis.ErrRedisNil) {
			return fetchUserFriendRequests(namespace, userID)
		}
		return nil, err
	}
	if value == "" {
		return nil, ErrUserFriendRequestNotExists
	}
	var ret []*types.FriendRequest
	err = json.Unmarshal([]byte(value), &ret)
	return ret, err
}

func fetchUserFriendRequests(namespace string, userID types.UserID) ([]*types.FriendRequest, error) {
	requests, err := GetFriendRequests(namespace, userID, nil, nil)
	value := ""
	expiration := redis.ShortExpiration
	if err != nil && err != ErrUserFriendRequestNotExists {
		return nil, err
	}
	if err == nil {
		b, err := json.Marshal(requests)
		if err != nil {
			return nil, err
		}
		value = string(b)
		expiration = redis.LongExpiration
	}
	redis.PutWithExpiration(namespace, redis.ObjTypeUserFriendRequests, userID.String(), value, expiration)
	return requests, err
}
