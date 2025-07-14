// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"encoding/json"
	"errors"
	"sync"

	"github.com/cylonix/utils/redis"
)

const (
	userBaseInfoCacheByUserIDPath     = "user_base_info_cache_by_user_id"
	userCacheByUserIDPath             = "user_cache_by_user_id"
	userDeviceCacheByDeviceIDPath     = "user_device_cache_by_device_id"
	userDeviceIDCacheByUserIDPath     = "user_device_id_cache_by_user_id"
	userDeviceListCacheByUserIDPath   = "user_device_list_cache_by_user_id"
	userLoginCacheByLoginIDPath       = "user_login_cache_by_login_id"
	userLoginCacheByLoginNamePath     = "user_login_cache_by_login_name"
	userLoginCacheByUserIDPath        = "user_login_cache_by_user_id"
	userWgInfoListCacheByUserIDPath   = "user_wg_info_list_cache_by_user_id"
	userWithBaseInfoCacheByUserIDPath = "user_with_base_info_cache_by_user_id"
)

var (
	userCacheByUserIDPaths = []string{
		userBaseInfoCacheByUserIDPath,
		userCacheByUserIDPath,
		userDeviceIDCacheByUserIDPath,
		userLoginCacheByUserIDPath,
		userWgInfoListCacheByUserIDPath,
		userWithBaseInfoCacheByUserIDPath,
	}
)

var (
	errCacheNotFound = errors.New("cache entry does not exist")
	cacheLockMapLock sync.Mutex
	cacheLockMap     = make(map[string]*sync.Mutex)
)

type notFoundInCache func(namespace string, userID *types.UserID, id *string, value interface{}) error

func lockCache(key string) {
	cacheLockMapLock.Lock()
	lock := cacheLockMap[key]
	if lock == nil {
		lock = &sync.Mutex{}
		cacheLockMap[key] = lock
	}
	cacheLockMapLock.Unlock()
	lock.Lock()
}
func unlockCache(key string) {
	cacheLockMapLock.Lock()
	lock := cacheLockMap[key]
	cacheLockMapLock.Unlock()
	lock.Unlock()
}

func getCacheKey(namespace, typePath string, userID *types.UserID, id *string) string {
	var key string
	if userID != nil {
		if id == nil {
			key = redis.GenerateID(namespace, typePath, userID.String())
		} else {
			key = redis.GenerateID(namespace, typePath, userID.String(), *id)
		}
	} else {
		if id == nil {
			key = redis.GenerateID(namespace, typePath)
		} else {
			key = redis.GenerateID(namespace, typePath, *id)
		}
	}
	return key
}

// To distinguish between no record error vs an internal error, caller can check
// errCacheNotFound and the callback's error code for no entry result e.g.
// grom.ErrRecordNotFound.
// Cache is keyed as /namespace/typePath[/userID[/id]]
func getDataFromCache(namespace, typePath string, userID *types.UserID, id *string, result interface{}, callback notFoundInCache) error {
	lockKey := namespace
	if userID != nil {
		lockKey = userID.String()
	}
	lockCache(lockKey)
	defer unlockCache(lockKey)

	key := getCacheKey(namespace, typePath, userID, id)
	resp, err := redis.GetWithKey(key)
	if err != nil {
		log := logger.WithField("cache", typePath)
		if errors.Is(err, redis.ErrRedisNil) {
			if callback == nil {
				return errCacheNotFound
			}
			if err = callback(namespace, userID, id, result); err != nil {
				log.WithError(err).Debugln("cache miss callback failed.")
				return err
			}
			data, err := json.Marshal(result)
			if err != nil {
				return err
			}
			return redis.PutWithKeyWithExpiration(key, string(data), redis.LongExpiration)
		}
		log.WithError(err).Debugln("cache lookup failed.")
		return err
	}
	if resp == "" {
		return errCacheNotFound
	}
	return json.Unmarshal([]byte(resp), result)
}

// No error is returned if entry does not exist.
func cleanCache(namespace, typePath string, userID *types.UserID, id *string) error {
	key := getCacheKey(namespace, typePath, userID, id)
	err := redis.DeleteWithKey(key)
	if err == nil || errors.Is(err, redis.ErrRedisNil) {
		return nil
	}
	return err
}

func cleanUserCache(namespace string, userID types.UserID) error {
	for _, path := range userCacheByUserIDPaths {
		if err := cleanCache(namespace, path, &userID, nil); err != nil {
			return err
		}
	}
	return nil
}
