// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/daemon/db/types"
	"errors"
	"testing"

	"github.com/cylonix/utils/redis"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestDBCache(t *testing.T) {
	namespace := "test_namespace"
	typePath := "test_path"
	deviceID := uuid.NewString()
	id := uuid.NewString()
	value := "put"
	var result interface{}
	err := redis.Put(namespace, typePath, id, value)
	assert.Nil(t, err)

	get, err := redis.Get(namespace, typePath, id)
	assert.Nil(t, err)
	assert.Equal(t, value, get)

	callBack := func(string, *types.UserID, *string, interface{}) error {return nil}
	err = getDataFromCache(namespace, typePath, &types.NilID, &deviceID, &result, callBack)
	assert.Nil(t, err)

	expectedErr := errors.New("test")
	callback := func(string, *types.UserID, *string, interface{}) error {return expectedErr}
	notExistsID := uuid.NewString()
	err = getDataFromCache(namespace, typePath, &types.NilID, &notExistsID, &result, callback)
	assert.ErrorIs(t, err, expectedErr)

	err = cleanCache(namespace, typePath, &types.NilID, &notExistsID)
	assert.Nil(t, err)

	err = cleanCache(namespace, typePath, &types.NilID, &id)
	assert.Nil(t, err)
	key := redis.GenerateID(namespace, typePath, types.NilID.String(), id)
	get, err = redis.GetWithKey(key)
	assert.NotNil(t, err)
	assert.Equal(t, redis.ErrRedisNil, err)
	assert.Equal(t, "", get)
}
