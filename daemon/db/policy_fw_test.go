// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testFwPolicyNamespace = "test-fw-namespace"
	testFwPolicyID        = "test fw policy id"
	testFwPolicyNameUpd   = "test fw policy upd"
	testFwPolicyName      = "test fw policy"
	testFwPolicyNoExist   = "test fw policy no exist"
)

func TestFwPolicyDB(t *testing.T) {
	assert.Nil(t, NewFwPolicy(testFwPolicyNamespace, testFwPolicyID, testFwPolicyName))
	ret, err := GetFwPolicy(testFwPolicyNamespace, testFwPolicyID)
	assert.Nil(t, err)
	assert.Equal(t, testFwPolicyName, ret)

	assert.Nil(t, UpdateFwPolicy(testFwPolicyNamespace, testFwPolicyID, testFwPolicyNameUpd))
	ret, err = GetFwPolicy(testFwPolicyNamespace, testFwPolicyID)
	assert.Nil(t, err)
	assert.Equal(t, ret, testFwPolicyNameUpd)

	assert.Nil(t, DeleteFwPolicy(testFwPolicyNamespace, testFwPolicyID))
	_, err = GetFwPolicy(testFwPolicyNamespace, testFwPolicyID)
	assert.NotNil(t, err)
}

func TestErrNewFwPolicy(t *testing.T) {
	err := NewFwPolicy(testFwPolicyNamespace, testFwPolicyID, testFwPolicyNoExist)
	assert.Nil(t, err)

	err = NewFwPolicy(testFwPolicyNamespace, testFwPolicyID, testFwPolicyNoExist)
	assert.NotNil(t, err)
	assert.ErrorIs(t, err, ErrFwPolicyExists)

	assert.Nil(t, DeleteFwPolicy(testFwPolicyNamespace, testFwPolicyID))
	assert.Nil(t, DeleteFwPolicy(testFwPolicyNamespace, testFwPolicyID))
}

func TestErrUpdateFwPolicy(t *testing.T) {
	assert.Nil(t, UpdateFwPolicy(testFwPolicyNamespace, testFwPolicyID, testFwPolicyNameUpd))
}
