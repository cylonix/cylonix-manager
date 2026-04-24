// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func withIgnoreInit(t *testing.T, ignore bool, fn func()) {
	t.Helper()
	prev := ignoreHeadscaleInitError
	SetIgnoreHeadscaleInitError(ignore)
	defer SetIgnoreHeadscaleInitError(prev)
	fn()
}

// Ensure every exported function returns ErrHeadscaleNotInitialized when
// headscale is nil AND returns no error when SetIgnoreHeadscaleInitError(true).
func TestHeadscaleFuncs_NotInitialized(t *testing.T) {
	// headscale is nil by default in tests.
	assert.Nil(t, headscale)
	userID := types.UserID(uuid.New())

	assert.ErrorIs(t, DeleteHsUser("ns", "net", userID), ErrHeadscaleNotInitialized)
	_, err := CreatePreAuthKey(&UserInfo{}, "desc", nil)
	assert.ErrorIs(t, err, ErrHeadscaleNotInitialized)
	_, err = CreateApiKey(&utils.UserTokenData{}, false)
	assert.ErrorIs(t, err, ErrHeadscaleNotInitialized)
	assert.ErrorIs(t, RefreshApiKey("p"), ErrHeadscaleNotInitialized)
	_, err = GetPreAuthKey("ns", 1)
	assert.ErrorIs(t, err, ErrHeadscaleNotInitialized)
	assert.ErrorIs(t, DeleteNode(1), ErrHeadscaleNotInitialized)
	_, err = GetNode("ns", &userID, 1)
	assert.ErrorIs(t, err, ErrHeadscaleNotInitialized)
	_, err = CreateWgNode(&types.UserBaseInfo{}, &types.WgNode{})
	assert.ErrorIs(t, err, ErrHeadscaleNotInitialized)
	assert.ErrorIs(t, UpdateWgNode(&types.UserBaseInfo{}, &types.WgNode{}), ErrHeadscaleNotInitialized)
	assert.ErrorIs(t, UpdateNodeCapabilities("ns", 1, nil, nil), ErrHeadscaleNotInitialized)
	assert.ErrorIs(t, UpdateUserNetworkDomain("ns", userID, "n"), ErrHeadscaleNotInitialized)
	assert.ErrorIs(t, UpdateUserPeers("ns", userID), ErrHeadscaleNotInitialized)
	assert.ErrorIs(t, AddDelShareToUser(1, "ns", "u", true), ErrHeadscaleNotInitialized)
	assert.ErrorIs(t, AddDelShareToUser(1, "ns", "u", false), ErrHeadscaleNotInitialized)
}

func TestHeadscaleFuncs_IgnoreInitError(t *testing.T) {
	withIgnoreInit(t, true, func() {
		assert.Nil(t, headscale)
		userID := types.UserID(uuid.New())

		assert.NoError(t, DeleteHsUser("ns", "net", userID))
		s, err := CreatePreAuthKey(&UserInfo{}, "desc", nil)
		assert.NoError(t, err)
		assert.Nil(t, s)
		s, err = CreateApiKey(&utils.UserTokenData{}, false)
		assert.NoError(t, err)
		assert.Nil(t, s)
		assert.NoError(t, RefreshApiKey("p"))
		k, err := GetPreAuthKey("ns", 1)
		assert.NoError(t, err)
		assert.Nil(t, k)
		assert.NoError(t, DeleteNode(1))
		node, err := GetNode("ns", &userID, 1)
		assert.NoError(t, err)
		assert.Nil(t, node)
		nid, err := CreateWgNode(&types.UserBaseInfo{}, &types.WgNode{})
		assert.NoError(t, err)
		assert.Nil(t, nid)
		assert.NoError(t, UpdateWgNode(&types.UserBaseInfo{}, &types.WgNode{}))
		assert.NoError(t, UpdateNodeCapabilities("ns", 1, nil, nil))
		assert.NoError(t, UpdateUserNetworkDomain("ns", userID, "n"))
		assert.NoError(t, UpdateUserPeers("ns", userID))
		assert.NoError(t, AddDelShareToUser(1, "ns", "u", true))
	})
}

func TestNewHsClientContext(t *testing.T) {
	ctx, cancel := newHsClientContext()
	defer cancel()
	assert.NotNil(t, ctx)
	dl, ok := ctx.Deadline()
	assert.True(t, ok)
	assert.False(t, dl.IsZero())
}
