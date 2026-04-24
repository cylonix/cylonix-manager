// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserInfo_NodeUser(t *testing.T) {
	var nilU *UserInfo
	u, err := nilU.NodeUser()
	assert.NoError(t, err)
	assert.Nil(t, u)

	id, idErr := types.NewID()
	assert.NoError(t, idErr)
	info := &UserInfo{
		UserID:    types.UserID(id),
		Namespace: "ns",
		LoginName: "user@example.com",
		Network:   "net1",
	}
	u, err = info.NodeUser()
	assert.NoError(t, err)
	assert.NotNil(t, u)
	assert.Equal(t, "ns", *u.Namespace)
	assert.Equal(t, "user@example.com", *u.LoginName)
	assert.Equal(t, id.String(), u.Name)
	assert.Equal(t, "net1", u.Network)
}
