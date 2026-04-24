// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgclient_test

import (
	"context"
	"errors"
	"testing"

	"github.com/cylonix/wg_agent"
	"github.com/stretchr/testify/assert"
)

func TestEmulator_CreateAndDelete(t *testing.T) {
	e := &Emulator{}
	assert.NoError(t, e.CreateUsers(context.Background(), "ns", nil))
	assert.NoError(t, e.CreateUser(context.Background(), "ns", "u", "wid", "did", "pk", nil))
	assert.NoError(t, e.DeleteUser(context.Background(), "ns", "u", "wid", "did", "pk"))

	e.CreateUserError = errors.New("x")
	assert.Error(t, e.CreateUsers(context.Background(), "ns", nil))
	assert.Error(t, e.CreateUser(context.Background(), "ns", "u", "w", "d", "p", nil))

	e.DeleteUserError = errors.New("x")
	assert.Error(t, e.DeleteUser(context.Background(), "ns", "u", "w", "d", "p"))
}

func TestEmulator_GetAllUserStats(t *testing.T) {
	e := &Emulator{
		OnlineUserStats:  []wg_agent.WgUserStats{{Name: "a"}},
		OfflineUserStats: []wg_agent.WgUserStats{{Name: "b"}},
	}
	list, err := e.GetAllUserStats(context.Background(), "ns")
	assert.NoError(t, err)
	assert.Len(t, list, 2)
}

func TestEmulator_GetUserDetail(t *testing.T) {
	pk := "pk"
	e := &Emulator{
		UserDetails: []wg_agent.WgUserDetail{
			{Name: "u", ID: "w", DeviceID: "d", Pubkey: &pk},
		},
	}
	d, err := e.GetUserDetail(context.Background(), "ns", "u", "w", "d", "pk")
	assert.NoError(t, err)
	assert.NotNil(t, d)

	_, err = e.GetUserDetail(context.Background(), "ns", "missing", "w", "d", "pk")
	assert.Error(t, err)
}

func TestEmulator_ListNamespaces(t *testing.T) {
	e := &Emulator{
		NamespaceDetails: map[string][]wg_agent.WgNamespaceDetail{
			"ns": {{Name: "a"}},
		},
	}
	list, err := e.ListNamespaces(context.Background(), "ns")
	assert.NoError(t, err)
	assert.Len(t, list, 1)

	_, err = e.ListNamespaces(context.Background(), "missing")
	assert.Error(t, err)
}
