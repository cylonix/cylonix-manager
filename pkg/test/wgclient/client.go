// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wgclient_test

import (
	"context"
	"cylonix/sase/daemon/db/types"
	"errors"
	"time"

	"github.com/cylonix/wg_agent"
)

type Emulator struct {
	OnlineUserStats  []wg_agent.WgUserStats
	OfflineUserStats []wg_agent.WgUserStats
	UserDetails      []wg_agent.WgUserDetail
	CreateUserError  error
	DeleteUserError  error
	NamespaceDetails map[string][]wg_agent.WgNamespaceDetail
}

func (e *Emulator) CreateUsers(ctx context.Context, namespace string, users []*types.WgInfo) error {
	return e.CreateUserError
}

func (e *Emulator) CreateUser(ctx context.Context, namespace, username, wgUserID, deviceID, publicKey string, allowedIPs []string) error {
	return e.CreateUserError
}

func (e *Emulator) DeleteUser(ctx context.Context, namespace, username, wgUserID, deviceID, publicKey string) error {
	return e.DeleteUserError
}

func (e *Emulator) GetAllUserStats(ctx context.Context, namespace string) ([]wg_agent.WgUserStats, error) {
	var list []wg_agent.WgUserStats
	for _, u := range e.OnlineUserStats {
		u.LastHandshakeTime = time.Now().Unix()
		list = append(list, u)
	}
	return append(list, e.OfflineUserStats...), nil
}

func (e *Emulator) GetUserDetail(ctx context.Context, namespace, username, wgUserID, deviceID, publicKey string) (*wg_agent.WgUserDetail, error) {
	for _, u := range e.UserDetails {
		if u.Name == username && u.ID == wgUserID && u.DeviceID == deviceID && u.Pubkey != nil && *u.Pubkey == publicKey {
			return &u, nil
		}
	}
	return nil, errors.New("device does not exists")
}

func (e *Emulator) ListNamespaces(ctx context.Context, namespace string) ([]wg_agent.WgNamespaceDetail, error) {
	if v, ok := e.NamespaceDetails[namespace]; ok {
		return v, nil
	}
	return nil, errors.New("namespace detail does not exist")
}
