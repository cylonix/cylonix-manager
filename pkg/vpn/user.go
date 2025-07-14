// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"cylonix/sase/daemon/db/types"

	hstypes "github.com/juanfont/headscale/hscontrol/types"
)

type UserInfo struct {
	UserID    types.UserID `json:"user_id"`
	Namespace string       `json:"namespace"`
	LoginName string       `json:"login_name"`
	Network   string       `json:"network"`
}

func (u *UserInfo) NodeUser() (*hstypes.User, error) {
	if u == nil {
		return nil, nil
	}
	return &hstypes.User{
		Namespace: &u.Namespace,
		LoginName: &u.LoginName,
		Name:      u.UserID.String(),
		Network:   u.Network,
	}, nil
}
