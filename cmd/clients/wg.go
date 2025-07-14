// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package clients

import (
	"github.com/cylonix/wg_agent"
)

type WgConfig struct {
	Name string `json:"name"`
	FQDN string `json:"restAPI"`
}

type WgState struct {
	WgConfig
	Client  *wg_agent.APIClient
	Offline bool
}

func NewWgClients(configs []*WgConfig) []*WgState {
	var s []*WgState
	for _, c := range configs {
		cfg := wg_agent.NewConfiguration()
		cfg.Servers[0].URL = c.FQDN + "/v1"
		cfg.Scheme = "http"
		w := &WgState{Client: wg_agent.NewAPIClient(cfg), WgConfig: *c}
		s = append(s, w)
	}
	return s
}
