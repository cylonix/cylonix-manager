// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipdrawer

import "net/netip"

type IPDrawerEmulator struct {
	ipdUrl string
}

func NewIPDrawerEmulator() (*IPDrawerEmulator, error) {
	return &IPDrawerEmulator{}, nil
}
func (ipDrawer *IPDrawerEmulator) InitIPdrawer() error {
	ipDrawer.ipdUrl = "http://127.0.0.1:25577"
	return nil
}
func (ipDrawer *IPDrawerEmulator) AllocateIPAddr(namespace, popName, uuid string, want *netip.Addr) (string, error) {
	return "127.0.0.1", nil
}
func (ipDrawer *IPDrawerEmulator) ReleaseIPAddr(namespace, popName, ip string) error {
	return nil
}
