// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"cylonix/sase/pkg/optional"
	"errors"
	"net/netip"

	"github.com/cylonix/utils/ipdrawer"
	"github.com/google/uuid"
	hstypes "github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/types/key"
)

type IPDrawer struct{}

var (
	ErrNotSupported = errors.New("not supported")
)

func newIPAllocator() *IPDrawer {
	return &IPDrawer{}
}

// IP drawer implements the IPAllocator interface
func (i *IPDrawer) FreeFor(ip *netip.Addr, user *hstypes.User, machineKey *key.MachinePublic) error {
	if ip == nil {
		return nil
	}
	return ipdrawer.ReleaseIPAddr(optional.String(user.Namespace), "", ip.String())
}
func (i *IPDrawer) NextFor(user *hstypes.User, machineKey *key.MachinePublic, v4 *netip.Addr, v6 *netip.Addr) (*netip.Addr, *netip.Addr, error) {
	hash := uuid.NewSHA1(uuid.Nil, []byte(user.Name + machineKey.String())).String()
	ip, err := ipdrawer.AllocateIPAddr(optional.String(user.Namespace), "", hash, v4)
	if err != nil {
		return nil, nil, err
	}
	ipAddr, err := netip.ParseAddr(ip)
	if err != nil {
		ipdrawer.ReleaseIPAddr(optional.String(user.Namespace), "", ip)
	}
	return &ipAddr, nil, nil
}

func (i *IPDrawer) NextV4(*hstypes.User) (*netip.Addr, error) { return nil, nil }
func (i *IPDrawer) NextV6(*hstypes.User) (*netip.Addr, error) { return nil, ErrNotSupported }
func (i *IPDrawer) PrefixV4(*hstypes.User) *netip.Prefix      { return nil }
func (i *IPDrawer) PrefixV6(*hstypes.User) *netip.Prefix      { return nil }
