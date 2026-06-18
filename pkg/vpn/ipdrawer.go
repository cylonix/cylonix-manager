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
	return AllocateIP(optional.String(user.Namespace), user.Name, machineKey.String(), v4, v6)
}

func AllocateIP(namespace, userID, machineKey string, v4 *netip.Addr, v6 *netip.Addr) (*netip.Addr, *netip.Addr, error) {
	hash := uuid.NewSHA1(uuid.Nil, []byte(userID+machineKey)).String()
	ip, err := ipdrawer.AllocateIPAddr(namespace, "", hash, v4)
	if err != nil {
		return nil, nil, err
	}
	v4Addr, err := netip.ParseAddr(ip)
	if err != nil {
		ipdrawer.ReleaseIPAddr(namespace, "", ip)
		return nil, nil, err
	}

	// Allocate the v6 address from the v6 pool using the same hash so the v4
	// and v6 reservations stay correlated in ipdrawer. Release the v4 if v6
	// allocation fails so we don't leak it.
	v6Addr, err := allocateIPv6(namespace, hash, v6)
	if err != nil {
		ipdrawer.ReleaseIPAddr(namespace, "", v4Addr.String())
		return nil, nil, err
	}
	return &v4Addr, &v6Addr, nil
}

// AllocateIPv6 allocates only an IPv6 address for an existing node, used to
// backfill a v6 address for devices that were assigned a v4 address before v6
// support existed. It uses the same uuid hash as AllocateIP so the v6
// reservation correlates with the node's existing v4 reservation.
func AllocateIPv6(namespace, userID, machineKey string) (*netip.Addr, error) {
	hash := uuid.NewSHA1(uuid.Nil, []byte(userID+machineKey)).String()
	v6Addr, err := allocateIPv6(namespace, hash, nil)
	if err != nil {
		return nil, err
	}
	return &v6Addr, nil
}

func allocateIPv6(namespace, hash string, want *netip.Addr) (netip.Addr, error) {
	ip, err := ipdrawer.AllocateIPv6Addr(namespace, "", hash, want)
	if err != nil {
		return netip.Addr{}, err
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		ipdrawer.ReleaseIPAddr(namespace, "", ip)
		return netip.Addr{}, err
	}
	return addr, nil
}

func ReleaseIP(namespace, ip string) error {
	return ipdrawer.ReleaseIPAddr(namespace, "", ip)
}

func (i *IPDrawer) NextV4(*hstypes.User) (*netip.Addr, error) { return nil, nil }
func (i *IPDrawer) NextV6(*hstypes.User) (*netip.Addr, error) { return nil, ErrNotSupported }
func (i *IPDrawer) PrefixV4(*hstypes.User) *netip.Prefix      { return nil }
func (i *IPDrawer) PrefixV6(*hstypes.User) *netip.Prefix      { return nil }
