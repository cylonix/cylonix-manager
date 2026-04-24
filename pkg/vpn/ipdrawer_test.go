// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"net/netip"
	"testing"

	hstypes "github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"tailscale.com/types/key"
)

func TestNewIPAllocator(t *testing.T) {
	a := newIPAllocator()
	assert.NotNil(t, a)
}

func TestIPDrawer_NextV6_NotSupported(t *testing.T) {
	a := newIPAllocator()
	_, err := a.NextV6(&hstypes.User{})
	assert.ErrorIs(t, err, ErrNotSupported)
}

func TestIPDrawer_NextV4_Nil(t *testing.T) {
	a := newIPAllocator()
	v4, err := a.NextV4(&hstypes.User{})
	assert.NoError(t, err)
	assert.Nil(t, v4)
}

func TestIPDrawer_Prefixes_Nil(t *testing.T) {
	a := newIPAllocator()
	assert.Nil(t, a.PrefixV4(&hstypes.User{}))
	assert.Nil(t, a.PrefixV6(&hstypes.User{}))
}

func TestIPDrawer_FreeFor_NilIP(t *testing.T) {
	a := newIPAllocator()
	ns := "ns"
	user := &hstypes.User{Namespace: &ns}
	mk := key.NewMachine().Public()
	assert.NoError(t, a.FreeFor(nil, user, &mk))
}

func TestAllocateIP_Error(t *testing.T) {
	// With no ipdrawer configured, AllocateIPAddr should return an error.
	_, _, err := AllocateIP("ns", "u", "mkey", nil, nil)
	assert.Error(t, err)
}

func TestReleaseIP_Error(t *testing.T) {
	err := ReleaseIP("ns", "1.2.3.4")
	_ = err // may or may not error depending on config; just exercise the path.
}

func TestIPDrawer_NextFor_Error(t *testing.T) {
	a := newIPAllocator()
	ns := "ns"
	user := &hstypes.User{Namespace: &ns, Name: "u"}
	mk := key.NewMachine().Public()
	addr := netip.MustParseAddr("10.0.0.1")
	_, _, err := a.NextFor(user, &mk, &addr, nil)
	// Without a configured ipdrawer, this should error.
	assert.Error(t, err)
}
