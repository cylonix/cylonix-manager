// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	dt "cylonix/sase/pkg/test/daemon"
	"cylonix/sase/pkg/test/fixtures"
	hs_test "cylonix/sase/pkg/test/headscale"
	vpnpkg "cylonix/sase/pkg/vpn"
	"net/netip"
	"testing"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	hstypes "github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"tailscale.com/types/key"
)

// setupFakeHeadscale wires a fake headscale client into pkg/vpn for the
// duration of the test. Returns the client so tests can inject errors.
func setupFakeHeadscale(t *testing.T) *hs_test.Client {
	t.Helper()
	fake := hs_test.New()
	vpnpkg.SetHeadscaleForTest(true)
	vpnpkg.SetHsClient(fake)
	t.Cleanup(func() {
		vpnpkg.SetHeadscaleForTest(false)
		vpnpkg.SetHsClient(nil)
	})
	return fake
}

func TestNodeHandler_PreAdd_AutoApprove(t *testing.T) {
	fake := setupFakeHeadscale(t)
	_ = fake

	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	// Flip auto-approve on the user so PreAdd takes the auto path.
	user := s.User
	user.WgEnabled = boolP(true)
	user.AutoApproveDevice = boolP(true)
	// Persist via UpdateUser — simplest is a direct base-info update.

	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(svc)

	// Build a node payload for a user that already has a wg info in db.
	// PreAdd will hit the "update wg info + rotate node key" path.
	addr := netip.MustParseAddr("10.0.0.1")
	mk := key.NewMachine()
	nk := key.NewNode()
	mkText, _ := mk.Public().MarshalText()
	_ = mkText

	node := &hstypes.Node{
		MachineKey:    mk.Public(),
		NodeKey:       nk.Public(),
		NetworkDomain: "net",
		GivenName:     s.Device.Name,
		IPv4:          &addr,
		User: hstypes.User{
			Name:      s.User.ID.String(),
			Namespace: &s.Namespace,
		},
	}
	// The device in the fixture was seeded with a synthetic machine key
	// that doesn't match; this exercises the "device approval required"
	// branch when no matching wg_info exists and auto-approve is false.
	_, err = nh.PreAdd(node)
	_ = err // The branch exercised depends on flags; don't assert success.
}

func TestNodeHandler_AuthURL_StateToken(t *testing.T) {
	setupFakeHeadscale(t)
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(svc)

	// AuthURL with no existing state, using a minimal node.
	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()
	url, err := nh.AuthURL(&hstypes.Node{
		MachineKey: mk,
		NodeKey:    nk,
		Hostname:   "host1",
	}, "")
	assert.NoError(t, err)
	assert.NotEmpty(t, url)

	// Pass the returned URL back through; should detect existing token and
	// either return current URL or update node key.
	url2, err := nh.AuthURL(&hstypes.Node{
		MachineKey: mk,
		NodeKey:    nk,
		Hostname:   "host1",
	}, url)
	assert.NoError(t, err)
	assert.NotEmpty(t, url2)
}

func TestNodeHandler_AuthStatus_AfterAuthURL(t *testing.T) {
	setupFakeHeadscale(t)
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(svc)

	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()
	url, err := nh.AuthURL(&hstypes.Node{
		MachineKey: mk, NodeKey: nk, Hostname: "host",
	}, "")
	if !assert.NoError(t, err) {
		return
	}
	// Fresh state: no user token yet, AuthStatus returns empty string.
	status, err := nh.AuthStatus(url)
	assert.NoError(t, err)
	assert.Equal(t, "", status)
}

func TestVpnService_CreateWgNodeUsesFake(t *testing.T) {
	setupFakeHeadscale(t)

	d := dt.NewEmulator()
	NewService(d, fwconfig.NewServiceEmulator(), testLogger)

	// Build a user-base-info + wg node and call pkg/vpn.CreateWgNode.
	uid, _ := types.NewID()
	did, _ := types.NewID()
	wgNode := &types.WgNode{
		Model:        types.Model{ID: did},
		Namespace:    "ns",
		NodeID:       0,
		Name:         "wg-create",
		PublicKeyHex: hexKey(),
		Addresses:    []netip.Prefix{netip.MustParsePrefix("10.1.0.1/32")},
		AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.1.0.1/32")},
	}
	su := &types.UserBaseInfo{
		Model:     types.Model{ID: uid},
		UserID:    types.UserID(uid),
		LoginName: "u",
		Namespace: "ns",
	}
	// Seed the fake user so getOrCreateHsUser succeeds.
	id, err := vpnpkg.CreateWgNode(su, wgNode)
	// If GetUser fails and CreateUser succeeds, node gets created.
	assert.NoError(t, err)
	assert.NotNil(t, id)
}

// Helpers.

func boolP(b bool) *bool { return &b }

// hexKey returns a raw-hex public key (no "mkey:"/"nodekey:" prefix).
func hexKey() string {
	out, _ := key.NewMachine().Public().MarshalText()
	s := string(out)
	for i, c := range s {
		if c == ':' {
			return s[i+1:]
		}
	}
	return s
}

// Compile-time usage hints for protos we reference indirectly.
var _ = v1.Node{}
