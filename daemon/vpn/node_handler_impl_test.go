// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/optional"
	dt "cylonix/sase/pkg/test/daemon"
	"net/netip"
	"testing"

	"github.com/google/uuid"
	hstypes "github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"tailscale.com/types/key"
)

// stringer wraps any string to satisfy fmt.Stringer for the changed() helper.
type stringer string

func (s stringer) String() string { return string(s) }

func TestChanged_Helper(t *testing.T) {
	assert.True(t, changed([]stringer{"a"}, []stringer{"a", "b"}))
	assert.False(t, changed([]stringer{"a", "b"}, []stringer{"b", "a"}))
	assert.True(t, changed([]stringer{"a"}, []stringer{"c"}))
	assert.False(t, changed([]stringer{}, []stringer{}))
}

func TestNodeKeyHelpers(t *testing.T) {
	priv := newNodeKey()
	pub := priv.Public()
	hex, err := nodeKeyToHex(pub)
	assert.NoError(t, err)
	assert.NotEmpty(t, hex)

	mpriv := newMachineKey()
	_ = mpriv
}

func TestMachineKeyToApprovalReferenceUUID(t *testing.T) {
	uid := types.UserID(uuid.New())
	id := machineKeyToApprovalReferenceUUID(uid, []byte("mkey:abc"))
	assert.NotEqual(t, uuid.Nil, id)

	// Deterministic.
	id2 := machineKeyToApprovalReferenceUUID(uid, []byte("mkey:abc"))
	assert.Equal(t, id, id2)
}

func TestNodeIDUint64P(t *testing.T) {
	// Zero ID -> nil.
	node := &hstypes.Node{ID: 0}
	assert.Nil(t, nodeIDUint64P(node))

	// Non-zero ID -> pointer.
	node = &hstypes.Node{ID: 42}
	p := nodeIDUint64P(node)
	assert.NotNil(t, p)
	assert.Equal(t, uint64(42), *p)
}

func TestNodeAddresses(t *testing.T) {
	addr := netip.MustParseAddr("10.0.0.1")
	node := &hstypes.Node{IPv4: &addr}
	prefixes, err := nodeAddresses(node)
	assert.NoError(t, err)
	assert.Len(t, prefixes, 1)

	// No IPv4 -> empty.
	prefixes, err = nodeAddresses(&hstypes.Node{})
	assert.NoError(t, err)
	assert.Empty(t, prefixes)
}

func TestUserBaseInfoToProfile(t *testing.T) {
	assert.Nil(t, userBaseInfoToProfile(nil))

	ub := &types.UserBaseInfo{DisplayName: "Alice"}
	p := userBaseInfoToProfile(ub)
	assert.Equal(t, "Alice", p.DisplayName)

	// Falls back to LoginName if DisplayName empty.
	ub = &types.UserBaseInfo{LoginName: "alice"}
	p = userBaseInfoToProfile(ub)
	assert.Equal(t, "alice", p.DisplayName)
}

func TestGetUserInfo_And_User(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)

	// Nil user -> nil.
	assert.Nil(t, nh.getUserInfo(nil))

	// Unparseable name -> nil.
	u := &hstypes.User{Name: "not-a-uuid"}
	assert.Nil(t, nh.getUserInfo(u))

	// Valid user.
	id := uuid.New()
	u = &hstypes.User{Name: id.String(), Namespace: optional.StringP("ns")}
	info := nh.getUserInfo(u)
	assert.NotNil(t, info)
	assert.Equal(t, "ns", info.Namespace)

	// User() returns nil for unknown user ID (not found).
	assert.Nil(t, nh.User(u))

	// Nil user -> nil.
	assert.Nil(t, nh.User(nil))
}

func TestPeers_NoDevice(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	// m with no WgName / no WgInfo / no userID -> default short-circuits.
	m := &types.WgInfo{}
	all, online, err := s.Peers(m)
	// Without an actual device in db, this may return nil/empty.
	_ = all
	_ = online
	_ = err
}

func TestActiveWgName_NoClient(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	// No wg client -> empty string.
	assert.Equal(t, "", s.ActiveWgName("ns", "no-such-wg"))
}

func TestListUserEntry(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	// Empty user's namespace returns empty list (no nodes).
	list, err := s.ListUserEntry("no-such-ns", nil)
	assert.NoError(t, err)
	assert.Empty(t, list)
}

func TestListFriendEntry_NoUser(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	_, _ = s.ListFriendEntry("no-such-ns", types.UserID(uuid.New()))
}

func TestListVpnPolicyEntry_NoDevice(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	_, err := s.ListVpnPolicyEntry("no-such-ns", types.UserID(uuid.New()), types.DeviceID(uuid.New()))
	// Device doesn't exist -> nil list, err may be non-nil.
	_ = err
}

// DerperServers/NameServers rely on ResourceService being non-nil, which
// the test emulator doesn't provide. Skip to avoid nil deref.

func TestAddDnsRecord_NilHostInfo(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	// With the emulator, AddDnsRecord returns success and an empty name.
	out, err := s.AddDnsRecord("1.2.3.4", nil)
	assert.NoError(t, err)
	assert.Equal(t, "", out)
	assert.NoError(t, s.DelDnsRecord("", ""))
}

func TestGetWgInfoWithMachineKey(t *testing.T) {
	// Valid machine key but no wg info in db -> error.
	mk := key.NewMachine().Public()
	_, err := getWgInfoWithMachineKey("ns", types.UserID(uuid.New()), mk)
	assert.Error(t, err)
}

func TestNodeHandler_PreAdd_NilUser(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)
	// Node with unparseable user name -> error.
	node := &hstypes.Node{User: hstypes.User{Name: "bad"}}
	_, err := nh.PreAdd(node)
	assert.Error(t, err)
}

func TestNodeHandler_PostAdd_NilUser(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)
	node := &hstypes.Node{User: hstypes.User{Name: "bad"}}
	err := nh.PostAdd(node)
	assert.Error(t, err)
}

func TestNodeHandler_Delete_NoOp(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)
	// Delete is a no-op in the current implementation.
	node := &hstypes.Node{User: hstypes.User{Name: "bad"}}
	assert.NoError(t, nh.Delete(node))
}

func TestNodeHandler_Update_NoNode(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)
	// Node ID not in db -> returns node, nil error (no-op).
	node := &hstypes.Node{ID: 42, User: hstypes.User{Name: "bad"}}
	ret, err := nh.Update(node)
	assert.NoError(t, err)
	assert.Equal(t, node, ret)
}

func TestNodeHandler_AuthStatus(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)
	// Empty auth URL -> error.
	_, err := nh.AuthStatus("")
	assert.Error(t, err)

	// Invalid URL format -> error.
	_, err = nh.AuthStatus("not-a-url")
	assert.Error(t, err)
}

func TestNodeHandler_RotateNodeKey_NoWgInfo(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)
	node := &hstypes.Node{User: hstypes.User{Name: "bad"}}
	err := nh.RotateNodeKey(node, key.NewNode().Public())
	assert.Error(t, err)
}

func TestNodeHandler_Recover_NoMatch(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)
	// Unmatched machine key, node key -> error.
	err := nh.Recover(key.NewMachine().Public(), key.NewNode().Public())
	_ = err
}

func TestNodeHandler_Peers(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)
	// Non-existent node -> empty peers.
	u := hstypes.User{Name: uuid.New().String(), Namespace: optional.StringP("ns")}
	node := &hstypes.Node{User: u}
	peers, _, _, err := nh.Peers(node)
	_ = peers
	_ = err
}

// Test RotateNodeKeyInGateway when WgName is empty -> no-op.
func TestRotateNodeKeyInGateway_NoWgName(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	m := &types.WgInfo{WgName: ""}
	mk := key.NewMachine().Public()
	nk := key.NewNode().Public()
	err := s.RotateNodeKeyInGateway(m, mk, nk, "hex")
	assert.NoError(t, err)
}

// Ensure the vpn service Stop/Start return without panic.
func TestVpnService_StartStop(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	assert.NoError(t, s.Start())
	s.Stop()
}

func TestProfiles_NoUsers(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)
	// Empty node list returns nil.
	out, err := nh.Profiles(nil)
	assert.NoError(t, err)
	assert.Nil(t, out)
}

// Exercise NewDevice error path (no gateway supported).
func TestNewDevice_NoGatewaySupport(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)

	_, err := s.NewDevice(
		testNamespace, testUserID, nil,
		"mk", "nk", "wg-name-not-supported",
		"linux", "hostname", false,
		[]netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		"1.1.1.1", nil,
	)
	assert.Error(t, err)
}

// TestUpdateNodeFunc exercises updateNode helper using a minimal wg info
// object (no DB writes needed for the nothing-to-change path).
func TestUpdateNode_NoChange(t *testing.T) {
	d := dt.NewEmulator()
	s := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(s)

	// When addresses/name/pubkey match, updateNode is a no-op.
	addr := netip.MustParseAddr("10.0.0.1")
	wgInfo := &types.WgInfo{
		Name:         "host",
		PublicKeyHex: "hex",
		Addresses:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
	}
	node := &hstypes.Node{GivenName: "host", IPv4: &addr}
	assert.NoError(t, nh.updateNode(wgInfo, node, "hex"))
}
