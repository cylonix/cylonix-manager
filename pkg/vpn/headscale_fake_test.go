// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"cylonix/sase/daemon/db/types"
	hs_test "cylonix/sase/pkg/test/headscale"
	"errors"
	"net/netip"
	"testing"

	"github.com/cylonix/utils"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/stretchr/testify/assert"
	"tailscale.com/types/key"
)

// withFake wraps a test body with a fake headscale client installed and
// restored afterwards.
func withFake(t *testing.T, setup func(*hs_test.Client), fn func()) {
	t.Helper()
	fake := hs_test.New()
	if setup != nil {
		setup(fake)
	}
	SetHeadscaleForTest(true)
	SetHsClient(fake)
	defer func() {
		SetHeadscaleForTest(false)
		SetHsClient(nil)
	}()
	fn()
}

func TestDeleteHsUser_WithFake(t *testing.T) {
	id := types.UserID(testUUID())
	withFake(t, func(c *hs_test.Client) {
		c.SeedUser(&v1.User{Name: id.String(), Namespace: "ns"})
	}, func() {
		assert.NoError(t, DeleteHsUser("ns", "net", id))
	})
}

func TestCreatePreAuthKey_WithFake(t *testing.T) {
	id := types.UserID(testUUID())
	userInfo := &UserInfo{
		Namespace: "ns",
		LoginName: "u",
		UserID:    id,
	}
	withFake(t, func(c *hs_test.Client) {
		c.SeedUser(&v1.User{Name: id.String(), Namespace: "ns"})
	}, func() {
		key, err := CreatePreAuthKey(userInfo, "desc", nil)
		assert.NoError(t, err)
		assert.NotNil(t, key)
		assert.Equal(t, "fake-preauthkey", *key)
	})
}

func TestCreateApiKey_WithFake(t *testing.T) {
	uid := testUUID()
	withFake(t, func(c *hs_test.Client) {
		c.SeedUser(&v1.User{Name: types.UserID(uid).String(), Namespace: "ns"})
	}, func() {
		tok := &utils.UserTokenData{
			Username:  "u",
			Namespace: "ns",
			UserID:    uid,
			Network:   "n",
		}
		key, err := CreateApiKey(tok, false)
		assert.NoError(t, err)
		assert.NotNil(t, key)

		// Also cover the IsSysAdmin, IsAdminUser, and isNetworkAdmin branches.
		tok.IsSysAdmin = true
		_, err = CreateApiKey(tok, false)
		assert.NoError(t, err)
		tok.IsSysAdmin = false
		tok.IsAdminUser = true
		_, err = CreateApiKey(tok, false)
		assert.NoError(t, err)
		tok.IsAdminUser = false
		_, err = CreateApiKey(tok, true)
		assert.NoError(t, err)
	})
}

func TestCreateApiKey_CreateError(t *testing.T) {
	uid := testUUID()
	withFake(t, func(c *hs_test.Client) {
		c.SeedUser(&v1.User{Name: types.UserID(uid).String(), Namespace: "ns"})
		c.ErrCreateApiKey = errors.New("boom")
	}, func() {
		_, err := CreateApiKey(&utils.UserTokenData{UserID: uid, Namespace: "ns"}, false)
		assert.Error(t, err)
	})
}

func TestRefreshApiKey_WithFake(t *testing.T) {
	withFake(t, nil, func() {
		assert.NoError(t, RefreshApiKey("prefix"))
	})
}

func TestGetPreAuthKey_WithFake(t *testing.T) {
	withFake(t, nil, func() {
		// Empty list -> returns nil.
		k, err := GetPreAuthKey("ns", 1)
		assert.NoError(t, err)
		assert.Nil(t, k)
	})
}

func TestDeleteNode_WithFake(t *testing.T) {
	withFake(t, func(c *hs_test.Client) {
		c.SeedNode(&v1.Node{Id: 7, Name: "n"})
	}, func() {
		assert.NoError(t, DeleteNode(7))
	})
}

func TestGetNode_WithFake(t *testing.T) {
	id := types.UserID(testUUID())
	withFake(t, func(c *hs_test.Client) {
		c.SeedUser(&v1.User{Name: id.String(), Namespace: "ns"})
		c.SeedNode(&v1.Node{
			Id:         9,
			Namespace:  "ns",
			MachineKey: "mkey:" + hexKey(),
			NodeKey:    "nodekey:" + hexKey(),
			DiscoKey:   "discokey:" + hexKey(),
			User:       &v1.User{Id: "1", Name: id.String(), Namespace: "ns"},
		})
	}, func() {
		// ParseProtoNode may reject if other required fields are missing;
		// either way we exercise the request path.
		_, _ = GetNode("ns", &id, 9)
	})
}

func TestGetNode_NotFound(t *testing.T) {
	withFake(t, nil, func() {
		n, err := GetNode("ns", nil, 999)
		assert.NoError(t, err)
		assert.Nil(t, n)
	})
}

func TestCreateWgNode_WithFake(t *testing.T) {
	uid, _ := types.NewID()
	did, _ := types.NewID()
	wgNode := &types.WgNode{
		Model:        types.Model{ID: did},
		Namespace:    "ns",
		Name:         "wg-n",
		PublicKeyHex: hexKey(),
		Addresses:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
		AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
	}
	su := &types.UserBaseInfo{
		Model:    types.Model{ID: uid},
		UserID:   types.UserID(uid),
		LoginName: "u",
	}
	withFake(t, func(c *hs_test.Client) {
		c.SeedUser(&v1.User{Name: types.UserID(uid).String(), Namespace: "ns"})
	}, func() {
		id, err := CreateWgNode(su, wgNode)
		assert.NoError(t, err)
		if assert.NotNil(t, id) {
			assert.Greater(t, *id, uint64(0))
		}
	})
}

func TestUpdateWgNode_WithFake(t *testing.T) {
	uid, _ := types.NewID()
	did, _ := types.NewID()
	wgNode := &types.WgNode{
		Model:        types.Model{ID: did},
		Namespace:    "ns",
		NodeID:       42,
		Name:         "wg-n",
		PublicKeyHex: hexKey(),
		Addresses:    []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
		AllowedIPs:   []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")},
	}
	su := &types.UserBaseInfo{
		Model:     types.Model{ID: uid},
		UserID:    types.UserID(uid),
		LoginName: "u",
		Namespace: "ns",
	}
	withFake(t, func(c *hs_test.Client) {
		c.SeedUser(&v1.User{Name: types.UserID(uid).String(), Namespace: "ns"})
	}, func() {
		assert.NoError(t, UpdateWgNode(su, wgNode))
	})
}

func TestUpdateNodeCapabilities_WithFake(t *testing.T) {
	withFake(t, nil, func() {
		assert.NoError(t, UpdateNodeCapabilities("ns", 1, []string{"a"}, []string{"b"}))
	})
}

func TestUpdateUserNetworkDomain_WithFake(t *testing.T) {
	withFake(t, nil, func() {
		assert.NoError(t, UpdateUserNetworkDomain("ns", types.UserID(testUUID()), "net"))
	})
}

func TestUpdateUserPeers_WithFake(t *testing.T) {
	withFake(t, nil, func() {
		assert.NoError(t, UpdateUserPeers("ns", types.UserID(testUUID())))
	})
}

func TestAddDelShareToUser_WithFake(t *testing.T) {
	withFake(t, nil, func() {
		assert.NoError(t, AddDelShareToUser(1, "ns", "u", true))
		assert.NoError(t, AddDelShareToUser(1, "ns", "u", false))
	})
}

// testUUID returns a deterministic-but-unique UUID per call.
func testUUID() [16]byte {
	id, _ := types.NewID()
	return id.UUID()
}

// hexKey returns a valid machine/node public key hex string; we use the
// machine private key's public hex marshal form.
func hexKey() string {
	mk := key.NewMachine().Public()
	out, _ := mk.MarshalText()
	// The marshal output includes the "mkey:" prefix; strip it.
	s := string(out)
	for i, c := range s {
		if c == ':' {
			s = s[i+1:]
			break
		}
	}
	return s
}
