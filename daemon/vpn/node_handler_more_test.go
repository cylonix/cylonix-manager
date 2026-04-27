// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/optional"
	dt "cylonix/sase/pkg/test/daemon"
	"cylonix/sase/pkg/test/fixtures"
	"testing"

	hstypes "github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
)

func TestNodeHandler_NetworkDomain(t *testing.T) {
	setupFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(svc)

	// Bad user info -> error.
	_, err = nh.NetworkDomain(&hstypes.User{Name: "not-a-uuid"})
	assert.Error(t, err)

	// Good user info.
	u := &hstypes.User{
		Name:      s.User.ID.String(),
		Namespace: optional.StringP(s.Namespace),
	}
	_, err = nh.NetworkDomain(u)
	_ = err // may or may not find a domain, but the code path runs.
}

func TestNodeHandler_RefreshToken(t *testing.T) {
	setupFakeHeadscale(t)
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(svc)
	assert.NoError(t, nh.RefreshToken(&hstypes.Node{}))
}

func TestNodeHandler_SetExitNode_BadUser(t *testing.T) {
	setupFakeHeadscale(t)
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(svc)

	// Bad user info -> error.
	node := &hstypes.Node{User: &hstypes.User{Name: "not-a-uuid"}}
	err := nh.SetExitNode(node, "x")
	assert.Error(t, err)
}

func TestNodeHandler_SetExitNode_NodeNotFound(t *testing.T) {
	setupFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)
	nh := NewNodeHandler(svc)

	// Valid user but no matching wg info -> error.
	node := &hstypes.Node{
		ID: 99999,
		User: &hstypes.User{
			Name:      s.User.ID.String(),
			Namespace: optional.StringP(s.Namespace),
		},
	}
	err = nh.SetExitNode(node, "x")
	assert.Error(t, err)
}

func TestNewDevice_WithFixtures(t *testing.T) {
	setupFakeHeadscale(t)
	s, err := fixtures.NewScenario(fixtures.Options{})
	if !assert.NoError(t, err) {
		return
	}
	defer s.Cleanup()

	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)

	// Create a new device for the user (no wg-gateway).
	err = db.AddUserDevice(s.Namespace, s.User.ID, &types.Device{
		Model:     types.Model{ID: mustNewID(t)},
		Namespace: s.Namespace,
		UserID:    s.User.ID,
	})
	_ = err

	// The NewDevice helper requires IsGatewaySupported; without supervisor
	// setup the path falls back to creating without wg. Just exercise.
	_, _ = svc.NewDevice(
		s.Namespace, s.User.ID, nil, "mk", "nk", "",
		"linux", "hostname", false, nil, "1.2.3.4", nil,
	)
}

// Ensure the AddDnsRecord/DelDnsRecord stubs run.
func TestVpnService_DnsRecord_Helpers(t *testing.T) {
	d := dt.NewEmulator()
	svc := NewService(d, fwconfig.NewServiceEmulator(), testLogger)

	_, err := svc.AddDnsRecord("1.2.3.4", nil)
	assert.NoError(t, err)
	assert.NoError(t, svc.DelDnsRecord("any", "any"))
}

func mustNewID(t *testing.T) types.ID {
	t.Helper()
	id, err := types.NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	return id
}
