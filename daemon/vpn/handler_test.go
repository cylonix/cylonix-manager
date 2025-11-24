// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/pkg/fwconfig"
	dt "cylonix/sase/pkg/test/daemon"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDevice(t *testing.T) {
	d := dt.NewEmulator()
	f := fwconfig.NewServiceEmulator()
	h := NewService(d, f, testLogger)
	var (
		namespace  = testNamespace
		userID     = testUserID
		ip         = netip.MustParsePrefix("100.64.0.1/32")
		machineKey = "test-machine-key"
		nodeKeyHex = "test-node-key"
		nodeID     = uint64(1)
	)
	device, err := h.NewDevice(
		namespace, userID, &nodeID, machineKey, nodeKeyHex, "", "linux", "test-pc",
		false, []netip.Prefix{ip}, "11.0.0.1", nil,
	)
	if !assert.Nil(t, err) || !assert.NotNil(t, device) {
		return
	}
	v, err := db.GetUserDeviceFast(namespace, userID, device.ID)
	assert.Nil(t, err)
	if assert.NotNil(t, v) && assert.NotNil(t, v.IP()) {
		assert.Equal(t, *v.IP(), ip.Addr().String())
	}
	w, err := db.GetWgInfoOfDevice(namespace, device.ID)
	assert.Nil(t, err)
	if assert.NotNil(t, w) && assert.NotNil(t, v.IP()) {
		assert.Equal(t, *w.IP(), ip.Addr().String())
	}
	w, err = db.WgInfoByMachineKey(namespace, userID, machineKey)
	assert.Nil(t, err)
	if assert.NotNil(t, w) && assert.NotNil(t, v.IP()) {
		assert.Equal(t, *w.IP(), ip.Addr().String())
	}
}
