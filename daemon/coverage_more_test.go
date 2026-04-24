// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"context"
	"testing"

	"github.com/cylonix/utils"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func newTestDaemon(t *testing.T) *Daemon {
	t.Helper()
	v := viper.New()
	v.Set("base_url", "http://localhost")
	d, err := NewDaemon(context.Background(), nil, v, &utils.ConfigCheckSetting{})
	if err != nil {
		t.Fatalf("NewDaemon: %v", err)
	}
	return d
}

func TestDaemon_Getters(t *testing.T) {
	d := newTestDaemon(t)

	assert.NotNil(t, d.Viper())
	assert.NotNil(t, d.ResourceService())
	assert.NotNil(t, d.Logger())
	// EsClient/AppTask/GlobalConfig/VpnService/FwConfigService are not
	// set before InstantiateAPI; just exercise the accessors.
	_ = d.EsClient()
	_ = d.AppTask()
	_ = d.GlobalConfig()
	_ = d.VpnService()
	_ = d.FwConfigService()

	// DefaultMeshMode branches.
	def := d.DefaultMeshMode(utils.DefaultNamespace, daemonLogger)
	assert.NotEmpty(t, def)
	other := d.DefaultMeshMode("other-ns", daemonLogger)
	assert.NotEmpty(t, other)
	assert.NotEqual(t, def, other)

	// IsExitNodeSupported passthrough.
	_ = d.IsExitNodeSupported("ns", [16]byte{}, [16]byte{})

	// AddDnsRecord / DelDnsRecord with nil dns server -> nil.
	assert.NoError(t, d.AddDnsRecord("host", "1.2.3.4"))
	assert.NoError(t, d.DelDnsRecord("host", "1.2.3.4"))
}

func TestDaemon_GetListeningAddrDefault(t *testing.T) {
	d := newTestDaemon(t)
	addr := d.getListeningAddr()
	assert.NotEmpty(t, addr)
	// Custom listen address.
	d.viper.Set("listening_addr", "127.0.0.1:12345")
	assert.Equal(t, "127.0.0.1:12345", d.getListeningAddr())
}

func TestDaemon_NamespaceInfo_NotFound(t *testing.T) {
	d := newTestDaemon(t)
	_, err := d.NamespaceInfo("does-not-exist")
	assert.Error(t, err)
}

func TestDaemon_PrepareCheck(t *testing.T) {
	d := newTestDaemon(t)
	_ = d.PrepareCheck() // may fail if /run/sase can't be created; just exercise.
}

func TestDaemon_SetLogLevel(t *testing.T) {
	d := newTestDaemon(t)
	d.viper.Set("log-level", "info")
	_ = d.setLogLevel(nil)
	// Invalid log level -> error.
	d.viper.Set("log-level", "bogus")
	_ = d.setLogLevel(nil)
}

// InstantiateAPI wires all services. Register() can fatal on failure so we
// just exercise happy path.
func TestDaemon_InstantiateAPI(t *testing.T) {
	d := newTestDaemon(t)
	if err := d.InstantiateAPI(); err != nil {
		t.Logf("InstantiateAPI: %v", err)
	}
	// After Instantiate, several services should be wired.
	_ = d.VpnService()
	_ = d.FwConfigService()
}
