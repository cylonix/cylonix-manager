// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"tailscale.com/types/key"
)

func TestFixKeyPrefix(t *testing.T) {
	assert.Equal(t, "mkey:abc", fixKeyPrefix("abc", "mkey:"))
	assert.Equal(t, "mkey:abc", fixKeyPrefix("mkey:abc", "mkey:"))
}

func TestFixMachinePublicKeyHexStringPrefix(t *testing.T) {
	assert.Equal(t, "mkey:abc", fixMachinePublicKeyHexStringPrefix("abc"))
	assert.Equal(t, "mkey:abc", fixMachinePublicKeyHexStringPrefix("mkey:abc"))
}

func TestFixNodePublicKeyHexStringPrefix(t *testing.T) {
	assert.Equal(t, "nodekey:abc", fixNodePublicKeyHexStringPrefix("abc"))
	assert.Equal(t, "nodekey:abc", fixNodePublicKeyHexStringPrefix("nodekey:abc"))
}

func TestTrimNodePublicKeyHexStringPrefix(t *testing.T) {
	assert.Equal(t, "abc", trimNodePublicKeyHexStringPrefix("nodekey:abc"))
	assert.Equal(t, "abc", trimNodePublicKeyHexStringPrefix("abc"))
}

func TestUnmarshalMachinePublicKeyText_err(t *testing.T) {
	_, err := UnmarshalMachinePublicKeyText("nope")
	assert.Error(t, err)
}

func TestUnmarshalNodePublicKeyText_err(t *testing.T) {
	_, err := UnmarshalNodePublicKeyText("nope")
	assert.Error(t, err)
}

func TestUnmarshalRoundTripMachineKey(t *testing.T) {
	mp := key.NewMachine().Public()
	data, err := mp.MarshalText()
	assert.NoError(t, err)
	parsed, err := UnmarshalMachinePublicKeyText(string(data))
	assert.NoError(t, err)
	assert.NotNil(t, parsed)
}

func TestUnmarshalRoundTripNodeKey(t *testing.T) {
	np := key.NewNode().Public()
	data, err := np.MarshalText()
	assert.NoError(t, err)
	parsed, err := UnmarshalNodePublicKeyText(string(data))
	assert.NoError(t, err)
	assert.NotNil(t, parsed)

	hex, err := NodeKeyToHexString(*parsed)
	assert.NoError(t, err)
	assert.NotEmpty(t, hex)
	assert.False(t, strings.HasPrefix(hex, nodePublicHexPrefix))
}
