// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	"fmt"
	"strings"

	"tailscale.com/types/key"
)

// __BEGIN_ from "tailscale.com/types/key"
// Ugly but have to so that we can convert between wireguard keys
// and tailscale keys.
const (
	// machinePublicHexPrefix is the prefix used to identify a
	// hex-encoded machine public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	machinePublicHexPrefix = "mkey:"

	// nodePublicHexPrefix is the prefix used to identify a
	// hex-encoded node public key.
	//
	// This prefix is used in the control protocol, so cannot be
	// changed.
	nodePublicHexPrefix = "nodekey:"
)
// __END__ from "tailscale.com/types/key"

func fixKeyPrefix(keyString, prefix string) string {
	if !strings.HasPrefix(keyString, prefix) {
		return prefix + keyString
	}
	return keyString
}

func fixMachinePublicKeyHexStringPrefix(keyString string) string {
	return fixKeyPrefix(keyString, machinePublicHexPrefix)
}

func fixNodePublicKeyHexStringPrefix(keyString string) string {
	return fixKeyPrefix(keyString, nodePublicHexPrefix)
}

func trimNodePublicKeyHexStringPrefix(keyString string) string {
	return strings.TrimPrefix(keyString, nodePublicHexPrefix)
}

func UnmarshalMachinePublicKeyText(pkHex string) (*key.MachinePublic, error) {
	var machineKey key.MachinePublic
	if err := machineKey.UnmarshalText([]byte(fixMachinePublicKeyHexStringPrefix(pkHex))); err != nil {
		return nil, fmt.Errorf("failed to unmarshal machine public key: %w", err)
	}
	return &machineKey, nil
}
func UnmarshalNodePublicKeyText(pkHex string) (*key.NodePublic, error) {
	var nodeKey key.NodePublic
	if err := nodeKey.UnmarshalText([]byte(fixNodePublicKeyHexStringPrefix(pkHex))); err != nil {
		return nil, fmt.Errorf("failed to unmarshal node public key: %w", err)
	}
	return &nodeKey, nil
}

func NodeKeyToHexString(nodeKey key.NodePublic) (string, error) {
	v, err := nodeKey.MarshalText()
	if err != nil {
		return "", err
	}
	return trimNodePublicKeyHexStringPrefix(string(v)), nil
}
