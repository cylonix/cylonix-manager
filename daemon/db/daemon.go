// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import "cylonix/sase/pkg/interfaces"

var (
	// Daemon interface to access some common functions in Daemon.
	daemon interfaces.DaemonInterface = nil
)

func SetDaemonInterface(d interfaces.DaemonInterface) error {
	daemon = d
	return nil
}

func getDefaultMeshMode(namespace string) string {
	if daemon == nil {
		return ""
	}
	return daemon.DefaultMeshMode(namespace, logger)
}
