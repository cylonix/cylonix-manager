// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package defaults

const (
	// SockPath is the path to the UNIX domain socket exposing the API to clients locally
	SockPath = "/var/run/cilium/health.sock"

	// SockPathEnv is the environment variable to overwrite SockPath
	SockPathEnv = "CILIUM_HEALTH_SOCK"

	// HTTPPathPort is used for probing base HTTP path connectivity
	HTTPPathPort = 4240

	// L7PathPort is used for probing L7 path connectivity
	L7PathPort = 4241

	// ServicePathPort is used for probing service redirect path connectivity
	ServicePathPort = 4242

	// ServiceL7PathPort is used for probing service redirect path connectivity with L7
	ServiceL7PathPort = 4243
)
