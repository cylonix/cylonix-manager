// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package clients

import "github.com/sirupsen/logrus"

const (
	wgPath = "/cylonix/wg/instance/conn_config/"
)

var (
	cLog = logrus.New().WithField("handle", "statistics-client")
)
