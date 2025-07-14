// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logger

import "github.com/sirupsen/logrus"

func New(verbose bool) *logrus.Entry {
	logger := logrus.NewEntry(logrus.New())
	if !verbose {
		logger.Logger.SetLevel(logrus.ErrorLevel)
	} else {
		logger.Logger.SetLevel(logrus.DebugLevel)
	}
	return logger
}
