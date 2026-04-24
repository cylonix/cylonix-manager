// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logger

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewLogger_Verbose(t *testing.T) {
	assert.Equal(t, logrus.DebugLevel, New(true).Logger.Level)
}

func TestNewLogger_NonVerbose(t *testing.T) {
	assert.Equal(t, logrus.ErrorLevel, New(false).Logger.Level)
}
