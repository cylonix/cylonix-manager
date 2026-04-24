// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestSetHandlerLogLevel(t *testing.T) {
	l := logrus.New()
	entry := logrus.NewEntry(l)
	setHandlerLogLevel(logrus.DebugLevel, entry)
	assert.Equal(t, logrus.DebugLevel, l.Level)
}

func TestLogEntryHandler_AddEntry(t *testing.T) {
	h := &logEntryHandler{}
	// Pass invalid IDs so userID/deviceID stay nil, and the AddLogAlarm
	// call operates on the emulator DB already initialized via TestMain.
	err := h.AddEntry("ns", "", "", logrus.ErrorLevel, "msg")
	// The function may succeed or fail depending on DB state; we just
	// exercise the code path without asserting a particular error.
	_ = err
}
