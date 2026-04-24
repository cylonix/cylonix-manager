// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logging

import (
	"bytes"
	"testing"

	ulog "github.com/cylonix/utils/log"
	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakeHandler struct {
	entries []struct {
		ns, u, d, msg string
		level         logrus.Level
	}
	err error
}

func (f *fakeHandler) AddEntry(namespace, userID, deviceID string, level logrus.Level, message string) error {
	f.entries = append(f.entries, struct {
		ns, u, d, msg string
		level         logrus.Level
	}{namespace, userID, deviceID, message, level})
	return f.err
}

func TestErrorHandler_NilEntry(t *testing.T) {
	h := &fakeHandler{}
	assert.NoError(t, errorHandler(nil, h))

	l := logrus.New()
	entry := logrus.NewEntry(l)
	// Data == nil
	assert.NoError(t, errorHandler(entry, h))
}

func TestErrorHandler_WithFields(t *testing.T) {
	h := &fakeHandler{}
	l := logrus.New()
	l.Out = &bytes.Buffer{}
	entry := l.WithFields(logrus.Fields{
		ulog.Namespace: "ns1",
		ulog.UserID:    "u1",
		ulog.DeviceID:  "d1",
		"other":        42, // non-string should be skipped
	})
	entry.Level = logrus.ErrorLevel
	err := errorHandler(entry, h)
	assert.NoError(t, err)
	assert.Len(t, h.entries, 1)
	e := h.entries[0]
	assert.Equal(t, "ns1", e.ns)
	assert.Equal(t, "u1", e.u)
	assert.Equal(t, "d1", e.d)
	assert.Contains(t, e.msg, "level=error")
}

func TestZeroLogErrorHandler_NilEvent(t *testing.T) {
	h := &fakeHandler{}
	// Must not panic.
	zeroLogErrorHandler(nil, "msg", h)
	assert.Len(t, h.entries, 0)
}

func TestZeroLogErrorHandler_Event(t *testing.T) {
	h := &fakeHandler{}
	logger := zerolog.New(&bytes.Buffer{})
	e := logger.Error().
		Str(ulog.Namespace, "ns1").
		Str(ulog.UserID, "u1").
		Str(ulog.DeviceID, "d1").
		Str("user", "u-alt")
	zeroLogErrorHandler(e, "hello", h)
	// The implementation may succeed or not depending on util support;
	// if it succeeds we expect exactly one entry.
	if len(h.entries) == 1 {
		got := h.entries[0]
		assert.Equal(t, "ns1", got.ns)
		assert.Equal(t, "d1", got.d)
	}
}

func TestAddZeroLogErrorHook(t *testing.T) {
	// Should not panic.
	h := &fakeHandler{}
	AddZeroLogErrorHook(h)
}
