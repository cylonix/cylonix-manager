// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestCleaner_StartAddRunClean(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	c := StartCleaner(logger)
	assert.NotNil(t, c)

	called := false
	c.AddCleanUpFunc("test", func() { called = true })
	c.cleanupFuncs.Run()
	assert.True(t, called)
}

func TestCleaner_SetCancelFunc(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	c := StartCleaner(logger)
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	c.SetCancelFunc(cancel)
	assert.NotNil(t, c.sigHandlerCancel)

	// Second call is a no-op.
	_, cancel2 := context.WithCancel(context.Background())
	c.SetCancelFunc(cancel2)
	cancel2()
}

func TestCleaner_RegisterSigHandler(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	c := StartCleaner(logger)
	// Just exercise the signal handler registration; don't actually signal.
	interrupt := c.RegisterSigHandler()
	assert.NotNil(t, interrupt)
}
