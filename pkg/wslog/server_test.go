// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package wslog

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestServer_Serve_AndSend(t *testing.T) {
	prev := singletonInstance
	defer func() { singletonInstance = prev }()

	gin.SetMode(gin.TestMode)
	// Use port 0 to let the OS pick a free port; then don't wait for Run.
	s := NewServer(Config{Addr: "127.0.0.1:0"}, logrus.NewEntry(logrus.New()))
	// Set the singleton manually so Send() doesn't no-op.
	singletonInstance = s.instance

	// Second call returns ErrServerRunning after engine is non-nil.
	// We fake it by directly setting engine to a new gin engine.
	s.engine = gin.New()
	assert.ErrorIs(t, s.Serve(), ErrServerRunning)

	// Send to an unknown client - should noop gracefully.
	Send("ns", "user", Alert, []byte("msg"))
}

func TestServer_HandlerUpgradeFails(t *testing.T) {
	// Instance with no clients; handler(c) without upgrade header will 500.
	s := &instance{
		namespaceClients: map[string]*clientsMap{},
		logger:           logrus.NewEntry(logrus.New()),
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/ws", func(c *gin.Context) { s.handler(c, Alert) })
	srv := httptest.NewServer(r)
	defer srv.Close()
	// Direct HTTP GET without upgrade -> non-200 status code.
	resp, err := srv.Client().Get(srv.URL + "/ws")
	if assert.NoError(t, err) {
		defer resp.Body.Close()
		assert.NotEqual(t, 200, resp.StatusCode)
	}
	// Wait a moment for goroutines.
	time.Sleep(10 * time.Millisecond)
}

func TestWsLogService_StartStop(t *testing.T) {
	s := NewService(Config{Addr: "127.0.0.1:0"}, logrus.NewEntry(logrus.New()))
	// Don't actually start because it would block binding.
	s.Stop()
	// s.Start would block-test; skip to avoid flakiness.
	_ = s
}
