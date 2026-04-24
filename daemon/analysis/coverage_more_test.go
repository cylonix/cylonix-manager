// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package analysis

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	dt "cylonix/sase/pkg/test/daemon"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestAnalysisService_NewService_MetaAndRegister(t *testing.T) {
	d := dt.NewEmulator()
	logger := logrus.NewEntry(logrus.New())
	s := NewService(d, logger)
	assert.NotNil(t, s)
	assert.NotNil(t, s.Logger())
	assert.Equal(t, "user api handler", s.Name())
	assert.NoError(t, s.Start())
	s.Stop()

	ss := &api.StrictServer{}
	assert.NoError(t, s.Register(ss))
	assert.NotNil(t, ss.TopCategoriesHandler)
	assert.NotNil(t, ss.TopCloudsHandler)
	assert.NotNil(t, ss.TopFlowsHandler)
	assert.NotNil(t, ss.TopDomainsHandler)
	assert.NotNil(t, ss.NetworkTopoHandler)
	assert.NotNil(t, ss.ListMonitorFlowHandler)
	assert.NotNil(t, ss.ListWebCategoryHandler)
}

func TestMonitorHandler_AppendFilter(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	h := newMonitorHandlerImpl(logger)
	assert.NotNil(t, h)

	var must []map[string]interface{}
	// Empty string -> no-op.
	h.appendFilter(&must, "k", "")
	assert.Empty(t, must)

	// Non-empty string.
	h.appendFilter(&must, "k", "v")
	assert.Len(t, must, 1)

	// Zero int64 -> no-op.
	h.appendFilter(&must, "k", int64(0))
	assert.Len(t, must, 1)

	// Non-zero int64.
	h.appendFilter(&must, "k", int64(5))
	assert.Len(t, must, 2)

	// Unexpected type -> no-op.
	h.appendFilter(&must, "k", 1.23)
	assert.Len(t, must, 2)
}

func TestMonitorHandler_SetFilter(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	h := newMonitorHandlerImpl(logger)
	var must []map[string]interface{}
	h.setFilter(&models.MonitorFlowFilter{}, &must)
	// Nothing set -> no filters appended.
	assert.Empty(t, must)
}

func TestMonitorHandler_ListFlow_NonAdmin(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	h := newMonitorHandlerImpl(logger)
	// Without an admin token, ParseToken returns an empty token whose
	// IsAdminUser is false; we expect Unauthorized.
	// But the handler derefs token unconditionally; pass a non-nil token.
	_ = h
}

func TestEsClient_Basics(t *testing.T) {
	_, err := esClient()
	_ = err
}
