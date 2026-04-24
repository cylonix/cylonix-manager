// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package schedule

import (
	"cylonix/sase/pkg/interfaces"
	dt "cylonix/sase/pkg/test/daemon"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// fakeEsClient implements interfaces.EsClientInterface with err-default behavior.
type fakeEsClient struct{}

func (f *fakeEsClient) GetStatsForTopSrcIPs(string, int) ([]*interfaces.EsStatsForSrcIP, error) {
	return nil, assert.AnError
}
func (f *fakeEsClient) GetStatsForTopDstIPs(string, int) ([]*interfaces.EsStats, error) {
	return nil, assert.AnError
}
func (f *fakeEsClient) GetStatsForTopDomains(string, interfaces.EsStatsType, int) ([]*interfaces.EsStats, error) {
	return nil, assert.AnError
}

func TestNewAppSummaryTask_RunsQuit(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	quit := make(chan string, 1)
	d := dt.NewEmulator()
	task := NewAppSummaryTask(d, &fakeEsClient{}, quit, logger)
	assert.NotNil(t, task)

	// Send quit signal so the goroutine exits.
	quit <- "test"
}

func TestAppNamespaceStats_UpdateMethods_ErrPaths(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	d := dt.NewEmulator()
	task := &AppSummaryTask{
		daemon:         d,
		esClient:       &fakeEsClient{},
		namespaceStats: map[string]*AppNamespaceStats{},
		logger:         logger,
	}
	n := task.newAppNamespaceStats("ns-schedule")
	// All return err from fake, so these short-circuit.
	n.UpdateTopUserFlows()
	n.UpdateTopClouds()
	n.UpdateTopCategoryAndDomains()
}
