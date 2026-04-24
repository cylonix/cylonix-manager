// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package schedule

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/pkg/interfaces"
	dt "cylonix/sase/pkg/test/daemon"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func newTestTask() *AppSummaryTask {
	return &AppSummaryTask{
		daemon:         dt.NewEmulator(),
		logger:         logrus.NewEntry(logrus.New()),
		namespaceStats: map[string]*AppNamespaceStats{},
	}
}

func TestAppSumMapToCategoryList(t *testing.T) {
	out := AppSumMapToCategoryList(map[string]int{"a": 1, "b": 2})
	assert.Len(t, out, 2)
}

func TestTask_SetProcessing(t *testing.T) {
	task := newTestTask()
	task.setProcessing(true)
	assert.True(t, task.isProcessing)
	task.setProcessing(false)
	assert.False(t, task.isProcessing)
}

func TestTask_GetSetNamespaceStats(t *testing.T) {
	task := newTestTask()
	v, ok := task.getNamespaceStats("ns")
	assert.Nil(t, v)
	assert.False(t, ok)

	stats := task.newAppNamespaceStats("ns")
	task.setNamespaceStats("ns", stats)
	v, ok = task.getNamespaceStats("ns")
	assert.True(t, ok)
	assert.Equal(t, stats, v)
}

func TestAppNamespaceStats_SetGetCategoriesAndDomains(t *testing.T) {
	task := newTestTask()
	n := task.newAppNamespaceStats("ns")
	// initially empty
	_, ok := n.getCategories(interfaces.EsAllStats)
	assert.False(t, ok)
	_, ok = n.getDomains(interfaces.EsAllStats)
	assert.False(t, ok)

	cats := []models.AppStatsItem{{}}
	n.setCategories(cats, interfaces.EsAllStats)
	out, ok := n.getCategories(interfaces.EsAllStats)
	assert.True(t, ok)
	assert.Equal(t, cats, out)

	n.setDomains(cats, interfaces.EsPermitStats)
	out, ok = n.getDomains(interfaces.EsPermitStats)
	assert.True(t, ok)
	assert.Equal(t, cats, out)
}

func TestTask_DeleteNamespace(t *testing.T) {
	task := newTestTask()
	task.setNamespaceStats("ns", task.newAppNamespaceStats("ns"))
	assert.NoError(t, task.DeleteNamespace("ns"))
	_, ok := task.getNamespaceStats("ns")
	assert.False(t, ok)
}

func TestTask_DomainToCategoryFallback(t *testing.T) {
	task := newTestTask()
	// Emulator returns nil GlobalConfig -> fallback to "others".
	assert.Equal(t, "others", task.domainToCategory("example.com"))
}

func TestTask_ProviderNameFromIPAddr(t *testing.T) {
	task := newTestTask()
	assert.Equal(t, "others", task.providerNameFromIPAddr("1.2.3.4"))
}

func TestTask_TopFlowsAndCategoriesAndDomainsAndClouds(t *testing.T) {
	task := newTestTask()
	// When stats not set, TopFlows returns nil.
	assert.Nil(t, task.TopFlows("ns"))
	// TopCategories returns a slice with items for each stat type.
	cats := task.TopCategories("ns")
	assert.Len(t, cats, len(interfaces.EsStatsTypeList))
	// TopDomains similar.
	doms := task.TopDomains("ns")
	assert.Len(t, doms, len(interfaces.EsStatsTypeList))
	// TopClouds returns nil when no stats.
	assert.Nil(t, task.TopClouds("ns"))

	// With stats set.
	stats := task.newAppNamespaceStats("ns")
	stats.userFlows = &models.TopUserFlows{}
	stats.clouds = []models.AppCloud{{}}
	task.setNamespaceStats("ns", stats)
	assert.NotNil(t, task.TopFlows("ns"))
	assert.Len(t, task.TopClouds("ns"), 1)
}

func TestTask_StatsToCategoriesAndDomains(t *testing.T) {
	task := newTestTask()
	n := task.newAppNamespaceStats("ns")
	cats, doms := n.statsToCategoriesAndDomains([]*interfaces.EsStats{
		{Domain: "a.com", Count: 5},
		{Domain: "b.com", Count: 3},
	})
	// Both domains fall into "others" -> single category with count 8.
	assert.Len(t, cats, 1)
	assert.Equal(t, 8, *cats[0].Count)
	assert.Len(t, doms, 2)
}

func TestTask_GetCategoriesAndDomains_NilStats(t *testing.T) {
	task := newTestTask()
	assert.Nil(t, task.getCategories("ns", interfaces.EsAllStats))
	assert.Nil(t, task.getDomains("ns", interfaces.EsAllStats))
}
