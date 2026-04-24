// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package es

import (
	"cylonix/sase/pkg/interfaces"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func newClientForTest(t *testing.T, url string) *EsClient {
	t.Helper()
	c, err := NewEsClient(url, logrus.NewEntry(logrus.New()))
	assert.NoError(t, err)
	return c
}

func TestNewEsClient_EmptyURL(t *testing.T) {
	_, err := NewEsClient("", logrus.NewEntry(logrus.New()))
	assert.Error(t, err)
}

func TestNewEsClient_OK(t *testing.T) {
	c, err := NewEsClient("http://localhost:9200", logrus.NewEntry(logrus.New()))
	assert.NoError(t, err)
	assert.NotNil(t, c)
}

func TestGetAggsQuery(t *testing.T) {
	c := newClientForTest(t, "http://localhost:9200")
	q := c.getAggsQuery("ns", "IP.source", 10, 5)
	assert.NotNil(t, q)
	assert.Equal(t, "ns", q.namespace)
	assert.Contains(t, q.query, "query")
	assert.Contains(t, q.query, "aggs")
}

func TestGetAggsQueryWithFilter(t *testing.T) {
	c := newClientForTest(t, "http://localhost:9200")
	q := c.getAggsQueryWithFilter("ns", "destination_names", "verdict", "FORWARDED", 10, 5)
	assert.NotNil(t, q)
}

func TestGetMustMatchQuery(t *testing.T) {
	c := newClientForTest(t, "http://localhost:9200")
	q := c.getMustMatchQuery("ns", "IP.source", "1.2.3.4", "destination_names", 10, 5)
	assert.NotNil(t, q)
}

func TestNewEsQuery(t *testing.T) {
	c := newClientForTest(t, "http://localhost:9200")
	q := c.newEsQuery("ns", map[string]interface{}{"foo": "bar"})
	assert.Equal(t, c, q.es)
	assert.Equal(t, "ns", q.namespace)
}

func TestSearch_InvalidHost(t *testing.T) {
	c := newClientForTest(t, "http://127.0.0.1:1")
	_, err := c.search("ns", map[string]interface{}{})
	assert.Error(t, err)
}

func TestGetStatsForTopSrcIPs_InvalidHost(t *testing.T) {
	c := newClientForTest(t, "http://127.0.0.1:1")
	_, err := c.GetStatsForTopSrcIPs("ns", 1)
	assert.Error(t, err)
}

func TestGetElasticsearchWithIp_InvalidHost(t *testing.T) {
	c := newClientForTest(t, "http://127.0.0.1:1")
	_, err := c.GetElasticsearchWithIp("ns", "1.2.3.4")
	assert.Error(t, err)
}

func TestGetStatsForTopDstIPs_InvalidHost(t *testing.T) {
	c := newClientForTest(t, "http://127.0.0.1:1")
	_, err := c.GetStatsForTopDstIPs("ns", 1)
	assert.Error(t, err)
}

func TestGetStatsForTopDomains_InvalidType(t *testing.T) {
	c := newClientForTest(t, "http://127.0.0.1:1")
	_, err := c.GetStatsForTopDomains("ns", interfaces.EsStatsType(99), 1)
	assert.Error(t, err)
}

func TestGetStatsForTopDomains_AllStats_InvalidHost(t *testing.T) {
	c := newClientForTest(t, "http://127.0.0.1:1")
	_, err := c.GetStatsForTopDomains("ns", interfaces.EsAllStats, 1)
	assert.Error(t, err)
	_, err = c.GetStatsForTopDomains("ns", interfaces.EsPermitStats, 1)
	assert.Error(t, err)
	_, err = c.GetStatsForTopDomains("ns", interfaces.EsDenyStats, 1)
	assert.Error(t, err)
}
