// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCleanTask(t *testing.T) {
	ts := &TaskTable{
		Config: &TaskConfig{
			Interval:   100,
			Namespaces: []string{"ns1", "ns2"},
		},
		Logger: testLogger,
	}

	task := NewCleanTask(ts)
	assert.Equal(t, "Clean task", task.Name())
	// Interval is min of config vs minCleanTaskInterval.
	assert.Equal(t, minCleanTaskInterval, task.Interval())

	// With larger interval, uses that.
	ts.Config.Interval = minCleanTaskInterval + 1000
	assert.Equal(t, minCleanTaskInterval+1000, task.Interval())

	// Exercise Task - just make sure it doesn't panic.
	task.Task(false)
}

func TestTaskTable_NamespaceList(t *testing.T) {
	ts := &TaskTable{
		Config: &TaskConfig{
			Namespaces: []string{"a", "b"},
		},
		Logger: testLogger,
	}
	list := ts.NamespaceList()
	assert.Equal(t, []string{"a", "b"}, list)

	// Empty namespaces - falls back to supervisor client map.
	ts.Config.Namespaces = nil
	// Don't panic - may return nil or empty list.
	_ = ts.NamespaceList()
}

// Prometheus task requires a PrometheusMetricsInterface; omitted here.
