// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package services

import (
	"cylonix/sase/cmd/statistics"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrometheusTaskInstance_Meta(t *testing.T) {
	ts := &TaskTable{
		Config: &TaskConfig{
			Interval: 0, // default.
		},
		Logger: testLogger,
	}
	pe := statistics.NewPrometheusMetricsEmulator()
	p := NewPrometheusTaskInstance(ts, pe)
	assert.Equal(t, "Prometheus task instance", p.Name())
	assert.Equal(t, defaultPrometheusTaskInterval, p.Interval())

	// Custom interval.
	ts.Config.Interval = 42
	assert.Equal(t, 42, p.Interval())
}

func TestPrometheusTaskInstance_Task_NoNamespace(t *testing.T) {
	ts := &TaskTable{
		Config: &TaskConfig{
			Namespaces: []string{}, // empty.
			Interval:   1,
		},
		Logger: testLogger,
	}
	pe := statistics.NewPrometheusMetricsEmulator()
	p := NewPrometheusTaskInstance(ts, pe)
	// Run the task with no namespaces; just exercise the wiring.
	p.Task(false)
}

func TestCleanTask_Meta(t *testing.T) {
	ts := &TaskTable{
		Config: &TaskConfig{Interval: 0},
		Logger: testLogger,
	}
	c := NewCleanTask(ts)
	assert.NotNil(t, c)
	_ = c.Name()
	_ = c.Interval()
}

// NewTaskTable without a valid config fails during initSupervisorClient.
func TestNewTaskTable_FailsWithoutConfig(t *testing.T) {
	_, err := NewTaskTable(testLogger, &TaskConfig{Interval: 1})
	// Expect an error because supervisor/etcd/postgres are not configured
	// for the test binary via viper.
	assert.Error(t, err)
}

// wgClientList and wgNamespaceMap with no etcd / no client - should return
// either empty or err without panicking.
func TestWgClientList_NoEtcd(t *testing.T) {
	_, err := wgClientList()
	_ = err
}
