// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package services

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/pkg/logging/logfields"

	ulog "github.com/cylonix/utils/log"

	"github.com/sirupsen/logrus"
)

const (
	alarmCleanupDays = 7
	minCleanTaskInterval = 3600 /* seconds */
)

type CleanTask struct {
	logger *logrus.Entry
	ts     *TaskTable
}

func (c *CleanTask) Task(_ bool) {
	for _, n := range c.ts.NamespaceList() {
		if err := db.DeleteOldAlarmMessages(n, 0, 0, alarmCleanupDays); err != nil {
			c.logger.WithField(ulog.Namespace, n).WithError(err).Errorln("Failed to delete old alarms in database.")
			break
		}
	}
}
func (ct *CleanTask) Interval() int {
	interval := ct.ts.Config.Interval
	if interval < minCleanTaskInterval {
		interval = minCleanTaskInterval
	}
	return interval
}

func (ct *CleanTask) Name() string {
	return "Clean task"
}

func NewCleanTask(ts *TaskTable) TaskItem {
	return &CleanTask{
		ts:     ts,
		logger: ts.Logger.WithField(logfields.LogSubsys, "clean-task"),
	}
}
