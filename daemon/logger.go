// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/logging"
	"cylonix/sase/pkg/wslog"
	"encoding/json"

	"github.com/sirupsen/logrus"
)

var (
	daemonLogger = logging.DefaultLogger.WithField("sys", "daemon")
)

func setHandlerLogLevel(level logrus.Level, logger *logrus.Entry) {
	logger.Logger.SetLevel(level)
	logger.Infoln("new log level is set to", level)
}

type logEntryHandler struct {
}

func (l *logEntryHandler) AddEntry(namespace, userIDStr, deviceIDStr string, level logrus.Level, message string) error {
	var userID *types.UserID
	var deviceID *types.DeviceID
	id, err := types.ParseID(userIDStr)
	if err == nil && !id.IsNil() {
		userID = &id
	}
	id, err = types.ParseID(deviceIDStr)
	if err == nil && !id.IsNil() {
		deviceID = &id
	}

	n, err := db.AddLogAlarm(namespace, userID, deviceID, level.String(), message)
	if err == nil {
		if b, err := json.Marshal(n); err == nil {
			go wslog.Send(namespace, userIDStr, wslog.Alert, b)
		}
	}
	return err
}
