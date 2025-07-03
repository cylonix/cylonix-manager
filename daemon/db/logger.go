package db

import (
	"cylonix/sase/pkg/logging"
	"cylonix/sase/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

var logger = logging.DefaultLogger.WithField(logfields.LogSubsys, "db")

func SetLogLevel(level logrus.Level) {
	logger.Logger.SetLevel(level)
}
