// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logging

import (
	"log"
	"strings"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
)

type LogEntryHandlerInterface interface {
	AddEntry(namespace, userID, deviceID string, level logrus.Level, message string) error
}

func AddHooks(logger *logrus.Entry, handler LogEntryHandlerInterface) error {
	log.Println("Add hooks to handle error and debug options.")
	cfg, err := utils.GetLogFilterConfig()
	if err != nil {
		return err
	}
	if cfg != nil {
		logger.Logger.AddHook(cfg)
	}
	logger.Logger.AddHook(&utils.ErrorLogHook{
		Handler: func(entry *logrus.Entry) error {
			return errorHandler(entry, handler)
		},
	})
	return nil
}

func AddZeroLogErrorHook(handler LogEntryHandlerInterface) {
	utils.SetGlobalZeroLogHook(
		zerolog.ErrorLevel,
		func(e *zerolog.Event, level zerolog.Level, message string) {
			zeroLogErrorHandler(e, message, handler)
		},
	)
}

func errorHandler(entry *logrus.Entry, handler LogEntryHandlerInterface) error {
	if entry == nil || entry.Data == nil {
		return nil
	}
	var namespace, userID, deviceID string
	for name, value := range entry.Data {
		sValue, ok := value.(string)
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(name, ulog.Namespace):
			namespace = sValue
		case strings.EqualFold(name, ulog.UserID):
			userID = sValue
		case strings.EqualFold(name, ulog.DeviceID):
			deviceID = sValue
		}
	}
	message, err := entry.String()
	if err != nil {
		return err
	}
	return handler.AddEntry(namespace, userID, deviceID, logrus.ErrorLevel, message)
}

func zeroLogErrorHandler(e *zerolog.Event, message string, handler LogEntryHandlerInterface) {
	if e == nil {
		return
	}
	fields, jsonString, err := utils.ZeroLogFields(e, message)
	if err != nil {
		return
	}
	var namespace, userID, deviceID string
	for name, value := range fields {
		sValue, ok := value.(string)
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(name, ulog.Namespace):
			namespace = sValue
		case strings.EqualFold(name, "user"):
			userID = sValue
		case strings.EqualFold(name, ulog.UserID):
			userID = sValue
		case strings.EqualFold(name, ulog.DeviceID):
			deviceID = sValue
		}
	}
	handler.AddEntry(namespace, userID, deviceID, logrus.ErrorLevel, jsonString)
}
