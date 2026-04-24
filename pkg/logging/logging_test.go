// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package logging

import (
	"bytes"
	"log/syslog"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestInitializeDefaultLogger(t *testing.T) {
	l := InitializeDefaultLogger()
	assert.NotNil(t, l)
	assert.Equal(t, logrus.InfoLevel, l.Level)
}

func TestLogOptions_GetLogLevel(t *testing.T) {
	opts := LogOptions{LevelOpt: "debug"}
	lvl, ok := opts.GetLogLevel()
	assert.True(t, ok)
	assert.Equal(t, logrus.DebugLevel, lvl)

	opts = LogOptions{LevelOpt: "bogus"}
	_, ok = opts.GetLogLevel()
	assert.False(t, ok)
}

func TestLogOptions_GetLogFormat(t *testing.T) {
	// Missing -> default.
	o := LogOptions{}
	assert.Equal(t, DefaultLogFormat, o.GetLogFormat())

	// Valid values.
	o = LogOptions{FormatOpt: "json"}
	assert.Equal(t, LogFormatJSON, o.GetLogFormat())
	o = LogOptions{FormatOpt: "text"}
	assert.Equal(t, LogFormatText, o.GetLogFormat())

	// Invalid -> default.
	o = LogOptions{FormatOpt: "invalid"}
	assert.Equal(t, DefaultLogFormat, o.GetLogFormat())
}

func TestGetLogLevelFromConfig(t *testing.T) {
	// logOptions is a package var used by GetLogLevelFromConfig.
	// Save/restore so we don't mutate global state across tests.
	saved := logOptions
	defer func() { logOptions = saved }()

	logOptions = LogOptions{LevelOpt: "warning"}
	lvl, ok := GetLogLevelFromConfig()
	assert.True(t, ok)
	assert.Equal(t, logrus.WarnLevel, lvl)
}

func TestConfigureLogLevelFromOptions(t *testing.T) {
	// Valid.
	o := LogOptions{LevelOpt: "warning"}
	assert.Equal(t, logrus.WarnLevel, o.configureLogLevelFromOptions())

	// Invalid falls back to default.
	o = LogOptions{LevelOpt: "bogus"}
	assert.Equal(t, LevelStringToLogrusLevel[DefaultLogLevelStr], o.configureLogLevelFromOptions())

	// Missing falls back to default.
	o = LogOptions{}
	assert.Equal(t, LevelStringToLogrusLevel[DefaultLogLevelStr], o.configureLogLevelFromOptions())
	assert.Equal(t, DefaultLogLevelStr, o[LevelOpt])
}

func TestSetupLogging_default(t *testing.T) {
	err := SetupLogging(nil, LogOptions{}, "tag", true)
	assert.NoError(t, err)
}

func TestSetupLogging_unknownDriver(t *testing.T) {
	err := SetupLogging([]string{"bogus"}, LogOptions{}, "tag", false)
	assert.Error(t, err)
}

func TestSetLogLevel(t *testing.T) {
	prev := DefaultLogger.Level
	defer SetLogLevel(prev)
	SetLogLevel(logrus.DebugLevel)
	assert.Equal(t, logrus.DebugLevel, DefaultLogger.Level)
}

func TestConfigureLogLevel(t *testing.T) {
	prev := DefaultLogger.Level
	defer SetLogLevel(prev)
	ConfigureLogLevel(true)
	assert.Equal(t, logrus.DebugLevel, DefaultLogger.Level)
	ConfigureLogLevel(false)
}

func TestGetFormatter(t *testing.T) {
	assert.IsType(t, &logrus.TextFormatter{}, GetFormatter(LogFormatText))
	assert.IsType(t, &logrus.JSONFormatter{}, GetFormatter(LogFormatJSON))
	assert.Nil(t, GetFormatter("bogus"))
}

func TestLogOptions_validateOpts(t *testing.T) {
	supported := map[string]bool{"syslog.level": true}
	assert.NoError(t, LogOptions{"syslog.level": "info"}.validateOpts("syslog", supported))
	assert.Error(t, LogOptions{"not.allowed": "x"}.validateOpts("syslog", supported))
}

func TestGetLogDriverConfig(t *testing.T) {
	opts := LogOptions{"syslog.level": "info", "unrelated": "x"}
	out := getLogDriverConfig(Syslog, opts)
	assert.Len(t, out, 1)
	assert.Equal(t, "info", out["syslog.level"])
}

func TestMultiLine(t *testing.T) {
	var buf bytes.Buffer
	logFn := func(args ...interface{}) {
		for _, a := range args {
			buf.WriteString(a.(string))
			buf.WriteString("|")
		}
	}
	MultiLine(logFn, "a\nb\nc")
	assert.Equal(t, "a|b|c|", buf.String())
}

func TestCanLogAt(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.InfoLevel)
	assert.True(t, CanLogAt(l, logrus.InfoLevel))
	assert.True(t, CanLogAt(l, logrus.WarnLevel))
	assert.False(t, CanLogAt(l, logrus.DebugLevel))
}

func TestGetLevel(t *testing.T) {
	l := logrus.New()
	l.SetLevel(logrus.ErrorLevel)
	assert.Equal(t, logrus.ErrorLevel, GetLevel(l))
}

func TestSyslogLevelMapping(t *testing.T) {
	assert.Equal(t, syslog.LOG_ERR, syslogLevelMap[logrus.ErrorLevel])
	assert.Equal(t, syslog.LOG_INFO, syslogLevelMap[logrus.InfoLevel])
	assert.Equal(t, syslog.LOG_DEBUG, syslogLevelMap[logrus.DebugLevel])
}

func TestDefaultLogFormatValue(t *testing.T) {
	// Simple sanity check that the constants remain as strings.
	assert.Equal(t, "text", string(LogFormatText))
	assert.Equal(t, "json", string(LogFormatJSON))
	assert.True(t, strings.EqualFold(DefaultLogLevelStr, "info"))
}
