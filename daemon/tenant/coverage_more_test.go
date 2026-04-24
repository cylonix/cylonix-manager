// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tenant

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"testing"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestNewService_NewSystemHandler(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	s := NewService(logger)
	assert.NotNil(t, s)
	assert.NotNil(t, s.handler)
	assert.NotNil(t, s.system)
	s.Stop()

	// Directly exercise newSystemHandlerImpl.
	h := newSystemHandlerImpl(logger)
	assert.NotNil(t, h)
}

// HealthStatus is a pure struct return; no token needed.
func TestSystemHandler_HealthStatus(t *testing.T) {
	h := newSystemHandlerImpl(logrus.NewEntry(logrus.New()))
	ret, err := h.HealthStatus(nil, api.GetHealthStatusRequestObject{})
	assert.NoError(t, err)
	if assert.NotNil(t, ret) {
		assert.True(t, optional.Bool(ret.Status))
	}
}

// PutLogs with empty body returns bad params.
func TestSystemHandler_PutLogs_NoBody(t *testing.T) {
	h := newSystemHandlerImpl(logrus.NewEntry(logrus.New()))
	uid, _ := types.NewID()
	tok := &utils.UserTokenData{
		Token:     "t",
		Namespace: "ns",
		UserID:    uid.UUID(),
	}
	err := h.PutLogs(tok, api.PutLogsRequestObject{})
	assert.Error(t, err)

	// With a body containing various log types.
	firewall := "firewall"
	app := "cylonix-app"
	other := "bogus"
	log := `{"IP":{"source":"1.2.3.4"}}`
	body := models.LogList{
		{Source: &firewall, Log: &log},
		{Source: &app, Log: &log},
		{Source: &other, Log: &log},
		{Source: nil, Log: nil},
	}
	assert.NoError(t, h.PutLogs(tok, api.PutLogsRequestObject{Body: &body}))
}

// ListPathSelect returns unauthorized for non-admin.
func TestSystemHandler_ListPathSelect_NonAdmin(t *testing.T) {
	h := newSystemHandlerImpl(logrus.NewEntry(logrus.New()))
	uid, _ := types.NewID()
	tok := &utils.UserTokenData{
		Token:       "t",
		Namespace:   "ns",
		UserID:      uid.UUID(),
		IsAdminUser: false,
	}
	_, err := h.ListPathSelect(tok, api.ListPathSelectRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}
