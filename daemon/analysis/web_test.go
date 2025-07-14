// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package analysis

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/fwconfig"
	dt "cylonix/sase/pkg/test/daemon"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestListCategories(t *testing.T) {
	logger := testLogger

	d := dt.NewEmulator()
	fwService := fwconfig.NewServiceEmulator()
	agent1 := fwconfig.NewEmulator()
	agent2 := fwconfig.NewEmulator()
	agent1.WebCategories = []string{"a.com", "b.io"}
	agent2.WebCategories = append(agent1.WebCategories, "c.com", "d.io")
	fwService.Agents = []fwconfig.ConfigInterface{agent1, agent2}
	d.FwService = fwService
	handler := newWebHandlerImpl(d, logger)
	params := api.ListWebCategoryRequestObject{}

	list, err := handler.ListCategory(nil, params)
	if assert.NotNil(t, err) {
		assert.Nil(t, list)
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
	}
	list, err = handler.ListCategory(testUserToken, params)
	if assert.NotNil(t, err) {
		assert.Nil(t, list)
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
	}
	testUserToken.IsAdminUser = true
	list, err = handler.ListCategory(testUserToken, params)
	if assert.Nil(t, err) {
		assert.NotNil(t, list)
		assert.Equal(t, len(agent2.WebCategories), int(list.Total))
	}
}
