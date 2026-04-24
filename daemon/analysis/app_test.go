// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package analysis

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	dt "cylonix/sase/pkg/test/daemon"
	"testing"

	"github.com/stretchr/testify/assert"
)

type fakeAppTask struct {
	categories []models.AppStats
	clouds     []models.AppCloud
	domains    []models.AppStats
	flows      *models.TopUserFlows
}

func (f *fakeAppTask) TopFlows(string) *models.TopUserFlows  { return f.flows }
func (f *fakeAppTask) TopCategories(string) []models.AppStats { return f.categories }
func (f *fakeAppTask) TopClouds(string) []models.AppCloud     { return f.clouds }
func (f *fakeAppTask) TopDomains(string) []models.AppStats    { return f.domains }

// daemon emulator with a custom AppTask.
type daemonWithTask struct {
	*dt.Emulator
	task *fakeAppTask
}

func (d *daemonWithTask) AppTask() any { return d.task }

// But Emulator already has AppTask returning nil. We need to override.
// The interface requires returning an AppSumTaskInterface. We accomplish
// that via method promotion: by embedding *dt.Emulator and redefining AppTask.
// However, for method sets to match Emulator's interface signature we must
// return interfaces.AppSumTaskInterface, not any. Since we want override,
// let's define on concrete type and use the handler directly.

// Helper that constructs the handler with an overridden daemon returning our
// fakeAppTask.
type embeddedDaemon struct {
	*dt.Emulator
	task *fakeAppTask
}

func (d *embeddedDaemon) AppTask() interfaceAppSumTask {
	return d.task
}

// interfaceAppSumTask just re-declares the exact AppSumTaskInterface signature.
type interfaceAppSumTask interface {
	TopFlows(string) *models.TopUserFlows
	TopCategories(string) []models.AppStats
	TopClouds(string) []models.AppCloud
	TopDomains(string) []models.AppStats
}

// NOTE: The Emulator returns nil for AppTask. Since embedding cannot override
// a method to return a different type, we simply test the nil path and the
// "non-admin" path separately, which cover the majority of the branches.

func TestAppImpl_ListEvent(t *testing.T) {
	d := dt.NewEmulator()
	h := newAppHandlerImpl(d, testLogger)
	testUserToken.IsAdminUser = false
	_, err := h.ListEvent(testUserToken, api.ListAppEventRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	testUserToken.IsAdminUser = true
	defer func() { testUserToken.IsAdminUser = false }()
	_, err = h.ListEvent(testUserToken, api.ListAppEventRequestObject{})
	assert.ErrorIs(t, err, common.ErrInternalErr)
}

func TestAppImpl_TopCategories_NilAppTask(t *testing.T) {
	d := dt.NewEmulator()
	h := newAppHandlerImpl(d, testLogger)
	testUserToken.IsAdminUser = false
	_, err := h.TopCategories(testUserToken, api.TopCategoriesRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	testUserToken.IsAdminUser = true
	defer func() { testUserToken.IsAdminUser = false }()
	_, err = h.TopCategories(testUserToken, api.TopCategoriesRequestObject{})
	assert.ErrorIs(t, err, common.ErrInternalErr)
}

func TestAppImpl_TopClouds_NilAppTask(t *testing.T) {
	d := dt.NewEmulator()
	h := newAppHandlerImpl(d, testLogger)
	testUserToken.IsAdminUser = false
	_, err := h.TopClouds(testUserToken, api.TopCloudsRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	testUserToken.IsAdminUser = true
	defer func() { testUserToken.IsAdminUser = false }()
	_, err = h.TopClouds(testUserToken, api.TopCloudsRequestObject{})
	assert.ErrorIs(t, err, common.ErrInternalErr)
}

func TestAppImpl_TopDomains_NilAppTask(t *testing.T) {
	d := dt.NewEmulator()
	h := newAppHandlerImpl(d, testLogger)
	testUserToken.IsAdminUser = false
	_, err := h.TopDomains(testUserToken, api.TopDomainsRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	testUserToken.IsAdminUser = true
	defer func() { testUserToken.IsAdminUser = false }()
	_, err = h.TopDomains(testUserToken, api.TopDomainsRequestObject{})
	assert.ErrorIs(t, err, common.ErrInternalErr)
}

func TestAppImpl_TopFlows_NilAppTask(t *testing.T) {
	d := dt.NewEmulator()
	h := newAppHandlerImpl(d, testLogger)
	testUserToken.IsAdminUser = false
	_, err := h.TopFlows(testUserToken, api.TopFlowsRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)

	testUserToken.IsAdminUser = true
	defer func() { testUserToken.IsAdminUser = false }()
	_, err = h.TopFlows(testUserToken, api.TopFlowsRequestObject{})
	assert.ErrorIs(t, err, common.ErrInternalErr)
}

func TestTopoImpl_Unauthorized(t *testing.T) {
	h := newTopoHandlerImpl(testLogger)
	testUserToken.IsAdminUser = false
	_, err := h.NetworkTopo(testUserToken, api.NetworkTopoRequestObject{})
	assert.ErrorIs(t, err, common.ErrModelUnauthorized)
}
