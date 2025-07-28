// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tenant

import (
	"cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	dbt "cylonix/sase/pkg/test/db"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	testLogger = logrus.NewEntry(logrus.New())
)

func testSetup() error {
	utils.Init(nil)
	if err := db.InitEmulator(testing.Verbose()); err != nil {
		return err
	}
	return nil
}

func testCleanup() {
	db.CleanupEmulator()
}
func TestMain(m *testing.M) {
	flag.Parse()
	if err := testSetup(); err != nil {
		log.Fatalf("Failed to setup test: %v.", err)
	}
	code := m.Run()
	testCleanup()
	os.Exit(code)
}
func newAddParam(namespace, name, phone string, tierID uuid.UUID) api.AddTenantConfigRequestObject {
	return api.AddTenantConfigRequestObject{
		Body: &models.TenantConfig{
			AutoAcceptRoutes:  optional.BoolP(true),
			AutoApproveDevice: optional.BoolP(true),
			Name:              name,
			Namespace:         namespace,
			NetworkDomain:     optional.P("test.com"),
			Email:             name + "@text.com",
			Phone:             phone,
			UserTierID:        &tierID,
		},
	}
}
func newRegisterParam(namespace, name, phone string) api.RegisterTenantRequestObject {
	code := "121234"
	smsToken := utils.NewSmsToken(phone)
	smsToken.Set("", code, false)
	return api.RegisterTenantRequestObject{
		Body: &models.TenantApproval{
			IsSmsCode:   true,
			Code:        code,
			CompanyName: name,
			Namespace:   namespace,
			Phone:       phone,
			Email:       name + "@test.com",
			Username:    "test-username",
			Password:    "13111",
		},
	}
}
func TestTenant(t *testing.T) {
	handler := newHandlerImpl(testLogger)
	namespace := "tenant-namespace-test"

	name := "12315"
	phone := "1235431143"

	username := "admin-123"
	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}

	tier, err := db.CreateUserTier(&types.UserTier{
		Name:           "test-tenant-tier",
		Description:    "test-tenant-tier-description",
		MaxUserCount:   100,
		MaxDeviceCount: 100,
	})
	if !assert.Nil(t, err) {
		return
	}

	_, tokenData := dbt.CreateTokenForTest(namespace, userID, username, false, nil)
	tokenData.IsSysAdmin = true

	registerParam := newRegisterParam(namespace, name, phone)
	err = handler.RegisterTenant(nil, registerParam)
	assert.Nil(t, err)

	addParam := newAddParam(namespace, name, phone, tier.ID.UUID())
	password, err := handler.AddConfig(tokenData, addParam)
	assert.Nil(t, err)
	assert.NotEmpty(t, password)

	addParam = newAddParam(namespace, "111", "aaa", tier.ID.UUID())
	password, err = handler.AddConfig(tokenData, addParam)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelCompanyExists)
		assert.Empty(t, password)
	}

	listParam := api.ListTenantConfigRequestObject{
		Params: models.ListTenantConfigParams{
			Page:     optional.IntP(1),
			PageSize: optional.IntP(10),
		},
	}
	total, list, err := handler.ListConfig(tokenData, listParam)
	if !assert.Nil(t, err) ||
		!assert.Equal(t, 1, total) ||
		!assert.Equal(t, 1, len(list)) {
		return
	}
	tenantID := list[0].ID

	companyName1 := "test-name-001"
	updateParam := api.UpdateTenantConfigRequestObject{
		Body: &models.TenantConfig{
			ID:                tenantID,
			Name:              companyName1,
			AutoApproveDevice: optional.BoolP(false),
			AutoAcceptRoutes:  optional.BoolP(false),
		},
	}
	err = handler.UpdateConfig(tokenData, updateParam)
	assert.Nil(t, err)

	total, list, err = handler.ListConfig(tokenData, listParam)
	if assert.Nil(t, err) && assert.Equal(t, 1, total) && assert.Equal(t, 1, len(list)) {
		if assert.NotNil(t, list[0].AutoAcceptRoutes) {
			assert.False(t, *list[0].AutoAcceptRoutes)
		}
		if assert.NotNil(t, list[0].AutoApproveDevice) {
			assert.False(t, *list[0].AutoApproveDevice)
		}
		assert.Equal(t, companyName1, list[0].Name)
	}

	getApprovalParam := api.GetTenantApprovalRecordsRequestObject{
		Params: models.GetTenantApprovalRecordsParams{
			Page:     optional.IntP(1),
			PageSize: optional.IntP(10),
		},
	}
	approvalTotal, approvalList, err := handler.ApprovalRecords(tokenData, getApprovalParam)
	if !assert.Nil(t, err) ||
		!assert.Equal(t, 1, approvalTotal) ||
		!assert.Equal(t, 1, len(approvalList)) {
		return
	}
	registrationID1 := approvalList[0].ID

	namespace2 := "namespace-test-002"
	companyName2 := "name-test-002"
	registerParam = newRegisterParam(namespace2, companyName2, "12311441")
	err = handler.RegisterTenant(nil, registerParam)
	assert.Nil(t, err)
	getApprovalParam = api.GetTenantApprovalRecordsRequestObject{
		Params: models.GetTenantApprovalRecordsParams{
			CompanyName: &companyName2,
		},
	}
	approvalTotal, approvalList, err = handler.ApprovalRecords(tokenData, getApprovalParam)
	if !assert.Nil(t, err) ||
		!assert.Equal(t, 1, approvalTotal) ||
		!assert.Equal(t, 1, len(approvalList)) {
		return
	}
	registrationID2 := approvalList[0].ID

	approvalUpdateParam := api.UpdateTenantApprovalRecordsRequestObject{
		Body: &models.ApproveParams{
			IDList: []uuid.UUID{registrationID2},
			Note:   "test-update",
		},
	}
	approvalUpdateParam.Body.SetState = models.ApprovalStateApproved
	err = handler.UpdateApprovals(tokenData, approvalUpdateParam)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelOperationNotSupported)
	}
	password, err = handler.UpdateTenantRegistration(tokenData, api.UpdateTenantRegistrationRequestObject{
		TenantRegistrationID: registrationID2,
		Params: models.UpdateTenantRegistrationParams{
			UserTierID:    tier.ID.UUID(),
			Note:          optional.StringP("test-approve"),
			NetworkDomain: "test.com",
		},
		Body: &models.TenantApproval{
			ApprovalRecord: &models.ApprovalRecord{
				State: models.ApprovalStateApproved,
			},
		},
	})
	assert.Nil(t, err)
	assert.NotEmpty(t, password)

	approvalUpdateParam.Body.SetState = models.ApprovalStateRejected
	err = handler.UpdateApprovals(tokenData, approvalUpdateParam)
	assert.Nil(t, err)

	summaryParam := api.GetTenantSummaryRequestObject{
		Params: models.GetTenantSummaryParams{
			Days:      optional.IntP(0),
			Namespace: &namespace,
		},
	}
	summaryList, err := handler.TenantSummary(tokenData, summaryParam)
	if assert.Nil(t, err) && assert.Equal(t, 1, len(summaryList)) {
		fmt.Println(summaryList[0].AlarmCount, summaryList[0].UserCount)
	}
	checkNamespaceParam := api.CheckNamespaceRequestObject{
		Params: models.CheckNamespaceParams{
			CompanyName: &namespace,
			Namespace:   &namespace,
		},
	}

	available, err := handler.IsNamespaceAvailable(checkNamespaceParam)
	assert.Nil(t, err)
	assert.False(t, available)
	checkNamespaceParam = api.CheckNamespaceRequestObject{
		Params: models.CheckNamespaceParams{
			CompanyName: optional.StringP("11231"),
			Namespace:   optional.StringP("11231"),
		},
	}
	available, err = handler.IsNamespaceAvailable(checkNamespaceParam)
	assert.Nil(t, err)
	assert.True(t, available)

	deleteConfigParam := api.DeleteTenantConfigsRequestObject{
		Body: &[]uuid.UUID{tenantID},
	}
	login, err := db.GetUserLoginByLoginName(namespace, list[0].Email)
	assert.Nil(t, err)
	if assert.NotNil(t, login) {
		assert.Nil(t, db.DeleteUser(namespace, login.UserID))
		err = handler.DeleteConfigs(tokenData, deleteConfigParam)
		assert.Nil(t, err)
	}

	getApprovalParam = api.GetTenantApprovalRecordsRequestObject{}
	getApprovalParam.Body = &[]uuid.UUID{registrationID1}
	approvalTotal, approvalList, err = handler.ApprovalRecords(tokenData, getApprovalParam)
	if assert.Nil(t, err) && assert.Equal(t, 1, len(approvalList)) {
		assert.Equal(t, 1, approvalTotal)
		assert.Equal(t, models.ApprovalStateHold, approvalList[0].ApprovalRecord.State)
	}

	total, list, err = handler.ListConfig(tokenData, listParam)
	if assert.Nil(t, err) {
		assert.Equal(t, 1, total)
		assert.Equal(t, 1, len(list))
	}
	getApprovalParam.Body = nil
	approvalTotal, approvalList, err = handler.ApprovalRecords(tokenData, getApprovalParam)
	if assert.Nil(t, err) {
		assert.Equal(t, 2, approvalTotal)
		assert.Equal(t, 2, len(approvalList))
	}

	deleteApprovalParam := api.DeleteTenantApprovalRecordsRequestObject{
		Body: &[]uuid.UUID{registrationID2},
	}
	err = handler.DeleteApprovals(tokenData, deleteApprovalParam)
	assert.Nil(t, err)

	getApprovalParam.Params = models.GetTenantApprovalRecordsParams{
		FilterBy:    optional.StringP("company_name"),
		FilterValue: &companyName2,
	}

	approvalTotal, approvalList, err = handler.ApprovalRecords(tokenData, getApprovalParam)
	if assert.Nil(t, err) {
		assert.Nil(t, approvalList)
		assert.Equal(t, 0, approvalTotal)
	}
}
