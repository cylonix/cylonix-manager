// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package qrcode

import (
	"cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	dbt "cylonix/sase/pkg/test/db"
	"flag"
	"log"
	"os"
	"strings"
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
func newCreateParam() api.CreateQrCodeRequestObject {
	rid := uuid.New().String()
	createParam := api.CreateQrCodeRequestObject{
		Params: models.CreateQrCodeParams{
			QrCodeType: utils.QRCodeTokenTypeAuthRequest,
		},
		Body: &models.QrCodeRequester{
			ID:        rid,
			Hostname:  optional.StringP(strings.Split(rid, "-")[0]),
			UserAgent: optional.StringP(strings.Split(rid, "-")[1]),
		},
	}
	return createParam
}
func TestQrCode(t *testing.T) {
	namespace := "qrcode-namespace"
	user, err := dbt.CreateUserForTest(namespace, "")
	if !assert.Nil(t, err) {
		return
	}
	userID := user.ID
	defer func() {
		assert.Nil(t, db.DeleteUser(nil, namespace, userID))
	}()

	username := "qrcode_username"
	handler := newHandlerImpl(testLogger)
	_, tokenData := dbt.CreateTokenForTest(namespace, userID, username, true, nil)
	defer tokenData.Delete()

	createParam := newCreateParam()
	qrCodeData, err := handler.CreateQrCode(nil, createParam)
	if !assert.Nil(t, err) || !assert.NotNil(t, qrCodeData) {
		return
	}
	requesterID := createParam.Body.ID

	checkParam := api.CheckQrCodeStateRequestObject{
		QrCodeToken: "1234",
		Params: models.CheckQrCodeStateParams{
			RequesterID: &requesterID,
		},
	}
	qrTokenData, err := handler.CheckQrCodeState(nil, checkParam)
	assert.NotNil(t, err)
	assert.ErrorAs(t, err, &common.BadParamsErr{})
	assert.Nil(t, qrTokenData)

	checkParam.QrCodeToken = qrCodeData.Token

	qrTokenData, err = handler.CheckQrCodeState(nil, checkParam)
	if assert.Nil(t, err) && assert.NotNil(t, qrTokenData) {
		assert.Equal(t, models.QrCodeTokenDataStateCreated, qrTokenData.State)
	}

	// Requester can update to scanned state with a matching requester ID.
	updateParam := api.UpdateQrCodeTokenRequestObject{
		QrCodeToken: qrCodeData.Token,
		Body: &models.QrCodeTokenData{
			APIKey: &models.APIKey{
				Key: "",
			},
			State: models.QrCodeTokenDataStateScanned,
			Requester: &models.QrCodeRequester {
				ID: requesterID,
			},
		},
	}
	err = handler.UpdateQrCodeToken(nil, updateParam)
	assert.Nil(t, err)

	// Repeated update from the same requester is not an error.
	err = handler.UpdateQrCodeToken(nil, updateParam)
	assert.Nil(t, err)

	qrTokenData, err = handler.CheckQrCodeState(nil, checkParam)
	if assert.Nil(t, err) && assert.NotNil(t, qrTokenData) {
		assert.Equal(t, models.QrCodeTokenDataStateScanned, qrTokenData.State)
	}

	// Update token to confirm state from a requester should fail.
	updateParam.Body.State = models.QrCodeTokenDataStateConfirmed
	err = handler.UpdateQrCodeToken(nil, updateParam)
	assert.ErrorIs(t, common.ErrModelUnauthorized, err)

	// Update state from a valid token should succeed.
	granterID := uuid.New().String()
	updateParam.Body.Requester.ID = granterID
	err = handler.UpdateQrCodeToken(tokenData, updateParam)
	assert.Nil(t, err)

	qrTokenData, err = handler.CheckQrCodeState(tokenData, checkParam)
	assert.Nil(t, qrTokenData)
	if assert.NotNil(t, err) {
		assert.Equal(t, common.ErrModelUnauthorized, err)
	}

	createParam = newCreateParam()
	qrCodeData, err = handler.CreateQrCode(nil, createParam)
	assert.Nil(t, err)
	requesterID = createParam.Body.ID

	updateParam.QrCodeToken = qrCodeData.Token
	checkParam.QrCodeToken = qrCodeData.Token

	updateParam.Body.State = models.QrCodeTokenDataStateConfirmed
	err = handler.UpdateQrCodeToken(tokenData, updateParam)
	assert.Nil(t, err)

	checkParam.Params.RequesterID = &requesterID
	qrTokenData, err = handler.CheckQrCodeState(nil, checkParam)
	assert.Nil(t, qrTokenData)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelCompanyNotExists)
	}

	tierID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	err = db.NewTenant(&types.TenantConfig{Namespace: namespace, UserTierID: &tierID}, types.NilID, "", "test")
	if !assert.Nil(t, err) {
		return
	}
	qrTokenData, err = handler.CheckQrCodeState(nil, checkParam)
	if assert.Nil(t, err) {
		assert.Equal(t, models.QrCodeTokenDataStateConfirmed, qrTokenData.State)
	}

	createParam = newCreateParam()
	qrCodeData, err = handler.CreateQrCode(tokenData, createParam)
	if !assert.Nil(t, err) || !assert.NotNil(t, qrCodeData) {
		return
	}
	requesterID = createParam.Body.ID

	checkParam.QrCodeToken = qrCodeData.Token

	qrTokenData, err = handler.CheckQrCodeState(tokenData, checkParam)
	assert.Nil(t, err)
	assert.Equal(t, models.QrCodeTokenDataStateCreated, qrTokenData.State)

	updateParam.QrCodeToken = qrCodeData.Token
	updateParam.Body.State = models.QrCodeTokenDataStateScanned

	requester := &models.QrCodeRequester{
		ID:        requesterID,
		Hostname:  optional.StringP("test-hostname"),
		UserAgent: optional.StringP("firefox"),
	}
	updateParam.Body.Requester = requester
	err = handler.UpdateQrCodeToken(nil, updateParam)
	assert.Nil(t, err)
	qrTokenData, err = handler.CheckQrCodeState(tokenData, checkParam)
	assert.Nil(t, err)
	assert.Equal(t, models.QrCodeTokenDataStateScanned, qrTokenData.State)

	updateParam.Body.State = models.QrCodeTokenDataStateConfirmed
	updateParam.Body.Requester.ID = granterID
	err = handler.UpdateQrCodeToken(tokenData, updateParam)
	assert.Nil(t, err)

	checkParam.Params.RequesterID = &requesterID
	qrTokenData, err = handler.CheckQrCodeState(nil, checkParam)
	if assert.Nil(t, err) && assert.NotNil(t, qrTokenData) {
		assert.Equal(t, models.QrCodeTokenDataStateConfirmed, qrTokenData.State)
		if assert.NotNil(t,  qrTokenData.Requester) {
			assert.Equal(t, requesterID, qrTokenData.Requester.ID)
		}
		if assert.NotNil(t, qrTokenData.APIKey)	{
			assert.NotNil(t, qrTokenData.APIKey.Key)
		}
	}
}
