// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package login

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
	"testing"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	testNamespace  = "test-namespace"
	testAdminToken *utils.UserTokenData
	testLogger     = logrus.NewEntry(logrus.New())
)

func TestAddLogin(t *testing.T) {
	namespace := testNamespace
	handler := newHandlerImpl(testLogger)
	phone := utils.New11DigitCode()
	code := utils.New6DigitCode()
	params := newLoginParam(phone, code)
	user, err := dbt.CreateUserForTest(namespace, phone)
	if !assert.Nil(t, err) {
		return
	}
	userID1 := user.ID
	defer func() {
		assert.Nil(t, db.DeleteUser(namespace, userID1))
	}()
	_, userToken1 := createTokenForTest(namespace, userID1, phone, false, nil)
	defer userToken1.Delete()

	// code invalid
	err = handler.AddLogin(userToken1, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelInvalidSmsCode)
	}

	// normal
	token := utils.NewSmsToken(phone)
	token.Set("", code, false)
	err = handler.AddLogin(userToken1, params)
	assert.Nil(t, err)

	// Add the same login again and expect user login exists err.
	token = utils.NewSmsToken(phone)
	token.Set("", code, false)
	err = handler.AddLogin(userToken1, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelUserLoginExists)
	}

	phone = "98745612347"
	code = "123456"
	user, err = dbt.CreateUserForTest(testNamespace, phone)
	if !assert.Nil(t, err) {
		return
	}
	userID2 := user.ID
	defer func() {
		assert.Nil(t, db.DeleteUser(namespace, userID2))
	}()

	params = newLoginParam(phone, code)
	params.Params.UserID = optional.StringP(userID2.String())
	err = handler.AddLogin(testAdminToken, params)
	assert.Nil(t, err)

}
func newLoginParam(phone, code string) api.AddLoginRequestObject {
	return api.AddLoginRequestObject{
		Params: models.AddLoginParams{
			PhoneNum: optional.StringP(phone),
			Code:     optional.StringP(code),
		},
		Body: &models.UserLogin{
			Credential: &phone,
			Login:      phone,
			LoginType:  models.LoginType(types.LoginTypePhone)},
	}
}

func createTokenForTest(namespace string, userID types.UserID, username string, isAdmin bool, adminNamespace []string) (string, *utils.UserTokenData) {
	token := utils.NewUserToken(testNamespace)
	userData := &utils.UserTokenData{
		Token:           token.Token,
		TokenTypeName:   token.Name(),
		Namespace:       namespace,
		UserID:          userID.UUID(),
		Username:        username,
		IsAdminUser:     isAdmin,
		AdminNamespaces: adminNamespace,
	}
	if err := token.Create(userData); err != nil {
		return "", nil
	}
	return token.Token, userData
}
func testSetup() error {
	utils.Init(nil)
	if err := db.InitEmulator(testing.Verbose()); err != nil {
		return err
	}
	if !testing.Verbose() {
		testLogger.Logger.SetLevel(logrus.ErrorLevel)
	}

	adminID, err := types.NewID()
	if err != nil {
		return err
	}

	_, testAdminToken = createTokenForTest(testNamespace, adminID, "admin", true, []string{testNamespace})

	return nil
}
func testCleanup() {
	db.CleanupEmulator()
	testAdminToken.Delete()
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
