// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/metrics"
	"cylonix/sase/pkg/optional"
	dt "cylonix/sase/pkg/test/daemon"
	dbt "cylonix/sase/pkg/test/db"
	rt "cylonix/sase/pkg/test/resource"
	"cylonix/sase/pkg/vpn"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/password"
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
	if !testing.Verbose() {
		testLogger.Logger.SetLevel(logrus.WarnLevel)
	}
	vpn.SetIgnoreHeadscaleInitError(true)
	return nil
}

func testCleanup() {
	vpn.SetIgnoreHeadscaleInitError(false)
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

func addTenantAndAdminToken(namespace string) (*utils.UserTokenData, error) {
	adminUser := "username-admin"
	adminUserID, err := types.NewID()
	if err != nil {
		return nil, err
	}

	tier, err := db.CreateUserTier(&types.UserTier{
		Name:           namespace + "-tier",
		Description:    "user tier for " + namespace,
		MaxUserCount:   20,
		MaxDeviceCount: 100,
	})
	if err != nil {
		return nil, err
	}

	_, adminToken := dbt.CreateTokenForTest(namespace, adminUserID, adminUser, true, nil)
	return adminToken, db.NewTenant(&types.TenantConfig{
		Namespace:  namespace,
		UserTierID: &tier.ID,
		TenantSetting: types.TenantSetting{
			MaxUser:       200,
			MaxDevice:     1000,
			NetworkDomain: namespace + "test.org",
		},
	}, adminUserID, adminUser, namespace)
}

func delTenantAndAdminToken(t *testing.T, namespace string, adminToken *utils.UserTokenData) {
	assert.Nil(t, adminToken.Delete())
	if !assert.Nil(t, db.DeleteUserTierByName(namespace+"-tier")) {
		users, _, err := db.GetUserList(&namespace, nil, false, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		if err != nil {
			t.Errorf("Failed to get user list for namespace %s: %v", namespace, err)
		}
		names := make([]string, 0, len(users))
		for _, user := range users {
			names = append(names, user.UserBaseInfo.DisplayName)
		}
		t.Errorf("Failed to delete user tier %s, users: %v", namespace+"-tier", names)
	}
	assert.Nil(t, db.DeleteTenantConfigByNamespace(namespace))
}

func TestUserHandlers(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "namespace-test-user"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}

	adminUser, err := addAdminUser(namespace)
	if !assert.Nil(t, err) || !assert.NotNil(t, adminUser) {
		return
	}
	defer assertDeleteUser(t, namespace, adminUser.ID)
	adminToken.UserID = adminUser.ID.UUID()

	t.Run("post-user", func(t *testing.T) {
		username := "username-test-001"
		password := "password-test-001"
		userPostParam := api.PostUserRequestObject{
			Params: models.PostUserParams{
				Namespace: &namespace,
			},
			Body: &models.User{
				Logins: []models.UserLogin{
					{
						Login:      strings.ToUpper(username),
						Credential: &password,
						LoginType:  types.LoginTypeUsername.ToModel(),
					},
				},
			},
		}

		err = handler.PostUser(adminToken, userPostParam)
		assert.Nil(t, err)
		login, err := db.GetUserLoginByLoginName(namespace, username)
		if assert.Nil(t, err) && assert.NotNil(t, login) {
			assert.Equal(t, username, login.LoginName)
			defer func() {
				assert.Nil(t, db.DeleteUser(nil, namespace, login.UserID))
			}()
			login, err = db.GetUserLogin(namespace, login.ID)
			if assert.Nil(t, err) && assert.NotNil(t, login) {
				assert.Equal(t, username, login.LoginName)
			}
		}
	})

	t.Run("list-user", func(t *testing.T) {
		ids := make([]types.ID, 100)
		defer func() {
			for _, id := range ids {
				assert.Nil(t, db.DeleteUser(nil, namespace, id))
			}
		}()
		for i := 0; i < 100; i++ {
			phone := fmt.Sprintf("408-123-34%2v", i)
			u, err := dbt.CreateUserForTest(namespace, phone)
			if !assert.Nil(t, err) {
				return
			}
			ids[i] = u.ID
		}
		getListParam := api.GetUserListRequestObject{
			Params: models.GetUserListParams{
				Page:     optional.IntP(1),
				PageSize: optional.IntP(10),
			},
		}
		userList, err := handler.GetUserList(adminToken, getListParam)
		if assert.Nil(t, err) {
			assert.Equal(t, 10, len(userList.Users))
		}
	})

	t.Run("update-user", func(t *testing.T) {
		username := "test-update-username"
		user, err := addUser(namespace, username)
		if !assert.Nil(t, err) || !assert.NotNil(t, user) {
			return
		}
		userID := user.ID
		loginID := user.UserLogins[0].ID
		defer assertDeleteUser(t, namespace, userID)
		login, err := db.GetUserLogin(namespace, loginID)
		if assert.Nil(t, err) && assert.NotNil(t, login) {
			assert.Equal(t, login.LoginName, username)
		}

		updateUsername := "username-test-update"
		newPassword := utils.NewPassword()
		userUpdateParam := api.UpdateUserRequestObject{
			Body: &models.UserUpdateInfo{
				SetUsername: optional.BoolP(true),
				Username:    &updateUsername,
				SetPassword: optional.BoolP(true),
				Password:    &newPassword,
			},
			UserID: userID.String(),
		}
		err = handler.UpdateUser(adminToken, userUpdateParam)
		assert.Nil(t, err)

		login, err = db.GetUserLogin(namespace, loginID)
		if assert.Nil(t, err) && assert.NotNil(t, login) {
			assert.Equal(t, login.LoginName, updateUsername)
		}

		var (
			newEmail       = "abc@123.com"
			newPhone       = "408-999-0001"
			newDisplayName = "new-nickname"
			enabled        = true
			meshMode       = models.MeshVpnModeTenant
			newLabels      models.LabelList
			labelIDs       []types.LabelID
		)
		defer db.DeleteLabels(namespace, nil, labelIDs)
		for i := 1; i <= 3; i++ {
			name := fmt.Sprintf("label-name-%v", i)
			label, err := dbt.NewLabelForTest(namespace, name, "red")
			if !assert.Nil(t, err) {
				return
			}
			newLabels = append(newLabels, *label.ToModel())
			labelIDs = append(labelIDs, label.ID)
		}
		userUpdateParam = api.UpdateUserRequestObject{
			UserID: userID.String(),
			Body: &models.UserUpdateInfo{
				AddEmail:              &newEmail,
				AddPhone:              &newPhone,
				AddLabels:             &newLabels,
				DisplayName:           &newDisplayName,
				WgEnabled:             &enabled,
				AutoAcceptRoutes:      &enabled,
				AutoApproveDevice:     &enabled,
				AdvertiseDefaultRoute: &enabled,
				MeshVpnMode:           &meshMode,
			},
		}
		err = handler.UpdateUser(adminToken, userUpdateParam)
		assert.Nil(t, err)
		user, err = db.GetUserFast(namespace, userID, true)
		if assert.Nil(t, err) {
			assert.True(t, optional.Bool(user.AdvertiseDefaultRoute))
			assert.True(t, optional.Bool(user.AutoAcceptRoutes))
			assert.True(t, optional.Bool(user.AutoApproveDevice))
			assert.True(t, optional.Bool(user.WgEnabled))
			assert.Equal(t, string(models.MeshVpnModeTenant), optional.String(user.MeshVpnMode))
		}

		login, err = db.GetUserLoginByUserIDAndLoginType(namespace, userID, types.LoginTypeEmail)
		if assert.Nil(t, err) && assert.NotNil(t, login) {
			assert.Equal(t, login.LoginName, newEmail)
		}
		login, err = db.GetUserLoginByUserIDAndLoginType(namespace, userID, types.LoginTypePhone)
		if assert.Nil(t, err) && assert.NotNil(t, login) {
			assert.Equal(t, login.LoginName, newPhone)
		}
	})

	t.Run("change-password", func(t *testing.T) {
		username := "test-change-password-username"
		user, err := addUser(namespace, username)
		if !assert.Nil(t, err) || !assert.NotNil(t, user) {
			return
		}
		userID := user.ID
		defer assertDeleteUser(t, namespace, userID)

		newPasswd := utils.NewPassword()
		changePasswdParam := newChangePasswdParam(userID.String(), username, newPasswd)
		_, err = handler.ChangePassword(adminToken, changePasswdParam)
		assert.Nil(t, err)

		login, err := db.GetUserLoginByUserIDAndLoginType(namespace, userID, types.LoginTypeUsername)
		if assert.Nil(t, err) && assert.NotNil(t, login) {
			assert.Nil(t, password.CompareToHash(newPasswd, login.Credential))
		}
	})

	t.Run("reset-password", func(t *testing.T) {
		username := "test-reset-password-username"
		user, err := addUser(namespace, username)
		if !assert.Nil(t, err) || !assert.NotNil(t, user) {
			return
		}
		userID := user.ID
		defer assertDeleteUser(t, namespace, userID)

		newPasswd := utils.NewPassword()
		resetPasswdParam := newResetPasswdParam(namespace, username, newPasswd)
		err = handler.ResetPassword(resetPasswdParam)
		if assert.NotNil(t, err) {
			assert.ErrorAs(t, err, &common.BadParamsErr{}) // Phone does not match.\ record.
		}

		phone := resetPasswdParam.Body.OneTimeCodeCheck.EmailOrPhone
		err = db.UpdateUserBaseInfo(namespace, userID, &types.UserBaseInfo{Mobile: &phone})
		if !assert.Nil(t, err) {
			return
		}
		token := utils.NewSmsToken(phone)
		err = token.Set("", resetPasswdParam.Body.OneTimeCodeCheck.Code, false)
		if !assert.Nil(t, err) {
			return
		}
		err = handler.ResetPassword(resetPasswdParam)
		assert.Nil(t, err)
		login, err := db.GetUserLoginByUserIDAndLoginType(namespace, userID, types.LoginTypeUsername)
		if assert.Nil(t, err) && assert.NotNil(t, login) {
			assert.Nil(t, password.CompareToHash(newPasswd, login.Credential))
		}
	})
	t.Run("delete-users", func(t *testing.T) {
		username := "test-delete-users-username"
		user, err := addUser(namespace, username)
		if !assert.Nil(t, err) || !assert.NotNil(t, user) {
			return
		}
		userID := user.ID
		defer db.DeleteUser(nil, namespace, userID)
		_, userToken := dbt.CreateTokenForTest(namespace, userID, username, false, nil)
		defer userToken.Delete()

		idList := []uuid.UUID{userID.UUID()}
		err = handler.DeleteUsers(userToken, api.DeleteUsersRequestObject{
			Body: &idList,
		})
		assert.Nil(t, err)
	})
	t.Run("delete-network-owner", func(t *testing.T) {
		username := "test-delete-network-owner-username"
		network := "test-delete-network-owner.org"
		otherUser, err := addTestUser(namespace, username+"-other", false, false, false, &network)
		if !assert.Nil(t, err) || !assert.NotNil(t, otherUser) {
			return
		}
		defer db.DeleteUser(nil, namespace, otherUser.ID)
		user, err := addTestUser(namespace, username, false, true, true, &network)
		if !assert.Nil(t, err) || !assert.NotNil(t, user) {
			return
		}
		userID := user.ID
		defer db.DeleteUser(nil, namespace, userID)
		_, userToken := dbt.CreateTokenForTest(namespace, userID, username, false, nil)
		defer userToken.Delete()

		idList := []uuid.UUID{otherUser.ID.UUID()}
		err = handler.DeleteUsers(userToken, api.DeleteUsersRequestObject{
			Body: &idList,
		})
		assert.Nil(t, err)
		_, err = db.GetUserFast(namespace, otherUser.ID, false)
		assert.ErrorIs(t, err, db.ErrUserNotExists)
		// Delete again should pass too.
		err = handler.DeleteUsers(userToken, api.DeleteUsersRequestObject{
			Body: &idList,
		})
		assert.Nil(t, err)
		// Now delete the network owner itself.
		idList = []uuid.UUID{userID.UUID()}
		err = handler.DeleteUsers(userToken, api.DeleteUsersRequestObject{
			Body: &idList,
		})
		assert.Nil(t, err)
		_, err = db.GetUserFast(namespace, user.ID, false)
		assert.ErrorIs(t, err, db.ErrUserNotExists)

		// Re-add to delete in one shot.
		otherUser, err = addTestUser(namespace, username+"-other", false, false, false, &network)
		if !assert.Nil(t, err) || !assert.NotNil(t, otherUser) {
			return
		}
		defer db.DeleteUser(nil, namespace, otherUser.ID)
		user, err = addTestUser(namespace, username, false, true, true, &network)
		if !assert.Nil(t, err) || !assert.NotNil(t, user) {
			return
		}
		userID = user.ID
		defer db.DeleteUser(nil, namespace, userID)
		_, userToken = dbt.CreateTokenForTest(namespace, userID, username, false, nil)
		defer userToken.Delete()
		err = handler.DeleteUsers(userToken, api.DeleteUsersRequestObject{
			Body: nil,
		})
		assert.Nil(t, err)
		_, err = db.GetUserFast(namespace, otherUser.ID, false)
		assert.ErrorIs(t, err, db.ErrUserNotExists)
		_, err = db.GetUserFast(namespace, otherUser.ID, false)
		assert.ErrorIs(t, err, db.ErrUserNotExists)

		// Re-add to delete in one shot with owner ID part of list.
		otherUser, err = addTestUser(namespace, username+"-other", false, false, false, &network)
		if !assert.Nil(t, err) || !assert.NotNil(t, otherUser) {
			return
		}
		defer db.DeleteUser(nil, namespace, otherUser.ID)
		user, err = addTestUser(namespace, username, false, true, true, &network)
		if !assert.Nil(t, err) || !assert.NotNil(t, user) {
			return
		}
		userID = user.ID
		defer db.DeleteUser(nil, namespace, userID)
		_, userToken = dbt.CreateTokenForTest(namespace, userID, username, false, nil)
		defer userToken.Delete()
		idList = []uuid.UUID{uuid.Nil, userID.UUID()}
		err = handler.DeleteUsers(userToken, api.DeleteUsersRequestObject{
			Body: &idList,
		})
		assert.Nil(t, err)
		_, err = db.GetUserFast(namespace, otherUser.ID, false)
		assert.ErrorIs(t, err, db.ErrUserNotExists)
		_, err = db.GetUserFast(namespace, otherUser.ID, false)
		assert.ErrorIs(t, err, db.ErrUserNotExists)
	})
}

func addUser(namespace, username string) (*types.User, error) {
	return addTestUser(namespace, username, false, false, false, nil)
}

func addTestUser(namespace, username string, isAdmin, isNetworkAdmin, isNetworkOwner bool, networkDomain *string) (*types.User, error) {
	var roles []string
	if isAdmin {
		roles = []string{types.NamespaceAdminRole}
	}
	if isNetworkAdmin {
		roles = append(roles, types.NetworkDomainAdminRole)
	}
	if isNetworkOwner {
		roles = append(roles, types.NetworkDomainOwnerRole)
	}
	return db.AddUser(
		namespace, "", "", "",
		[]types.UserLogin{
			{
				Namespace:  namespace,
				LoginName:  username,
				LoginType:  types.LoginTypeUsername,
				Credential: utils.NewPassword(),
			},
		},
		roles, nil, nil, networkDomain, nil,
	)
}
func addAdminUser(namespace string) (*types.User, error) {
	return addTestUser(namespace, namespace+"-admin", true, false, false, nil)
}

func assertDeleteUser(t *testing.T, namespace string, userID types.UserID) {
	assert.Nil(t, db.DeleteUser(nil, namespace, userID))
}

func newChangePasswdParam(userID, username string, newPasswd string) api.ChangePasswordRequestObject {
	phone := utils.New11DigitCode()
	code := utils.New6DigitCode()
	smsToken := utils.NewSmsToken(phone)
	smsToken.Set("", code, false)
	loginType := models.LoginTypeUsername
	return api.ChangePasswordRequestObject{
		Body: &models.ChangePassword{
			LoginName:   &username,
			LoginType:   &loginType,
			NewPassword: &newPasswd,
		},
		Params: models.ChangePasswordParams{
			Code:     &code,
			PhoneNum: &phone,
		},

		UserID: userID,
	}
}

func newResetPasswdParam(namespace, username, newPasswd string) api.ResetPasswordRequestObject {
	phone := utils.New11DigitCode()
	code := utils.New6DigitCode()
	smsToken := utils.NewSmsToken(phone)
	smsToken.Set("", code, false)
	return api.ResetPasswordRequestObject{
		Body: &models.ResetPassword{
			LoginName:   username,
			Namespace:   namespace,
			NewPassword: newPasswd,
			OneTimeCodeCheck: models.OneTimeCodeCheck{
				Code:         code,
				EmailOrPhone: phone,
				IsPhone:      true,
			},
		},
	}

}
func newRegisterParam(namespace, loginName string) api.RegisterUserRequestObject {
	phone := utils.New11DigitCode()
	code := utils.New6DigitCode()
	smsToken := utils.NewSmsToken(phone)
	smsToken.Set("", code, false)
	loginType := models.LoginTypeUsername
	return api.RegisterUserRequestObject{
		Body: &models.UserApprovalInfo{
			Phone:     &phone,
			Code:      code,
			Namespace: namespace,
			Login:     models.UserLogin{Login: loginName, LoginType: loginType},
		},
	}
}

func addUserApproval(namespace, username string) (*types.UserApproval, error) {
	r := models.UserApprovalInfo{
		Namespace: namespace,
		Login: models.UserLogin{
			Login:      username,
			Credential: optional.StringP(utils.NewPassword()),
			LoginType:  models.LoginTypeUsername,
		},
	}
	return db.NewUserApproval(&r, types.NilID, "", "")
}

func deleteUserApproval(t *testing.T, namespace string, approvalIDs []types.UserApprovalID) {
	assert.Nil(t, db.DeleteUserApprovals(namespace, approvalIDs))
}
func TestRegisterUser(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "test-register-user-namespace"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}

	t.Run("create", func(t *testing.T) {
		registerParam := newRegisterParam(namespace, "test-login-name")
		err = handler.RegisterUser(nil, registerParam)
		assert.Nil(t, err)
		getParam := api.GetUserApprovalsRequestObject{
			Params: models.GetUserApprovalsParams{
				Page:      optional.IntP(1),
				PageSize:  optional.IntP(10),
				Namespace: &namespace,
			},
		}
		total, list, err := handler.ApprovalRecords(adminToken, getParam)
		if assert.Nil(t, err) {
			assert.Equal(t, 1, total)
			assert.Equal(t, 1, len(list))
		}
	})
	t.Run("update", func(t *testing.T) {
		username := "user-test-update-approval"
		approval, err := addUserApproval(namespace, username)
		if !assert.Nil(t, err) || !assert.NotNil(t, approval) {
			return
		}
		defer deleteUserApproval(t, namespace, []types.UserApprovalID{approval.ID})
		updateParam := api.UpdateUserApprovalRequestObject{
			Body: &models.ApproveParams{
				IDList:   []uuid.UUID{approval.ID.UUID()},
				SetState: models.ApprovalStateApproved,
				Note:     "test-update-approval",
			},
		}
		err = handler.UpdateApprovals(adminToken, updateParam)
		if assert.Nil(t, err) {
			v, err := db.GetUserApproval(namespace, approval.ID)
			if assert.Nil(t, err) {
				if assert.NotNil(t, v) {
					assert.Equal(t, types.ApprovalStateApproved, v.State)
				}
			}
			newUser, err := db.GetUserByLoginName(namespace, username)
			if assert.Nil(t, err) && assert.NotNil(t, newUser) {
				defer db.DeleteUser(nil, namespace, newUser.ID)
			}
		}
	})

	t.Run("delete", func(t *testing.T) {
		username := "user-test-delete-approval"
		approval, err := addUserApproval(namespace, username)
		if !assert.Nil(t, err) || !assert.NotNil(t, approval) {
			return
		}
		defer deleteUserApproval(t, namespace, []types.UserApprovalID{approval.ID})
		deleteParam := api.DeleteUserApprovalsRequestObject{
			Body: &[]uuid.UUID{approval.ID.UUID()},
		}

		err = handler.DeleteApprovals(adminToken, deleteParam)
		assert.Nil(t, err)
		_, err = db.GetUserApproval(namespace, approval.ID)
		assert.ErrorIs(t, err, db.ErrUserApprovalNotExists)
	})
}

func addAlarm(namespace, username string, userID types.UserID) (*types.AlarmMessage, error) {
	return db.AddAlarm(namespace, &models.Notice{
		Username:  &username,
		UserID:    userID.UUIDP(),
		CreatedAt: optional.Int64P(time.Now().Unix()),
		State:     models.NoticeStateUnread,
		Type:      models.NoticeTypeAlarm,
	})
}
func delAlarms(t *testing.T, namespace string, idList []types.ID) {
	assert.Nil(t, db.DeleteAlarms(&namespace, nil, nil, nil, idList))
}

func TestAlarm(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "namespace-test-alarm"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	username := "username-test-alarm"
	user, err := addUser(namespace, username)
	if !assert.Nil(t, err) || !assert.NotNil(t, user) {
		return
	}
	defer db.DeleteUser(nil, namespace, user.ID)
	userID := user.ID

	_, userToken := dbt.CreateTokenForTest(namespace, userID, username, false, nil)
	defer userToken.Delete()

	t.Run("list", func(t *testing.T) {
		alarm, err := addAlarm(namespace, username, userID)
		if !assert.Nil(t, err) {
			return
		}
		defer delAlarms(t, namespace, []types.ID{alarm.ID})

		listNoticeParam := api.ListNoticeRequestObject{
			Params: models.ListNoticeParams{
				Page:     optional.IntP(1),
				PageSize: optional.IntP(10),
			},
			Category: models.NoticeCategoryAlarm,
		}

		noticeList, err := handler.ListNotice(userToken, listNoticeParam)
		if assert.Nil(t, err) {
			assert.Equal(t, 1, noticeList.Total)
		}
	})

	t.Run("update", func(t *testing.T) {
		alarm, err := addAlarm(namespace, username, userID)
		if !assert.Nil(t, err) {
			return
		}
		defer delAlarms(t, namespace, []types.ID{alarm.ID})
		updateParam := api.UpdateNoticesRequestObject{
			Category: models.NoticeCategoryAlarm,
			Body: &models.NoticeUpdate{
				IDList: []uuid.UUID{alarm.ID.UUID()},
				State:  models.NoticeStateRead,
			},
		}

		err = handler.UpdateNotices(userToken, updateParam)
		assert.Nil(t, err)

		v, err := db.GetAlarm(namespace, alarm.ID)
		if assert.Nil(t, err) && assert.NotNil(t, v) {
			assert.Equal(t, v.State, types.NoticeState(models.NoticeStateRead))
		}
	})

	t.Run("delete", func(t *testing.T) {
		alarm, err := addAlarm(namespace, username, userID)
		if !assert.Nil(t, err) {
			return
		}
		defer delAlarms(t, namespace, []types.ID{alarm.ID})
		deleteParam := api.DeleteNoticesRequestObject{
			Body:     &[]uuid.UUID{alarm.ID.UUID()},
			Category: models.NoticeCategoryAlarm,
		}
		err = handler.DeleteNotices(userToken, deleteParam)
		assert.Nil(t, err)
		_, err = db.GetAlarm(namespace, alarm.ID)
		assert.ErrorIs(t, err, db.ErrAlarmNotExists)
	})
}

func addDeviceApprovalAlert(namespace, username string, userID types.UserID) (*types.Alert, error) {
	id, err := types.NewID()
	if err != nil {
		return nil, err
	}
	return db.NewDeviceApprovalAlert(namespace, username, userID, id, "linux", "", "")
}

func delAlerts(t *testing.T, namespace string, alertType models.NoticeType, idList []types.AlertID) {
	assert.Nil(t, db.DeleteAlerts(namespace, nil, idList))
}

func TestAlert(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "namespace-test-alert"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	username := "username-test-alert"
	user, err := addUser(namespace, username)
	if !assert.Nil(t, err) || !assert.NotNil(t, user) {
		return
	}
	defer db.DeleteUser(nil, namespace, user.ID)
	userID := user.ID

	_, userToken := dbt.CreateTokenForTest(namespace, userID, username, false, nil)
	defer userToken.Delete()

	t.Run("list", func(t *testing.T) {
		alertType := models.NoticeTypeDeviceApproval
		alert, err := addDeviceApprovalAlert(namespace, username, userID)
		if !assert.Nil(t, err) || !assert.NotNil(t, alert) {
			return
		}
		defer delAlerts(t, namespace, alertType, []types.AlertID{alert.ID})

		listNoticeParam := api.ListNoticeRequestObject{
			Params: models.ListNoticeParams{
				Page:     optional.IntP(1),
				PageSize: optional.IntP(10),
				Type:     &alertType,
			},
			Category: models.NoticeCategoryAlert,
		}

		noticeList, err := handler.ListNotice(userToken, listNoticeParam)
		if assert.Nil(t, err) {
			assert.Equal(t, 1, noticeList.Total)
		}
	})

	t.Run("update", func(t *testing.T) {
		alertType := models.NoticeTypeDeviceApproval
		alert, err := addDeviceApprovalAlert(namespace, username, userID)
		if !assert.Nil(t, err) || !assert.NotNil(t, alert) {
			return
		}
		defer delAlerts(t, namespace, alertType, []types.AlertID{alert.ID})

		updateParam := api.UpdateNoticesRequestObject{
			Category: models.NoticeCategoryAlert,
			Body: &models.NoticeUpdate{
				IDList: []uuid.UUID{alert.ID.UUID()},
				State:  models.NoticeStateRead,
			},
		}
		err = handler.UpdateNotices(userToken, updateParam)
		if !assert.Nil(t, err) {
			return
		}
		v, err := db.GetAlert(namespace, alert.ID)
		if assert.Nil(t, err) && assert.NotNil(t, v) {
			assert.Equal(t, models.NoticeStateRead, v.State.ToModel())
		}
	})

	t.Run("delete", func(t *testing.T) {
		alertType := models.NoticeTypeDeviceApproval
		alert, err := addDeviceApprovalAlert(namespace, username, userID)
		if !assert.Nil(t, err) || !assert.NotNil(t, alert) {
			return
		}
		defer delAlerts(t, namespace, alertType, []types.AlertID{alert.ID})

		deleteParam := api.DeleteNoticesRequestObject{
			Body:     &[]uuid.UUID{alert.ID.UUID()},
			Category: models.NoticeCategoryAlert,
		}
		err = handler.DeleteNotices(userToken, deleteParam)
		assert.Nil(t, err)
		_, err = db.GetAlert(namespace, alert.ID)
		assert.ErrorIs(t, err, db.ErrAlertNotExists)
	})
}

func TestUserTrafficStats(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "namespace-test-user-traffic-stats"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	username := "username-test-user-traffic-stats"
	user, err := addUser(namespace, username)
	if !assert.Nil(t, err) || !assert.NotNil(t, user) {
		return
	}
	defer db.DeleteUser(nil, namespace, user.ID)
	userID := user.ID

	_, userToken := dbt.CreateTokenForTest(namespace, userID, username, false, nil)
	defer userToken.Delete()

	device, err := dbt.CreateDeviceForTest(namespace, userID, "10.0.0.1")
	if !assert.Nil(t, err) {
		return
	}
	deviceID := device.ID
	defer func() {
		assert.Nil(t, db.DeleteUserDevices(nil, namespace, userID, []types.DeviceID{deviceID}))
	}()

	var idList []types.DeviceWgTrafficStatsID
	defer func() {
		assert.Nil(t, db.DeleteDeviceWgTrafficStats(namespace, idList))
	}()
	var wgNames []string
	for i := 0; i < 10; i++ {
		wgName := fmt.Sprintf("wg-test-user-traffic-stats-%v", i)
		d, err := db.UpdateDeviceTrafficByWgData(namespace, deviceID, time.Now().Unix()-600, uint64(100), uint64(1000), wgName)
		if !assert.Nil(t, err) {
			return
		}
		wgNames = append(wgNames, wgName)
		idList = append(idList, d.ID)
	}
	deviceTrafficParam := api.GetDeviceTrafficRequestObject{
		UserID: userID.String(),
		Body:   &[]uuid.UUID{deviceID.UUID()},
	}
	trafficList, err := handler.UserDeviceTraffic(userToken, deviceTrafficParam)
	if assert.Nil(t, err) && assert.Equal(t, 1, len(trafficList)) {
		m := trafficList[0].WgStats
		if assert.NotNil(t, m) && assert.Equal(t, 10, len(*m)) {
			s := (*m)[0]
			assert.Equal(t, s.WgServer, wgNames[0])
			assert.Equal(t, uint64(100), optional.Uint64(s.TrafficStats.RxBytes))
			assert.Equal(t, uint64(1000), optional.Uint64(s.TrafficStats.TxBytes))
		}
	}
}

func TestUserSummaryStats(t *testing.T) {
	prometheusE, err := metrics.NewPrometheusEmulator()
	if !assert.Nil(t, err) {
		return
	}
	metrics.SetPrometheusClient(prometheusE)

	handler := newHandlerImpl(nil, testLogger)
	namespace := "namespace-test-user-summary-stats"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	adminUser, err := addAdminUser(namespace)
	if !assert.Nil(t, err) || !assert.NotNil(t, adminUser) {
		return
	}
	defer db.DeleteUser(nil, namespace, adminUser.ID)
	adminToken.UserID = adminUser.ID.UUID()

	username := "user-test-user-summary-stats"
	user, err := addUser(namespace, username)
	if !assert.Nil(t, err) || !assert.NotNil(t, user) {
		return
	}
	defer db.DeleteUser(nil, namespace, user.ID)
	userID := user.ID
	_, userToken := dbt.CreateTokenForTest(namespace, userID, username, false, nil)
	defer userToken.Delete()

	device, err := dbt.CreateDeviceForTest(namespace, userID, "10.0.0.1")
	if !assert.Nil(t, err) || !assert.NotNil(t, device) {
		return
	}
	deviceID := device.ID
	defer func() {
		assert.Nil(t, db.DeleteUserDevices(nil, namespace, userID, []types.DeviceID{deviceID}))
	}()

	prometheusE.SetUserSummaryStats(namespace, userID.String(), []models.SummaryStats{
		{
			UserCount:   optional.IntP(1),
			DeviceCount: optional.IntP(1),
		},
	})
	userSummaryParam := api.GetUserSummaryRequestObject{
		Params: models.GetUserSummaryParams{
			Days:   optional.IntP(1),
			UserID: optional.StringP(userID.String()),
		},
	}
	userSummaryList, err := handler.UserSummary(adminToken, userSummaryParam)
	if assert.Nil(t, err) && assert.Equal(t, 1, len(userSummaryList)) {
		if assert.NotNil(t, userSummaryList[0].UserCount) {
			assert.Equal(t, 1, *userSummaryList[0].UserCount)
		}
		if assert.NotNil(t, userSummaryList[0].DeviceCount) {
			assert.Equal(t, 1, *userSummaryList[0].DeviceCount)
		}
	}
	deviceSummaryParam := api.GetUserDeviceSummaryRequestObject{
		Params: models.GetUserDeviceSummaryParams{
			Days:   optional.IntP(1),
			UserID: optional.StringP(userID.String()),
		},
	}
	prometheusE.SetDeviceSummaryStats(namespace, userID.String(), device.ID.String(), []models.DeviceSummaryItem{
		{
			TrafficStats: &models.TrafficStats{},
		},
	})
	deviceList, err := handler.UserDeviceSummary(adminToken, deviceSummaryParam)
	if assert.Nil(t, err) && assert.Equal(t, 1, len(deviceList)) {
		if assert.NotNil(t, deviceList[0].DeviceID) {
			assert.Equal(t, device.ID.UUID(), *deviceList[0].DeviceID)
		}
	}
}

func TestProfileImg(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	var (
		namespace = "profile-namespace"
		username  = "profile-username"

		profileImg = "test-profile-img"
	)
	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	_, userToken := dbt.CreateTokenForTest(namespace, userID, username, false, nil)
	defer userToken.Delete()
	userIDStr := userID.String()

	t.Run("update", func(t *testing.T) {
		updateProfileParam := api.UpdateProfileImgRequestObject{
			Params: models.UpdateProfileImgParams{
				UserID: userID.StringP(),
			},
			Body: &models.UserProfile{
				Base64Image: ("test-profile-img-update"),
			},
		}
		defer func() {
			assert.Nil(t, db.DeleteUserProfile(namespace, userIDStr))
		}()
		err = handler.UpdateProfileImg(userToken, updateProfileParam)
		assert.Nil(t, err)

		updateProfileParam.Body.Base64Image = profileImg
		err = handler.UpdateProfileImg(userToken, updateProfileParam)
		assert.Nil(t, err)
		img, err := db.GetUserProfile(namespace, userIDStr)
		if assert.Nil(t, err) && assert.NotNil(t, img) {
			assert.Equal(t, profileImg, img.Base64Image)
		}
	})
	t.Run("get", func(t *testing.T) {
		getProfileParam := api.GetProfileImgRequestObject{
			Params: models.GetProfileImgParams{
				UserID: userID.StringP(),
			},
		}
		userProfile, err := handler.ProfileImg(userToken, getProfileParam)
		assert.Nil(t, err)
		if assert.NotNil(t, userProfile) {
			assert.Empty(t, userProfile.Base64Image)
		}
		m, err := db.AddUserProfile(namespace, userIDStr, &models.UserProfile{
			Base64Image: profileImg,
		})
		if assert.Nil(t, err) && assert.NotNil(t, m) {
			assert.Equal(t, profileImg, m.Base64Image)
		}
		defer func() {
			assert.Nil(t, db.DeleteUserProfile(namespace, userIDStr))
		}()
		m, err = handler.ProfileImg(userToken, getProfileParam)
		assert.Nil(t, err)
		if assert.NotNil(t, userProfile) {
			assert.Equal(t, profileImg, m.Base64Image)
		}
	})
	t.Run("delete", func(t *testing.T) {
		deleteProfileParam := api.DeleteProfileImgRequestObject{
			Params: models.DeleteProfileImgParams{
				UserID: &userIDStr,
			},
		}
		err = handler.DeleteProfileImg(userToken, deleteProfileParam)
		assert.Nil(t, err)
		m, err := db.AddUserProfile(namespace, userIDStr, &models.UserProfile{
			Base64Image: profileImg,
		})
		if assert.Nil(t, err) && assert.NotNil(t, m) {
			assert.Equal(t, profileImg, m.Base64Image)
		}
		defer func() {
			assert.Nil(t, db.DeleteUserProfile(namespace, userIDStr))
		}()
		err = handler.DeleteProfileImg(userToken, deleteProfileParam)
		assert.Nil(t, err)
	})
}

func TestAccessPoint(t *testing.T) {
	handler := newHandlerImpl(nil, testLogger)
	namespace := "namespace-test-access-point"
	username := "username-test-access-point"
	adminToken, err := addTenantAndAdminToken(namespace)
	defer delTenantAndAdminToken(t, namespace, adminToken)
	if !assert.Nil(t, err) {
		return
	}
	user, err := addUser(namespace, username)
	if !assert.Nil(t, err) || !assert.NotNil(t, user) {
		return
	}
	defer db.DeleteUser(nil, namespace, user.ID)
	userID := user.ID

	wgName0 := "wg-name-0"
	_, userToken := dbt.CreateTokenForTest(namespace, userID, username, false, nil)

	d := dt.NewEmulator()
	r := rt.NewEmulator()
	r.SetWgAccessPoints(namespace, "wg-id-001", []string{wgName0})
	s := common.NewSupervisorService(d, r, testLogger)
	common.NewWgService(d, s, r, testLogger)

	listParam := api.ListAccessPointRequestObject{
		UserID: userID.String(),
	}
	list, err := handler.ListAccessPoint(userToken, listParam)
	if assert.Nil(t, err) {
		for _, access := range list {
			fmt.Println("debug ", access.Name)
		}
	}
}
