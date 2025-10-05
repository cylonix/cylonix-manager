// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"

	"github.com/sirupsen/logrus"
)

func newUserApproval(
	r *models.UserApprovalInfo, loginNames []string,
	approverID types.UserID, approverName string, logger *logrus.Entry,
	okIfRegistered bool,
) (*types.UserApproval, error) {
	exists, approval, err := userLoginExists(r.Namespace, loginNames, true)
	if err != nil {
		logger.WithError(err).Errorln("Failed to check if user exists.")
		return nil, common.ErrInternalErr
	}
	if exists {
		logger.WithError(common.ErrModelUserExists).Errorln("Failed to register new user.")
		return nil, common.ErrModelUserExists
	}
	if approval != nil {
		if okIfRegistered {
			return approval, nil
		}
		logger.WithError(common.ErrModelUserRegistered).Errorln("Failed to register new user.")
		switch string(r.Login.LoginType) {
		case string(models.LoginTypeEmail):
			return nil, common.ErrModelEmailRegistered
		case string(models.LoginTypeGoogle):
			return nil, common.ErrModelGmailRegistered
		case string(models.LoginTypePhone):
			return nil, common.ErrModelPhoneRegistered
		case string(models.LoginTypeUsername):
			return nil, common.ErrModelUsernameRegistered
		case string(models.LoginTypeWechat):
			return nil, common.ErrModelWeChatRegistered
		}
		return nil, common.ErrModelUserRegistered
	}

	// A real new user. Add a record for approval book keeping and the user.
	approval, err = db.NewUserApproval(r, approverID, approverName, "")
	if err != nil {
		logger.WithError(err).Errorln("Failed to add user approval record.")
		return nil, common.ErrInternalErr
	}
	r = approval.ToModel()
	alert, err := db.NewUserApprovalAlert(
		r.Namespace, approval.ID, optional.String(r.Email),
		optional.String(r.Phone), "", loginNames,
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to add user approval alert.")
		return nil, common.ErrInternalErr
	}
	sendNewUserApprovalApprovalAlert(
		r.Namespace, approval.ID, alert.ID,
		optional.String(r.Email), optional.String(r.Phone), "", loginNames,
	)
	return approval, nil
}

func modelsAttributesToMap(list models.AttributeList) map[string][]string {
	m := make(map[string][]string)
	for _, kv := range list {
		m[kv.Key] = kv.Value
	}
	return m
}

func createNewUserFromRegistration(
	namespace string, approvalID types.UserApprovalID, logger *logrus.Entry,
) error {
	approval, err := db.GetUserApproval(namespace, approvalID)
	if err != nil {
		return errors.New("failed to get approval record")
	}
	r := approval.ToModel()
	var login *types.UserLogin
	login = login.FromModel(namespace, &r.Login)
	attributes := map[string][]string{}
	if r.Attributes != nil {
		attributes = modelsAttributesToMap(*r.Attributes)
	}
	email, phone := optional.String(r.Email), optional.String(r.Phone)
	return common.CreateUser(
		login, namespace, email, phone, optional.StringSlice(r.Roles),
		attributes, nil /* user tier to inherits from tenant config */,
		nil /* user network domain interits from tenant config */,
		r.IsAdmin, logger,
	)
}

// UserLoginExists checks if any of the login has been used by a user or pending
// registration approval. No record found is not an error.
func userLoginExists(
	namespace string, loginNames []string, checkRegister bool,
) (loginExists bool, approval *types.UserApproval, err error) {
	loginExists, err = db.UserLoginExists(namespace, loginNames)
	if err == nil {
		if loginExists {
			return true, nil, nil
		}
	} else {
		if !errors.Is(err, db.ErrUserNotExists) {
			err = common.ErrInternalErr
			return
		}
		err = nil
	}

	// Not used by any user. Check registration records.
	if !checkRegister {
		return
	}
	for _, loginName := range loginNames {
		approval, err = db.UserApprovalExists(namespace, loginName)
		if err != nil {
			err = common.ErrInternalErr
			return
		}
		if approval != nil {
			return
		}
	}
	return
}
