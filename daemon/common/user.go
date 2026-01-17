// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package common

import (
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"errors"
	"fmt"
	"math"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
)

const (
	UserTypeAdmin = "admin"
	UserTypeUser  = "user"
)

func codeCheckInternalErr(err error) error {
	return fmt.Errorf("%w: failed to check code: %v", ErrInternalErr, err)
}

func wrongPhoneErr(phone string) error {
	return fmt.Errorf("%w: phone %v does not match", ErrModelPhoneInvalid, phone)
}

func wrongEmailErr(email string) error {
	return fmt.Errorf("%w: email %v does not match", ErrModelBadParameters, email)
}

func CheckUserOneTimeCode(namespace string, userID types.UserID, codeP, emailP, phoneP *string) (*types.User, error) {
	su, err := db.GetUserFast(namespace, userID, false)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to get user from db: %v", ErrInternalErr, err)
	}
	ub := &su.UserBaseInfo
	if codeP == nil || (phoneP == nil && emailP == nil) {
		return nil, ErrModelBadParameters
	}
	phone, email, code := ub.Mobile, ub.Email, *codeP
	if phoneP != nil {
		if *phoneP != optional.String(phone) {
			return nil, wrongPhoneErr(*phoneP)
		}
		valid, err := CheckSmsCode(*phoneP, code)
		if err != nil {
			return nil, codeCheckInternalErr(err)
		}
		if !valid {
			return nil, ErrModelInvalidSmsCode
		}
	}
	if emailP != nil {
		if *emailP != optional.String(email) {
			return nil, wrongEmailErr(*emailP)
		}
		valid, err := CheckEmailCode(*emailP, code)
		if err != nil {
			return nil, codeCheckInternalErr(err)
		}
		if !valid {
			return nil, ErrModelOneTimeCodeInvalid
		}
	}
	return su, nil
}

// Create default user tier if not yet exists.
func GetOrCreateDefaultUserTier() (*types.UserTier, error) {
	tier, err := db.GetUserTierByName(utils.DefaultUserTier)
	if err != nil {
		if !errors.Is(err, db.ErrUserTierNotExists) {
			return nil, err
		}
		tier, err = db.CreateUserTier(&types.UserTier{
			Name:           utils.DefaultUserTier,
			Description:    utils.DefaultUserTierDescription,
			MaxUserCount:   utils.DefaultUserTierMaxUserCount,
			MaxDeviceCount: utils.DefaultUserTierMaxDeviceCount,
		})
		if err != nil {
			return nil, err
		}
	}
	return tier, nil
}

func CreateUser(
	login *types.UserLogin, namespace, email, phone string, roles []string,
	attributes map[string][]string, userTier, networkDomain *string,
	isAdmin bool, logger *logrus.Entry,
) error {
	loginSlice := []types.UserLogin{*login}
	user, err := db.AddUser(
		namespace, email, phone, login.DisplayName, loginSlice, roles,
		attributes, userTier, networkDomain, nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create the new user in the database: %w", err)
	}
	login = &user.UserLogins[0]
	l, err := db.GetUserLogin(namespace, login.ID)
	if err != nil {
		return fmt.Errorf("failed to get the just created user login for %v: %w", login.LoginName, err)
	}
	s, _ := json.Marshal(l)
	logger.WithField("login", string(s)).Debugln("Login created successfully.")
	return nil
}

func NamespaceRootUserNetworkDomain(namespace string) string {
	return "system-internal." + namespace
}

func IsNamespaceRootUser(username string) bool {
	if username == "root" || username == "system-internal" {
		return true
	}
	return false
}

func GetOrCreateNamespaceRootUser(namespace string) (*types.User, error) {
	// Try to get "root" user first
	username := "root"
	user, err := db.GetUserByLoginName(namespace, username)
	if err == nil {
		return user, nil
	}
	// Try to get "system-internal" user next
	username = "system-internal"
	user, err = db.GetUserByLoginName(namespace, username)
	if err != nil {
		if errors.Is(err, db.ErrUserNotExists) || errors.Is(err, db.ErrUserLoginNotExists) {
			networkDomain := NamespaceRootUserNetworkDomain(namespace)
			user, err = db.AddUser(
				namespace, username+"@"+namespace+".internal", "",
				"System Internal", []types.UserLogin{
					{
						LoginName:   username,
						LoginType:   types.LoginTypeUsername,
						DisplayName: username,
						Namespace:   namespace,
						Credential:  utils.NewPassword(),
					},
				},
			nil, nil, nil, &networkDomain, nil)
		}
	}
	return user, err
}

func ChangeExitNode(user *types.User, wgInfo *types.WgInfo, newWgName string, token *utils.UserTokenData, logger *logrus.Entry) (exitNodeID *types.ID, err error) {
	namespace, userID, newWgID := wgInfo.Namespace, wgInfo.UserID, ""
	if !IsGatewaySupported(namespace, user, userID, wgInfo.DeviceID) {
		return nil, nil
	}

	if newWgName != "" {
		wg, err := WgClientByName(namespace, newWgName)
		if err != nil {
			return nil, fmt.Errorf("failed to get wg gateway by name: %w", err)
		}
		newWgID = wg.ID()
		exitNodeID = optional.P(wg.ExitNodeID())
	}

	oldWgID, oldWgName, wgDevice := wgInfo.WgID, wgInfo.WgName, wgInfo.ToModel()
	if err = MoveDeviceToNewWg(wgDevice, oldWgID, oldWgName, newWgID, newWgName); err != nil {
		err = fmt.Errorf("failed to move device to new wg: %w", err)
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		logger.Debugf("Rollback device to old wg %v in wg agent", oldWgName)
		if newErr := MoveDeviceToNewWg(wgDevice, newWgID, newWgName, oldWgID, oldWgName); newErr != nil {
			logger.WithError(newErr).Errorln("Failed to restore device to old wg.")
		}
	}()

	if err = db.UpdateWgInfoWgNode(wgInfo.DeviceID, newWgID, newWgName); err != nil {
		err = fmt.Errorf("failed to update wg ino in db: %w", err)
		return nil, err
	}
	defer func() {
		if err == nil {
			return
		}
		logger.Debugf("Rollback device to old wg %v in db", oldWgName)
		if newErr := db.UpdateWgInfoWgNode(wgInfo.DeviceID, oldWgID, oldWgName); newErr != nil {
			logger.WithError(err).Errorln("Failed to recover wg info to old wg.")
		}
	}()
	if token != nil {
		token.WgServerName = newWgName
		if err = utils.UpdateUserToken(token.Token, token); err != nil {
			err = fmt.Errorf("failed to update user token: %w", err)
			return nil, err
		}
	}
	if err = MoveDeviceToNewFw(namespace, userID, wgInfo.DeviceID, *wgInfo.IP(), oldWgName, newWgName); err != nil {
		if errors.Is(err, ErrFwConfigNotExists) {
			logger.WithError(err).Infoln("Skip moving fw since there is no fw exists for the new wg")
			err = nil
		} else {
			err = fmt.Errorf("failed to move device to fw: %w", err)
			return nil, err
		}
	}
	logger.WithField("new-wg", newWgName).Infoln("moved to new wg")
	return
}

func NewSysadminTenant(namespace, creatorName, createNote string) (*types.TenantConfig, error) {
	// namespace should not be the default namespace
	if namespace == utils.DefaultNamespace {
		return nil, fmt.Errorf("cannot create sysadmin tenant in default namespace")
	}
	tier, err := GetOrCreateDefaultUserTier()
	if err != nil {
		return nil, err
	}
	tenant := &types.TenantConfig{
		Name:      "Sysadmin namespace",
		Namespace: namespace,
		UserTierID: &tier.ID,
	}
	if err := db.NewTenant(tenant, types.NilID, creatorName, createNote); err != nil {
		return nil, err
	}
	return tenant, nil
}

func NewDefaultTenant(creatorName, createNote string) (*types.TenantConfig, error) {
	tier, err := GetOrCreateDefaultUserTier()
	if err != nil {
		return nil, err
	}

	namespace := utils.DefaultNamespace
	tenant := &types.TenantConfig{
		Name:      "Default namespace",
		Namespace: namespace,
		TenantSetting: types.TenantSetting{
			MaxUser:          math.MaxUint32, // Limit by user pay plan
			MaxDevice:        math.MaxUint32, // Limit by user pay plan
			MaxDevicePerUser: math.MaxUint32, // Limit by user pay plan
		},
		UserTierID: &tier.ID,
	}
	if err := db.NewTenant(tenant, types.NilID, creatorName, createNote); err != nil {
		return nil, err
	}
	return tenant, nil
}