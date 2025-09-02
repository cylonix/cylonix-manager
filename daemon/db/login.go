// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"strings"

	pw "github.com/cylonix/utils/password"
	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
)

var (
	ErrBadLoginID              = errors.New("invalid login ID")
	ErrBadLoginUserInfo        = errors.New("invalid login info")
	ErrBadUserBaseInfo         = errors.New("invalid user base info")
	ErrInvalidLoginType        = errors.New("invalid login type")
	ErrInvalidPasswordHistory  = errors.New("invalid password history")
	ErrSamePassword            = errors.New("password is the same")
	ErrSamePhone               = errors.New("phone is the same")
	ErrWechatAuthInfoNotExists = errors.New("wechat auth info does not exists")
)

// UpdateLoginUsernamePassword updates the login username and/or password.
// Returns
// - ErrSamePassword if password not changed.
// - ErrInvalidLoginType if it is not a password login
// - Other errors if failed to hash or save to DB.
func UpdateLoginUsernamePassword(l *types.UserLogin, username, password string) error {
	if l.Password() == "" {
		return ErrInvalidLoginType
	}
	if username == "" && password == "" {
		return ErrBadParams
	}
	credential := ""
	if password != "" {
		hash, err := pw.NewHash(password)
		if err != nil {
			return fmt.Errorf("failed to update login password: %w", err)
		}
		if pw.CompareToHash(password, l.Credential) == nil {
			return ErrSamePassword
		}
		credential = string(hash)
	}
	update := types.UserLogin{
		LoginName:  username,
		Credential: credential,
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	namespace := l.Namespace
	tx = tx.Begin()
	defer tx.Rollback()

	tx = tx.Model(l).Where("id = ? and namespace = ?", l.ID, namespace)
	if err = tx.Updates(&update).Error; err != nil {
		return err
	}
	if err = cleanLoginCache(l); err != nil {
		return err
	}

	if err = tx.Commit().Error; err != nil {
		return err
	}
	return nil
}

// UpdateLoginPhone updates the login phone number.
// Returns
// - ErrSamePhone if phone is not changed.
// - ErrInvalidLoginType if it is not a phone login
// - Other errors if failed to hash or save to DB.
func UpdateLoginPhone(l *types.UserLogin, phone string) error {
	phone = strings.TrimSpace(phone)
	if l.LoginType != types.LoginTypePhone {
		return ErrInvalidLoginType
	}
	if phone == "" {
		return ErrBadParams
	}
	if l.Phone() == phone {
		return ErrSamePhone
	}
	lu := &types.UserLogin{
		LoginName: phone,
	}
	tx, err := getPGconn()
	tx = tx.Begin()
	defer tx.Rollback()

	if err != nil {
		return err
	}
	namespace := l.Namespace
	login := types.UserLogin{Model: types.Model{ID: l.ID}, Namespace: namespace}
	if err = tx.Model(&types.UserLogin{}).Where(&login).Updates(lu).Error; err != nil {
		return err
	}
	ub := types.UserBaseInfo{Model: types.Model{ID: l.UserID}, Namespace: namespace}
	err = tx.Model(&types.UserBaseInfo{}).Where(&ub).Updates(&types.UserBaseInfo{Mobile: &phone}).Error
	if err != nil {
		return err
	}
	if err = cleanLoginCache(l); err != nil {
		return err
	}
	if err = tx.Commit().Error; err != nil {
		return err
	}
	return nil
}

func GetUserLogin(namespace string, loginID types.LoginID) (*types.UserLogin, error) {
	if loginID == types.NilID {
		return nil, ErrBadLoginID
	}
	ret := &types.UserLogin{}
	err := getUserLogin(namespace, loginID, ret)
	return ret, err
}
func getUserLogin(namespace string, loginID types.LoginID, result interface{}) error {
	if err := postgres.SelectFirst(result, "id = ? and namespace = ?", loginID, namespace); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserLoginNotExists
		}
		logger.WithError(err).Debugln("get user login")
		return err
	}
	return nil
}

// GetUserLoginByLoginName returns the first login matches.
// Namespace is optional.
func getUserLoginByLoginName(namespace, loginName string, result interface{}) error {
	var err error
	if namespace == "" {
		err = postgres.SelectFirst(result, "login_name = ?", loginName)
	} else {
		err = postgres.SelectFirst(result, "namespace = ? and login_name = ?", namespace, loginName)
	}
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserLoginNotExists
		}
		return err
	}
	return nil
}

func LoginNameToUserID(namespace, loginName string) (types.UserID, error) {
	l := &types.UserLogin{}
	if err := getUserLoginByLoginName(namespace, loginName, l); err != nil {
		return types.NilID, err
	}
	return l.UserID, nil
}

func IsLoginAvailable(namespace, loginName string, loginType types.LoginType) (bool, error) {
	result := &types.UserLogin{}
	namespace = types.NormalizeNamespace(namespace)
	loginName = types.NormalizeLoginName(loginName)
	err := postgres.SelectFirst(result, "namespace = ? and login_name = ? and login_type = ?", namespace, loginName, loginType)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// UserLoginExists check if a list of login names e.g. username, phone, email
// et al is already in use. Not existing is not an error.
func UserLoginExists(namespace string, loginNames []string) (bool, error) {
	result := &types.UserLogin{}

	if len(loginNames) <= 0 || namespace == "" {
		return false, errors.New("empty namespace or login name list")
	}
	var err error

	for i := range loginNames {
		loginNames[i] = types.NormalizeLoginName(loginNames[i])
	}

	if len(loginNames) == 1 {
		err = postgres.SelectFirst(result, "namespace = ? and login_name = ?", namespace, loginNames[0])
	} else {
		err = postgres.SelectFirst(result, "namespace = ? and login_name in ?", namespace, loginNames)
	}
	if err == nil {
		return true, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return false, nil
	}
	return false, err
}

// GetUserLoginByUserIDAndLoginType returns the first login matches.
// For username login, it will return the only record.
// Namespace is optional
func GetUserLoginByUserIDAndLoginType(namespace string, userID types.UserID, loginType types.LoginType) (*types.UserLogin, error) {
	var (
		result = &types.UserLogin{}
		where  = "namespace = ? and user_id = ? and login_type = ?"
		err    error
	)
	namespace = types.NormalizeNamespace(namespace)
	if namespace == "" {
		where = "user_id = ? and login_type = ?"
		err = postgres.SelectFirst(result, where, userID, loginType)
	} else {
		err = postgres.SelectFirst(result, where, namespace, userID, loginType)
	}
	if err == nil {
		return result, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserLoginNotExists
	}
	return nil, err
}

// RegistrationState returns the registration state of a login
// Nil result without error means the login is not never registered before.
func LoginRegistrationState(namespace, loginName string) (*models.ApprovalState, error) {
	exists, err := UserLoginExists(namespace, []string{loginName})
	if err == nil && exists {
		state := models.ApprovalStateApproved
		return &state, nil
	}
	if !errors.Is(err, ErrUserNotExists) {
		return nil, err
	}

	// Not found in user logins. Check registration approval records.
	state, err := GetUserApprovalState(namespace, loginName)
	if err == nil {
		if *state == types.ApprovalStateApproved {
			// Can't be missing in the login database but approved.
			return nil, ErrInternalErr
		}
		v := state.ToModel()
		return &v, nil
	}
	if errors.Is(err, ErrUserApprovalNotExists) {
		return nil, nil
	}
	return nil, err
}

func GetUserLoginByUserID(namespace string, userID types.UserID) ([]*types.UserLogin, error) {
	ret := []*types.UserLogin{}
	err := getUserLoginByUserID(namespace, userID, &ret)
	if len(ret) == 0 {
		return nil, ErrUserLoginNotExists
	}
	return ret, err
}
func getUserLoginByUserID(namespace string, userID types.UserID, result interface{}) error {
	err := postgres.SelectAll(result, "namespace = ? and user_id = ?", namespace, userID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserLoginNotExists
		}
	}
	return err
}
func GetUserLoginByUserIDFast(namespace string, userID types.UserID) ([]*types.UserLogin, error) {
	ret := []*types.UserLogin{}
	err := getDataFromCache(
		namespace, userLoginCacheByUserIDPath, &userID, nil,
		&ret, func(namespace string, userID *types.UserID, _ *string, result interface{}) error {
			if userID == nil {
				return errors.New("nil user id")
			}
			return getUserLoginByUserID(namespace, *userID, result)
		},
	)
	if err != nil {
		if errors.Is(err, errCacheNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserLoginNotExists
		}
		return nil, err
	}
	if len(ret) == 0 {
		return nil, ErrUserLoginNotExists
	}
	return ret, nil
}

// CreateUserLogin adds a new user login. It also assigns the login ID base on
// the login name. If a login ID is set, it will check if it matches.
func CreateUserLogin(loginUser *types.UserLogin) error {
	if loginUser.Namespace == "" ||
		loginUser.LoginName == "" ||
		loginUser.UserID == types.NilID {
		return fmt.Errorf("%w: namespace=%v login_name=%v user_id=%v",
			ErrBadLoginUserInfo, loginUser.Namespace, loginUser.LoginName, loginUser.UserID)
	}
	if err := loginUser.Model.SetIDIfNil(); err != nil {
		return err
	}

	l, err := loginUser.Normalize()
	if err != nil {
		return err
	}
	namespace, userID, loginName := l.Namespace, l.UserID, l.LoginName
	_, err = GetUserLoginByLoginName(namespace, loginName)
	if err == nil {
		return ErrUserLoginExists
	}
	if err != ErrUserLoginNotExists {
		return err
	}

	tx, err := postgres.Connect()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	if err := tx.
		Model(&types.User{Model: types.Model{ID: userID}}).
		Where(&types.User{Namespace: namespace}).
		Association("UserLogins").
		Append(l); err != nil {
		return err
	}

	switch loginUser.LoginType {
	case types.LoginTypePhone:
		err = tx.
			Model(&types.UserBaseInfo{Model: types.Model{ID: userID}}).
			Update("mobile", loginName).
			Error
	case types.LoginTypeEmail:
		err = tx.
			Model(&types.UserBaseInfo{Model: types.Model{ID: userID}}).
			Update("email", loginName).
			Error
	}
	if err != nil {
		return err
	}
	if err = cleanLoginCache(l); err != nil {
		return err
	}
	return tx.Commit().Error
}

func cleanLoginCache(login *types.UserLogin) error {
	namespace := login.Namespace
	loginID := login.ID.String()
	loginName := login.LoginName
	if err := cleanUserCache(namespace, login.UserID); err != nil {
		return err
	}
	if err := cleanCache(namespace, userLoginCacheByLoginIDPath, nil, &loginID); err != nil {
		return err
	}
	if err := cleanCache(namespace, userLoginCacheByLoginNamePath, nil, &loginName); err != nil {
		return err
	}
	return nil
}

func DeleteUserLogin(namespace string, userID types.UserID, loginID types.LoginID) error {
	login, err := GetUserLoginFast(namespace, loginID)
	if err != nil {
		if errors.Is(err, ErrUserLoginNotExists) {
			return nil
		}
		return err
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	err = tx.Delete(&types.UserLogin{}, "namespace = ? and id = ?", namespace, loginID).Error
	if err != nil {
		return err
	}
	if err = cleanLoginCache(login); err != nil {
		return err
	}

	return tx.Commit().Error
}
func DeleteUserLoginByUserID(namespace string, userID types.UserID) error {
	logins, err := GetUserLoginByUserIDFast(namespace, userID)
	if err != nil {
		if errors.Is(err, ErrUserLoginNotExists) {
			return nil
		}
		return err
	}
	if logins == nil {
		return nil
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	err = tx.Delete(&types.UserLogin{}, "namespace = ? and user_id = ?", namespace, userID).Error
	if err != nil {
		return err
	}
	for _, l := range logins {
		if err = cleanLoginCache(l); err != nil {
			return err
		}
	}
	return tx.Commit().Error
}
func DeleteUserLoginCheckUserID(namespace string, userID types.UserID, loginName string) error {
	loginInfo, err := GetUserLoginByLoginName(namespace, loginName)
	if err != nil {
		return err
	}
	if loginInfo.UserID != userID {
		return ErrUserLoginUsedByOtherUser
	}
	return DeleteUserLogin(namespace, userID, types.LoginID(loginInfo.ID))
}

// GetUserEmailOrPhone does not return error if there is no email/phone
// login exists for the user.
func GetUserEmailOrPhone(namespace string, userID types.UserID, phone bool) (*string, error) {
	loginType := types.LoginTypeEmail
	if phone {
		loginType = types.LoginTypePhone
	}
	login, err := GetUserLoginByUserIDAndLoginType(namespace, userID, loginType)
	if err == nil {
		return &login.LoginName, nil
	}
	if errors.Is(err, ErrUserLoginNotExists) {
		return nil, nil
	}
	return nil, err
}

func GetUserLoginFast(namespace string, loginID types.LoginID) (*types.UserLogin, error) {
	return getUserLoginFast(namespace, loginID, false /* with fallback */)
}
func GetUserLoginByLoginName(namespace, loginName string) (*types.UserLogin, error) {
	ret := &types.UserLogin{}
	err := getUserLoginByLoginName(namespace, loginName, ret)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserLoginNotExists
		}
		return nil, err
	}
	return ret, nil
}
func GetUserLoginCacheOnly(namespace string, loginID types.LoginID) (*types.UserLogin, error) {
	return getUserLoginFast(namespace, loginID, true /* no fallback */)
}
func getUserLoginFast(namespace string, loginID types.LoginID, cacheOnly bool) (*types.UserLogin, error) {
	if loginID == types.NilID {
		return nil, ErrBadLoginID
	}
	callback := func(namespace string, _ *types.UserID, loginIDStr *string, result interface{}) error {
		loginID, err := types.ParseLoginID(optional.String(loginIDStr))
		if err != nil {
			return err
		}
		return getUserLogin(namespace, loginID, result)
	}
	if cacheOnly {
		callback = nil
	}
	ret := &types.UserLogin{}
	loginIDStr := loginID.String()
	if err := getDataFromCache(
		namespace, userLoginCacheByLoginIDPath, nil, &loginIDStr, ret, callback,
	); err != nil {
		if errors.Is(err, errCacheNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserLoginNotExists
		}
		logger.WithError(err).Debugln("get user login fast")
		return nil, err
	}
	return ret, nil
}

func GetLoginName(namespace string, userID types.UserID) (string, error) {
	logins, err := GetUserLoginByUserIDFast(namespace, userID)
	if err != nil {
		return "", err
	}
	if len(logins) <= 0 {
		return "", ErrUserLoginNotExists
	}
	return logins[0].LoginName, nil
}
