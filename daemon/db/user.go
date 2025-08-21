// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type UserMetricCount struct {
	UserID types.UserID
	Total  int64
}

func GetUserList(
	namespace *string, filterBy, filterValue, contain, sortBy, sortDesc *string,
	wgEnable *bool, forUserIDs []types.UserID, page, pageSize *int,
) ([]*types.User, int64, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, 0, err
	}
	ret := []*types.User{}
	var total int64

	pg = pg.Model(&types.User{})
	if len(forUserIDs) > 0 {
		if len(forUserIDs) == 1 {
			pg = pg.Where("id = ?", forUserIDs[0])
		} else {
			pg = pg.Where("id in ?", forUserIDs)
		}
	}
	if namespace != nil {
		pg = pg.Where("namespace = ? ", *namespace)
	}
	if filterBy != nil && *filterBy != "" && filterValue != nil {
		if *filterBy == "is_admin_user" || *filterBy == "is_sys_admin" {
			f := false
			switch *filterValue {
			case "true", "1", "yes", "TRUE", "YES":
				f = true
			case "false", "0", "no", "FALSE", "NO":
				f = false
			default:
				return nil, 0, fmt.Errorf("invalid value for filter '%s': %s", *filterBy, *filterValue)
			}
			pg = filterExact(pg, filterBy, f)
		} else {
			pg = filter(pg, filterBy, filterValue)
		}
	}
	if wgEnable != nil {
		pg = pg.Where("wg_enabled = ?", *wgEnable)
	}
	pg = pg.
		Preload("Labels").
		Preload("UserBaseInfo").
		Preload("UserLogins").
		Preload("UserTier")
	if err = pg.Count(&total).Error; err != nil {
		return nil, 0, err
	}
	pg = postgres.Sort(pg, sortBy, sortDesc)
	pg = postgres.Page(pg, total, page, pageSize)
	if err = pg.Find(&ret).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, ErrUserNotExists
		}
		return nil, 0, err
	}
	return ret, total, nil
}

func SearchUser(namespace string, username, email, phone *string) (*types.User, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	if username != nil {
		login, err := GetUserLoginByLoginName(namespace, *username)
		if err != nil {
			return nil, err
		}
		return GetUserWithBaseInfoFast(namespace, login.UserID)
	}
	if email != nil {
		rst := &types.UserBaseInfo{}
		pg = pg.Model(rst)
		if err = pg.First(rst, "namespace = ? && email = ?", namespace, *email).Error; err != nil {
			return nil, err
		}
		return GetUserWithBaseInfoFast(namespace, rst.UserID)
	}
	if phone != nil {
		rst := &types.UserBaseInfo{}
		pg = pg.Model(rst)
		if err = pg.First(rst, "namespace = ? && mobile = ?", namespace, *phone).Error; err != nil {
			return nil, err
		}
		return GetUserWithBaseInfoFast(namespace, rst.UserID)
	}
	return nil, ErrBadParams
}

func GetUser(userID types.UserID, rst interface{}) error {
	db, err := getUserPreloadConn()
	if err != nil {
		return err
	}
	if err = db.Model(&types.User{}).
		First(rst, "id = ?", userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotExists
		}
		return err
	}
	return nil
}

func GetUserBaseInfoList(namespace string, userIDs []types.UserID) ([]types.UserBaseInfo, error) {
	tx, err := getPGconn()
	if err != nil {
		return nil, err
	}
	var ret []types.UserBaseInfo
	err = tx.Model(&types.UserBaseInfo{}).
		Where("namespace = ? and id in ?", namespace, userIDs).
		Find(&ret).
		Error
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func GetUserIDList(tx *gorm.DB, namespace string, network *string) ([]types.UserID, error) {
	var userIDs []types.UserID
	query := tx.Model(&types.User{}).Select("id").Where("namespace = ?", namespace)
	if network != nil {
		query = query.Where("network = ?", *network)
	}
	err := query.Find(&userIDs).Error
	if err != nil {
		return nil, err
	}
	return userIDs, nil
}

func GetUserFast(namespace string, userID types.UserID, withDetails bool) (*types.User, error) {
	if !withDetails {
		return GetUserWithBaseInfoFast(namespace, userID)
	}
	ret := &types.User{}
	err := getDataFromCache(
		namespace, userCacheByUserIDPath, &userID, nil, ret,
		func(namespace string, userID *types.UserID, _ *string, rst interface{}) error {
			if userID == nil {
				return errors.New("nil user id")
			}
			err := GetUser(*userID, rst)
			if err != nil {
				return err
			}
			user, ok := rst.(*types.User)
			if !ok {
				return fmt.Errorf("failed to cast result to *types.User")
			}
			if user.Namespace != namespace {
				return fmt.Errorf("%w: namespace is '%v', want '%v'", ErrNamespaceMismatch, user.Namespace, namespace)
			}
			return nil
		},
	)
	if err != nil {
		if errors.Is(err, errCacheNotFound) {
			return nil, ErrUserNotExists
		}
		return nil, err
	}
	if ret.Namespace != namespace {
		return nil, fmt.Errorf("%w: namespace is '%v', want '%v'", ErrNamespaceMismatch, ret.Namespace, namespace)
	}
	return ret, nil
}

func FindUserInBatches(namespace string, size int, processFunc func(user *types.User) (bool, error)) error {
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	results := make([]*types.User, size)
	pg = pg.Model(&types.User{}).Where("namespace = ?", namespace)
	err = pg.FindInBatches(&results, size, func(tx *gorm.DB, batch int) error {
		modified := false
		for _, result := range results {
			ret, err := processFunc(result)
			if err != nil {
				// Returning an error will stop further batch processing
				return err
			}
			if ret {
				modified = true
			}
		}

		// Save changes to the records in the current batch
		if modified {
			tx.Save(&results)
		}

		return nil
	}).Error
	return pgCheckError(err, ErrUserNotExists)
}

func GetUserIDsWithLabelIDs(labelIDs []string) ([]uint, error) {
	db, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	userIDs := []uint{}
	err = db.Raw(`select user_id from user_label_relation where label_id in ?`, labelIDs).Find(&userIDs).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrUserNotExists
		}
		return nil, err
	}
	return userIDs, nil
}
func GetUserByLoginName(namespace, loginName string) (*types.User, error) {
	userLogin, err := GetUserLoginByLoginName(namespace, loginName)
	if err != nil {
		return nil, err
	}
	return GetUserFast(namespace, userLogin.UserID, false)
}

func getUserWithBaseInfo(userID types.UserID, rst interface{}) error {
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	err = pg.Model(&types.User{}).Preload("UserBaseInfo").
		Where("id = ?", userID).First(rst).Error
	if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrUserNotExists
	}
	return err
}
func GetUserWithBaseInfoFast(namespace string, userID types.UserID) (*types.User, error) {
	ret := &types.User{}
	err := getDataFromCache(
		namespace, userWithBaseInfoCacheByUserIDPath, &userID, nil, ret,
		func(namespace string, userID *types.UserID, _ *string, rst interface{}) error {
			if userID == nil {
				return errors.New("nil user id")
			}
			return getUserWithBaseInfo(*userID, rst)
		},
	)
	if err != nil {
		if errors.Is(err, errCacheNotFound) {
			return nil, ErrUserNotExists
		}
		return nil, err
	}
	if ret.Namespace != namespace {
		return nil, fmt.Errorf("%w: namespace is '%v', want '%v'", ErrNamespaceMismatch, ret.Namespace, namespace)
	}
	return ret, nil
}

func GetUsernameByEmail(namespace, email string) (string, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return "", err
	}
	namespace = types.NormalizeNamespace(namespace)
	pg = pg.Model(&types.UserBaseInfo{Namespace: namespace})
	user := &types.UserBaseInfo{}
	err = pg.Where("namespace = ? and email = ?", namespace, email).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", ErrUserNotExists
		}
		return "", fmt.Errorf("failed to get user: %w", err)
	}
	login, err := GetUserLoginByUserIDAndLoginType(namespace, user.UserID, types.LoginTypeUsername)
	if err != nil {
		return "", fmt.Errorf("failed to get user login: %w", err)
	}
	return login.LoginName, nil
}

func getUserPreloadConn() (*gorm.DB, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	return pg.
		Preload("Labels").
		Preload("FwStats").
		Preload("UserLogins").
		Preload("UserTier").
		Preload("UserBaseInfo"), nil
}
func checkUserCreationError(err error) error {
	if errors.Is(err, gorm.ErrDuplicatedKey) || strings.Contains(err.Error(), "duplicate key value") {
		if strings.Contains(err.Error(), "phone") {
			return ErrUserWithPhoneExists
		}
		if strings.Contains(err.Error(), "email") {
			return ErrUserWithEmailExists
		}
	}
	return err
}

func AddSysAdminUser(namespace, email, phone, displayName, username, password string) (*types.User, error) {
	return addUser(namespace, email, phone, displayName, []types.UserLogin{
		{
			LoginName:   username,
			Credential:  password,
			DisplayName: displayName,
			LoginType:   types.LoginTypeUsername,
			Namespace:   namespace,
		},
	}, nil, nil, optional.P(true), nil, nil, types.NilID)
}

func GetUserTierByName(name string) (*types.UserTier, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	tier := &types.UserTier{}
	err = pg.Model(&types.UserTier{}).Where("name = ?", name).First(tier).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserTierNotExists
		}
		return nil, err
	}
	return tier, nil
}

func GetUserTier(id types.ID) (*types.UserTier, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	tier := &types.UserTier{}
	err = pg.Model(&types.UserTier{}).Where("id = ?", id).First(tier).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserTierNotExists
		}
		return nil, err
	}
	return tier, nil
}
func CreateUserTier(tier *types.UserTier) (*types.UserTier, error) {
	id, err := types.NewID()
	if err != nil {
		return nil, err
	}
	tier.ID = id
	if tier.Name == "" || tier.Description == "" || tier.MaxUserCount == 0 || tier.MaxDeviceCount == 0 {
		return nil, fmt.Errorf("%w: name, description, max_user_count and max_device_count are required", ErrBadParams)
	}
	if err := postgres.Create(tier); err != nil {
		return nil, err
	}
	return tier, nil
}

func DeleteUserTier(tierID types.ID) error {
	pg, err := postgres.Connect()
	if err != nil {
		return fmt.Errorf("failed to conenct to DB: %w", err)
	}
	count := int64(0)
	err = pg.Model(&types.User{}).Where("user_tier_id = ?", tierID).Count(&count).Error
	if err != nil {
		return fmt.Errorf("failed to count users with tier id %s: %w", tierID, err)
	}
	if count > 0 {
		return fmt.Errorf("failed to delete user tier %s: %d users are using this tier", tierID, count)
	}
	if err := postgres.Delete(&types.UserTier{}, "id = ?", tierID); err != nil {
		return err
	}
	return nil
}

func DeleteUserTierByName(name string) error {
	tier, err := GetUserTierByName(name)
	if err != nil {
		if !errors.Is(err, ErrUserTierNotExists) {
			return fmt.Errorf("failed to delete user tier %s: %w", name, err)
		}
		return nil
	}
	if err := DeleteUserTier(tier.ID); err != nil {
		return fmt.Errorf("failed to delete user tier %s: %w", name, err)
	}
	return nil
}

func AddUser(
	namespace, email, phone, displayName string,
	loginSlice []types.UserLogin,
	roles []string, attributes map[string][]string,
	tier *string,
	networkDomain *string, userID *types.UserID,
) (*types.User, error) {
	return addUser(
		namespace, email, phone, displayName, loginSlice, roles, attributes,
		nil /* never add sysadmin by this API */, tier, networkDomain,
		optional.V(userID, types.NilID),
	)
}

func addUser(
	namespace, email, phone, displayName string,
	loginSlice []types.UserLogin,
	roles []string, attributes map[string][]string,
	isSysAdmin *bool,
	tier *string,
	networkDomain *string, userID types.UserID,
) (*types.User, error) {
	tenant, err := GetTenantConfigByNamespace(namespace)
	if err != nil {
		return nil, err
	}
	if tenant == nil {
		return nil, fmt.Errorf("%w: tenant config not found for namespace %s", ErrTenantConfigNotFound, namespace)
	}
	if tenant.MaxUser != 0 {
		userCount, err := UserCount(&namespace, nil)
		if err != nil {
			return nil, err
		}
		if uint(userCount) >= tenant.MaxUser {
			return nil, fmt.Errorf("%w: max user limit reached for namespace '%s' (%v)",
				ErrMaxUserLimitReached, namespace, tenant.MaxUser)
		}
	}
	var userTierID *types.ID
	if tier != nil {
		tier, err := GetUserTierByName(*tier)
		if err != nil {
			return nil, err
		}
		userTierID = &tier.ID
	} else {
		userTierID = tenant.UserTierID
		if userTierID == nil {
			tier, err := GetUserTierByName(utils.DefaultUserTier)
			if err != nil {
				return nil, fmt.Errorf("failed to get default user tier: %w", err)
			}
			userTierID = &tier.ID
		}
	}
	if userTierID == nil && !optional.Bool(isSysAdmin) {
		return nil, fmt.Errorf("%w: user tier not specified", ErrBadParams)
	}

	userTier, err := GetUserTier(*userTierID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user tier %s: %w", *userTierID, err)
	}

	if networkDomain == nil || *networkDomain == "" {
		if tenant.NetworkDomain != "" {
			networkDomain = &tenant.NetworkDomain
		} else {
			return nil, fmt.Errorf("%w: network domain not specified", ErrBadParams)
		}
	}

	// Check user limit by the network domain.
	n, err := UserCount(&namespace, networkDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to count users for network domain %s: %w", *networkDomain, err)
	}
	if n >= int64(userTier.MaxUserCount) {
		return nil, fmt.Errorf("%w: max user limit reached for network domain %s (%v)",
			ErrMaxUserLimitReached, *networkDomain, userTier.MaxUserCount)
	}

	logins := types.UserLoginSlice(loginSlice)
	if err := logins.Normalize(namespace); err != nil {
		return nil, err
	}
	if err := logins.CreateID(); err != nil {
		return nil, err
	}
	meshMode := getDefaultMeshMode(namespace)

	loginName, loginType := logins.Name()
	setIfEmpty(&email, logins.Email())
	setIfEmpty(&phone, logins.Phone())
	setIfEmpty(&displayName, logins.DisplayName())
	setIfEmpty(&displayName, loginName)

	var attributesP *map[string][]string
	if len(attributes) > 0 {
		attributesP = &attributes
	}

	if userID.IsNil() {
		userID, err = types.NewID()
		if err != nil {
			return nil, err
		}
	}

	u := &types.User{
		Model:                 types.Model{ID: userID},
		Namespace:             namespace,
		TenantConfigID:        tenant.ID,
		UserLogins:            logins,
		MeshVpnMode:           &meshMode,
		AdvertiseDefaultRoute: optional.P(true),
		AutoApproveDevice:     optional.P(true),
		WgEnabled:             optional.P(true),
		IsAdminUser:           optional.P(slices.Contains(roles, types.NamespaceAdminRole) || optional.Bool(isSysAdmin)),
		IsSysAdmin:            isSysAdmin,
		Roles:                 roles,
		Attributes:            attributesP,
		UserTierID:            userTierID,
		NetworkDomain:         networkDomain,
		UserBaseInfo: types.UserBaseInfo{
			Model:         types.Model{ID: userID},
			UserID:        userID,
			CompanyName:   tenant.Name,
			Namespace:     namespace,
			Mobile:        optional.NilIfEmptyStringP(phone),
			LoginName:     loginName,
			LoginType:     loginType,
			DisplayName:   displayName,
			ProfilePicURL: logins.ProfilePicURL(),
			Email:         optional.NilIfEmptyStringP(email),
		},
	}

	lockCache(namespace)
	defer unlockCache(namespace)
	lockCache(userID.String())
	defer unlockCache(userID.String())
	tx, err := getPGconn()
	if err != nil {
		return nil, err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	if err := tx.Create(u).Error; err != nil {
		return nil, checkUserCreationError(err)
	}

	for _, login := range loginSlice {
		if err := cleanCache(namespace, userLoginCacheByLoginNamePath, nil, &login.LoginName); err != nil {
			return nil, err
		}
	}
	if err := deleteUserCache(namespace, userID); err != nil {
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}
	logins.SetUserID(userID)
	return u, nil
}

func SetUserMustChangePassword(namespace string, userID uint, mustChangePassword bool) error {
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	return pg.
		Model(&types.User{}).
		Where("id = ? and namespace = ?", userID, namespace).
		Update("must_change_password", &mustChangePassword).
		Error
}

func DeleteUser(tx *gorm.DB, namespace string, userID types.UserID) error {
	if namespace == "" || userID == types.NilID {
		return ErrBadParams
	}
	if _, err := GetUserWithBaseInfoFast(namespace, userID); err != nil {
		return ErrUserNotExists
	}
	lockCache(userID.String())
	defer unlockCache(userID.String())
	var err error
	commit := false
	if tx == nil {
		commit = true
		tx, err = getPGconn()
		if err != nil {
			return err
		}
		tx = tx.Begin()
		defer tx.Rollback()
	}

	value := &types.User{Model: types.Model{ID: userID}, Namespace: namespace}
	if err = tx.Select(clause.Associations).Delete(value).Error; err != nil {
		return err
	}
	if err = deleteUserCache(namespace, userID); err != nil {
		return err
	}
	if !commit {
		return nil
	}
	return tx.Commit().Error
}
func deleteUserCache(namespace string, userID types.UserID) error {
	return cleanUserCache(namespace, userID)
}

func AddUserLabel(namespace string, userID types.UserID, labels []types.Label) error {
	if labels == nil {
		return ErrBadParams
	}
	if err := types.LabelList(labels).SetIDIfNil(); err != nil {
		return err
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	model := &types.User{Model: types.Model{ID: userID}, Namespace: namespace}
	if err = tx.Model(model).Association("Labels").Append(&labels); err != nil {
		return err
	}
	return nil
}
func DeleteUserLabel(namespace string, userID types.UserID, labelID types.ID) error {
	tx, err := postgres.Connect()
	if err != nil {
		return err
	}
	return tx.
		Model(&types.User{Model: types.Model{ID: userID}}).
		Where(&types.User{Namespace: namespace}).
		Association("Labels").
		Delete(&types.Label{Model: types.Model{ID: labelID}})
}
func UpdateUserLastSeen(namespace string, userID types.UserID, lastSeen int64) error {
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	return pg.
		Model(&types.User{}).
		Where("id = ? and namespace = ?", userID, namespace).
		Update("last_seen", lastSeen).Error
}
func UpdateUserLabels(namespace string, userID types.UserID, labelList []types.Label, replace bool) error {
	if err := types.LabelList(labelList).SetIDIfNil(); err != nil {
		return err
	}
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	tx := pg.Begin()
	tx = tx.Model(&types.User{Namespace: namespace, Model: types.Model{ID: userID}})
	if replace {
		if err = tx.Association("Labels").Replace(&labelList); err != nil {
			tx.Rollback()
			return err
		}
	} else {
		if err = tx.Association("Labels").Append(&labelList); err != nil {
			tx.Rollback()
			return err
		}
	}

	return tx.Commit().Error
}
func GetUserLabelIDList(namespace string, userID types.UserID) ([]uint, error) {
	db, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	var list []uint
	err = db.Raw(`select label_id from user_label_relation where user_id = ?`, userID).Find(&list).Error
	if err != nil {
		return nil, err
	}
	return list, nil
}
func GetUserLabelList(namespace string, userID types.UserID) ([]types.Label, error) {
	db, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	db = db.Model(&types.User{Namespace: namespace, Model: types.Model{ID: userID}})
	ret := []types.Label{}
	err = db.Association("Labels").Find(&ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func UpdateUser(namespace string, userID types.UserID, update *models.UserUpdateInfo) error {
	_, err := GetUserFast(namespace, userID, false)
	if err != nil {
		return err
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	userUpdate := map[string]interface{}{}
	ubUpdate := map[string]interface{}{}
	updateUser := false
	updateUserBaseInfo := false
	if update.AdvertiseDefaultRoute != nil {
		updateUser = true
		userUpdate["advertise_default_route"] = update.AdvertiseDefaultRoute
	}
	if update.WgEnabled != nil {
		updateUser = true
		userUpdate["wg_enabled"] = update.WgEnabled
	}
	if update.MeshVpnMode != nil {
		updateUser = true
		userUpdate["mesh_vpn_mode"] = update.MeshVpnMode
	}
	if update.AutoAcceptRoutes != nil {
		updateUser = true
		userUpdate["auto_accept_routes"] = update.AutoAcceptRoutes
	}
	if update.AutoApproveDevice != nil {
		updateUser = true
		userUpdate["auto_approve_device"] = update.AutoApproveDevice
	}
	if update.AddEmail != nil {
		updateUserBaseInfo = true
		ubUpdate["email"] = *update.AddEmail
	}
	if update.AddPhone != nil {
		updateUserBaseInfo = true
		ubUpdate["mobile"] = update.AddPhone
	}
	if updateUser {
		model := &types.User{Model: types.Model{ID: userID}, Namespace: namespace}
		if err := tx.Model(model).Updates(userUpdate).Error; err != nil {
			return err
		}
	}
	if updateUserBaseInfo {
		ubUpdate["updated_at"] = time.Now().Unix()
		model := &types.UserBaseInfo{Model: types.Model{ID: userID}, Namespace: namespace}
		if err := tx.Model(model).Updates(ubUpdate).Error; err != nil {
			return err
		}
	}
	if err = deleteUserCache(namespace, userID); err != nil {
		return err
	}
	return tx.Commit().Error
}

func OnlineDeviceCountUserIDMap(namespace string) (map[types.UserID]int64, error) {
	ret := map[types.UserID]int64{}
	userDeviceCountList := []*UserMetricCount{}
	pg, err := postgres.Connect()
	if err != nil {
		return ret, err
	}
	if err := pg.Raw(
		"select user_id, count(id) total from devices where namespace = ? and last_seen > ? group by user_id",
		namespace, time.Now().Unix()-180).
		Find(&userDeviceCountList).Error; err != nil {
		return ret, err
	}
	for _, userDeviceCount := range userDeviceCountList {
		if userDeviceCount.UserID != types.NilID {
			ret[userDeviceCount.UserID] = userDeviceCount.Total
		}
	}
	return ret, nil
}
func LabelCountUserIDMap() (map[types.UserID]int64, error) {
	ret := map[types.UserID]int64{}
	userLabelCountList := []*UserMetricCount{}
	pg, err := postgres.Connect()
	if err != nil {
		return ret, err
	}
	if err := pg.Raw("select user_id, count(label_id) total from user_label_relation group by user_id").
		Find(&userLabelCountList).Error; err != nil {
		return ret, err
	}
	for _, userLabelCount := range userLabelCountList {
		if userLabelCount.UserID != types.NilID {
			ret[userLabelCount.UserID] = userLabelCount.Total
		}
	}
	return ret, nil
}

func DeviceCount(namespace *string, userID *types.UserID, networkDomain *string) (int64, error) {
	db, err := postgres.Connect()
	if err != nil || db == nil {
		return 0, fmt.Errorf("failed to connect to db: %w", err)
	}
	db = db.Model(&types.Device{})
	if namespace != nil {
		ns := types.NormalizeNamespace(*namespace)
		db = db.Where("namespace = ?", ns)
	}
	if userID != nil {
		db = db.Where("user_id = ?", *userID)
	}
	if networkDomain != nil {
		db = db.Where("network_domain = ?", networkDomain)
	}
	var ret int64
	if err := db.Count(&ret).Error; err != nil {
		return 0, fmt.Errorf("failed to count: %w", err)
	}
	return ret, nil
}
func OnlineUserCount(namespace string) (int64, error) {
	user := types.User{
		Namespace: namespace,
	}
	return postgres.TableCount(&user, "last_seen > ?", time.Now().Unix()-180)
}
func UserCount(namespace *string, networkDomain *string) (int64, error) {
	db, err := postgres.Connect()
	if err != nil || db == nil {
		return 0, fmt.Errorf("failed to connect to db: %w", err)
	}
	db = db.Model(&types.User{})
	if namespace != nil {
		ns := types.NormalizeNamespace(*namespace)
		db = db.Where("namespace = ?", ns)
	}
	if networkDomain != nil {
		db = db.Where("network_domain = ?", networkDomain)
	}
	var ret int64
	if err := db.Count(&ret).Error; err != nil {
		return 0, fmt.Errorf("failed to count: %w", err)
	}
	return ret, nil
}

// Default to true if not set by tenant config.
func DeviceAutoApprove(namespace string, userID types.UserID) (bool, error) {
	t, err := GetTenantConfigByNamespace(namespace)
	if err != nil {
		return false, err
	}
	if t.AutoApproveDevice != nil && *t.AutoApproveDevice {
		return true, nil
	}
	u, err := GetUserFast(namespace, userID, false)
	if err != nil {
		return false, err
	}
	return optional.V(u.AutoApproveDevice, true), nil
}

func GetUserBaseInfo(namespace string, userID types.UserID, result interface{}) error {
	if err := postgres.SelectFirst(result, "id = ?", userID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotExists
		}
		return err
	}
	v, ok := result.(*types.UserBaseInfo)
	if !ok || v.Namespace != namespace {
		return fmt.Errorf("%w: namespace is '%v', want '%v'", ErrNamespaceMismatch, v.Namespace, namespace)
	}
	return nil
}

// Only allow to update mobile, email, displayname and profile picture url.
func UpdateUserBaseInfo(namespace string, userID types.UserID, userBaseInfo *types.UserBaseInfo) error {
	userInfo := &types.UserBaseInfo{
		Email:         userBaseInfo.Email,
		Mobile:        userBaseInfo.Mobile,
		DisplayName:   userBaseInfo.DisplayName,
		ProfilePicURL: userBaseInfo.ProfilePicURL,
	}
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()
	err = tx.
		Model(&types.UserBaseInfo{}).
		Where("id = ? and namespace = ?", userID, namespace).
		Updates(userInfo).
		Error
	if err != nil {
		return err
	}
	if err = deleteUserCache(namespace, userID); err != nil {
		return err
	}
	return tx.Commit().Error
}

func DeleteUserBaseInfo(namespace string, userID types.UserID) error {
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()
	err = tx.Delete(&types.UserBaseInfo{}, "id = ? and namespace = ?", userID, namespace).Error
	if err != nil {
		return err
	}
	if err := deleteUserCache(namespace, userID); err != nil {
		return err
	}
	return tx.Commit().Error
}

func getUserBaseInfoFast(namespace string, userID types.UserID, cacheOnly bool) (*types.UserBaseInfo, error) {
	ret := &types.UserBaseInfo{}
	callback := func(namespace string, userID *types.UserID, _ *string, result interface{}) error {
		if userID == nil {
			return errors.New("nil user id")
		}
		return GetUserBaseInfo(namespace, *userID, result)
	}
	if cacheOnly {
		callback = nil
	}
	if err := getDataFromCache(
		namespace, userBaseInfoCacheByUserIDPath, &userID, nil, ret, callback,
	); err != nil {
		if errors.Is(err, errCacheNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotExists
		}
		return nil, err
	}
	return ret, nil
}

func GetUserBaseInfoFast(namespace string, userID types.UserID) (*types.UserBaseInfo, error) {
	return getUserBaseInfoFast(namespace, userID, false /* with fallback */)
}
func GetUserBaseInfoCacheOnly(namespace string, userID types.UserID) (*types.UserBaseInfo, error) {
	return getUserBaseInfoFast(namespace, userID, true /* no fallback */)
}

func GetUserByEmailDomainOrNil(domain string) (*types.User, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	ret := types.UserLogin{}
	err = pg.Model(&types.UserLogin{}).
		Where("login_name LIKE ?", "%@"+domain).
		First(&ret).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	user, err := GetUserFast(ret.Namespace, ret.UserID, false)
	if err != nil {
		if errors.Is(err, ErrUserNotExists) {
			return nil, nil
		}
		return nil, err
	}
	return user, nil
}

func IsNetworkDomainInUse(domain string) (bool, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return false, err
	}
	user := types.User{}
	err = pg.Model(&types.User{}).
		Where("network_domain = ?", domain).
		First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func UpdateUserNetworkDomain(namespace, prevDomain, newDomain string, ofUserID *types.UserID, onUpdate func() error) error {
	if prevDomain == "" && (ofUserID == nil || ofUserID.IsNil()) {
		return fmt.Errorf("%w: prevDomain and ofUserID are both empty", ErrBadParams)
	}
	if newDomain == "" {
		return fmt.Errorf("%w: newDomain is empty", ErrBadParams)
	}

	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	tx := pg.Begin()
	defer tx.Rollback()

	tx = tx.Model(&types.User{}).Where("namespace = ?", namespace)
	if ofUserID != nil {
		tx = tx.Where("id = ?", *ofUserID)
	} else {
		tx = tx.Where("network_domain = ?", prevDomain)
	}
	if err = tx.Update("network_domain", newDomain).Error; err != nil {
		return err
	}
	if onUpdate != nil {
		if err := onUpdate(); err != nil {
			return err
		}
	}
	return tx.Commit().Error
}

func AddUserRole(namespace string, userID types.UserID, role string) error {
	if role == "" {
		return fmt.Errorf("%w: role is empty", ErrBadParams)
	}
	user := &types.User{}
	if err := GetUser(userID, user); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotExists
		}
		return err
	}
	if user.Namespace != namespace {
		return fmt.Errorf("%w: namespace is '%v', want '%v'", ErrNamespaceMismatch, user.Namespace, namespace)
	}
	if role == string(models.PredefinedRolesNetworkAdmin) {
		role = types.NetworkDomainAdminRole
	}
	if role == string(models.PredefinedRolesNetworkOwner) {
		role = types.NetworkDomainOwnerRole
	}
	roles := append(user.Roles, role)
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	return tx.Model(&types.User{}).
		Where("namespace = ? and id = ?", namespace, userID).
		Update("roles", roles).Error
}
func DelUserRole(namespace string, userID types.UserID, role string) error {
	if role == "" {
		return fmt.Errorf("%w: role is empty", ErrBadParams)
	}
	user := &types.User{}
	if err := GetUser(userID, user); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrUserNotExists
		}
		return err
	}
	if user.Namespace != namespace {
		return fmt.Errorf("%w: namespace is '%v', want '%v'", ErrNamespaceMismatch, user.Namespace, namespace)
	}
	if role == string(models.PredefinedRolesNetworkAdmin) {
		role = types.NetworkDomainAdminRole
	}
	if !slices.Contains(user.Roles, role) {
		return nil
	}
	roles := slices.Delete(user.Roles, slices.Index(user.Roles, role), slices.Index(user.Roles, role)+1)

	tx, err := getPGconn()
	if err != nil {
		return err
	}
	return tx.Model(&types.User{}).
		Where("namespace = ? and id = ?", namespace, userID).
		Update("roles", roles).Error
}
