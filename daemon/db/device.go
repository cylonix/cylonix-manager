// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"
	"fmt"
	"time"

	"github.com/cylonix/utils/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

func AddUserDevice(namespace string, userID types.UserID, device *types.Device) error {
	user := &types.User{}
	err := GetUser(userID, user)
	if err != nil {
		return err
	}
	if user.Namespace != namespace {
		return fmt.Errorf("%w: has '%s' expected '%s'", ErrNamespaceMismatch, user.Namespace, namespace)
	}
	if device.ID == types.NilID {
		device.ID, err = types.NewID()
		if err != nil {
			return err
		}
	}
	device.UserID = userID
	device.NetworkDomain = user.NetworkDomain
	if device.WgInfo != nil {
		device.WgInfo.Namespace = namespace
		device.WgInfo.ID = device.ID
		device.WgInfo.UserID = userID
		device.WgInfo.DeviceID = device.ID
	}

	lockCache(userID.String())
	defer unlockCache(userID.String())
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	if err = clearDeviceCache(namespace, userID, device.ID); err != nil {
		return err
	}
	if err = tx.Create(device).Error; err != nil {
		return err
	}

	err = tx.
		Model(&types.User{Model: types.Model{ID: userID}}).
		Where(&types.User{Namespace: namespace}).
		Association("Devices").Append(device)
	if err != nil {
		return err
	}
	return tx.Commit().Error
}

func clearDeviceCache(namespace string, userID types.UserID, deviceID types.DeviceID) error {
	if err := cleanUserCache(namespace, userID); err != nil {
		return err
	}
	deviceIDStr := deviceID.String()
	if deviceID.IsNil() {
		deviceIDStr = "*"
	}
	return cleanCache(namespace, userDeviceCacheByDeviceIDPath, &userID, &deviceIDStr)
}

func DeleteUserDevices(tx *gorm.DB, namespace string, userID types.UserID, deviceIDs []types.DeviceID) error {
	if len(deviceIDs) <= 0 {
		return DeleteAllDevicesOfUser(namespace, userID)
	}

	lockCache(userID.String())
	defer unlockCache(userID.String())
	var err error
	commit := false
	if tx == nil {
		tx, err = postgres.Connect()
		if err != nil {
			return err
		}
		tx = tx.Begin()
		commit = true
		defer tx.Rollback()
	}

	if len(deviceIDs) == 1 {
		if err = clearDeviceCache(namespace, userID, deviceIDs[0]); err != nil {
			return err
		}
		value := types.Device{
			Namespace: namespace,
			UserID:    userID,
			Model:     types.Model{ID: deviceIDs[0]},
		}
		err = tx.
			Select(clause.Associations).
			Delete(&value, "namespace = ? and user_id = ?", namespace, userID).
			Error
		if err != nil {
			return err
		}
	} else {
		if err = clearDeviceCache(namespace, userID, types.NilID); err != nil {
			return err
		}
		for _, v := range deviceIDs {
			if err = tx.
				Select(clause.Associations).
				Delete(&types.Device{Model: types.Model{ID: v}}).Error; err != nil {
				return err
			}
		}
	}
	if !commit {
		return nil
	}
	return tx.Commit().Error
}

func ListDevice(namespace *string, userIDs []types.UserID, onlineOnly bool,
	capability, filterBy, filterValue, sortBy, sortDesc *string,
	page, pageSize *int,
) ([]types.Device, int64, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, 0, err
	}
	db := pg.Model(&types.Device{})
	if namespace != nil {
		db = db.Where("namespace = ?", *namespace)
	}
	if len(userIDs) > 0 {
		db = db.Where("user_id IN ?", userIDs)
	}
	if capability != nil && *capability != "" {
		cid := []types.DeviceID{}
		q := "select device_id from device_capabilities_relation" +
			" left join device_capabilities on device_capabilities.id =" +
			" device_capabilities_relation.device_capability_id" +
			" where device_capabilities.namespace = ? and" +
			" device_capabilities.name like ?"
		if err := pg.Raw(q, namespace, like(*capability)).Find(&cid).Error; err != nil {
			return nil, 0, err
		}
		db = db.Where("device_id in ?", cid)
	}
	if onlineOnly {
		db = db.Where("last_seen > ?", time.Now().Unix()-180)
	}
	db = filter(db, filterBy, filterValue)

	var total int64
	if err = db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	ret := []types.Device{}
	db = postgres.Sort(db, sortBy, sortDesc)
	db = postgres.Page(db, total, page, pageSize)
	db = db.
		Preload("Labels").
		Preload("User").
		Preload("User.UserBaseInfo").
		Preload("VpnLabels").
		Preload("WgInfo").
		Preload("Capabilities")
	if err = db.Find(&ret).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, ErrDeviceNotExists
		}
	}
	return ret, total, nil
}
func GetUserDevice(namespace string, deviceID types.DeviceID, rst interface{}) error {
	db, err := postgres.Connect()
	if err != nil {
		return err
	}

	db = db.Model(&types.Device{}).
		Preload("WgInfo").
		Preload("Labels").
		Preload("VpnLabels").
		Preload("Capabilities").
		Where("id = ? ", deviceID)
	if namespace != "" {
		db = db.Where("namespace = ?", namespace)
	}
	err = db.First(rst).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrDeviceNotExists
	}
	return err
}
func GetUserDeviceFast(namespace string, userID types.UserID, deviceID types.DeviceID) (*types.Device, error) {
	if namespace == "" {
		return nil, fmt.Errorf("%w: cached based get device must have namespace", ErrBadParams)
	}
	ret := types.Device{}
	deviceIDString := deviceID.String()
	if err := getDataFromCache(
		namespace, userDeviceCacheByDeviceIDPath, &userID, &deviceIDString, &ret,
		func(namespace string, userID *types.UserID, deviceIDStr *string, result interface{}) error {
			deviceID, err := types.ParseID(optional.String(deviceIDStr))
			if err != nil {
				return err
			}
			return GetUserDevice(namespace, deviceID, result)
		},
	); err != nil {
		if errors.Is(err, errCacheNotFound) {
			return nil, ErrDeviceNotExists
		}
		return nil, err
	}
	return &ret, nil
}
func GetUserDeviceList(namespace string, userID types.UserID) ([]*types.Device, error) {
	ret := []*types.Device{}
	err := getUserDeviceList(namespace, userID, &ret)
	if len(ret) == 0 {
		return nil, ErrDeviceNotExists
	}
	return ret, err
}
func getUserDeviceList(namespace string, userID types.UserID, rst interface{}) error {
	db, err := postgres.Connect()
	if err != nil {
		return err
	}
	err = db.Model(&types.Device{}).
		Where("namespace = ? and user_id = ?  ", namespace, userID).
		Preload("WgInfo").
		Preload("Labels").
		Preload("VpnLabels").
		Preload("Capabilities").
		Find(rst).Error
	if err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrDeviceNotExists
	}
	return err
}
func GetUserDeviceListFast(namespace string, userID types.UserID) ([]*types.Device, error) {
	ret := []*types.Device{}
	if err := getDataFromCache(
		namespace, userDeviceListCacheByUserIDPath, &userID, nil, &ret,
		func(namespace string, userID *types.UserID, _ *string, result interface{}) error {
			if userID == nil {
				return errors.New("nil user id")
			}
			return getUserDeviceList(namespace, *userID, result)
		},
	); err != nil {
		if errors.Is(err, errCacheNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceNotExists
		}
		return nil, err
	}
	if len(ret) == 0 {
		return nil, ErrDeviceNotExists
	}
	return ret, nil
}

func GetUserDeviceIDList(namespace string, userID types.UserID) ([]types.DeviceID, error) {
	ret := []types.DeviceID{}
	err := getUserDeviceIDList(namespace, userID, &ret)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrDeviceNotExists
	}

	return ret, err
}
func getUserDeviceIDList(namespace string, userID types.UserID, rst interface{}) error {
	db, err := postgres.Connect()
	if err != nil {
		return err
	}
	err = db.
		Model(&types.Device{}).
		Where(&types.Device{Namespace: namespace, UserID: userID}).
		Pluck("ID", rst).
		Error
	if err != nil {
		return err
	}
	return nil
}
func GetUserDeviceCount(namespace string, userID types.UserID) (int, error) {
	db, err := postgres.Connect()
	if err != nil {
		return 0, err
	}
	ret := &types.User{}
	if err = db.
		Model(ret).Where("id = ?", userID).
		Preload("Devices").
		Find(ret).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, nil
		}
		return 0, err
	}
	return len(ret.Devices), nil
}
func DeleteAllDevicesOfUser(namespace string, userID types.UserID) error {
	lockCache(userID.String())
	defer unlockCache(userID.String())
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()
	if err = clearDeviceCache(namespace, userID, types.NilID); err != nil {
		return err
	}

	var rst []types.Device
	err = tx.Model(&types.Device{}).Select("ID").
		Where(&types.Device{Namespace: namespace, UserID: userID}).
		Find(&rst).Error
	if err != nil {
		return err
	}

	for _, v := range rst {
		err = tx.
			Select(clause.Associations).
			Delete(&v).
			Error
		if err != nil {
			return err
		}
	}

	return tx.Commit().Error
}
func GetUserDeviceIDListFast(namespace string, userID types.UserID) ([]types.DeviceID, error) {
	ret := []types.DeviceID{}
	if err := getDataFromCache(
		namespace, userDeviceIDCacheByUserIDPath, &userID, nil, &ret,
		func(namespace string, userID *types.UserID, _ *string, result interface{}) error {
			if userID == nil {
				return errors.New("nil user id")
			}
			return getUserDeviceIDList(namespace, *userID, result)
		},
	); err != nil {
		if errors.Is(err, errCacheNotFound) || errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceNotExists
		}
		return nil, err
	}
	return ret, nil
}

func GetDeviceIDsWithLabels(labels []types.Label) ([]types.DeviceID, error) {
	labelIDs := []types.LabelID{}
	for _, label := range labels {
		labelIDs = append(labelIDs, label.ID)
	}
	return GetDeviceIDsWithLabelIDs(labelIDs)
}
func GetDeviceIDsWithLabelIDs(labelIDs []types.LabelID) ([]types.DeviceID, error) {
	deviceIDs := []types.DeviceID{}
	db, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	err = db.Raw(`select device_id from device_label_relation where label_id in ?`, labelIDs).Find(&deviceIDs).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceNotExists
		}
		return nil, err
	}
	return deviceIDs, nil
}

// GetDeviceLabels get the device labels.
func GetDeviceLabels(namespace string, deviceID types.DeviceID) ([]types.Label, error) {
	ret := types.Device{}
	if err := GetUserDevice(namespace, deviceID, &ret); err != nil {
		return nil, err
	}
	return ret.Labels, nil
}

// AddOrReplaceDeviceLabelRelation will append or replace the labels to the relationship.
func AddOrReplaceDeviceLabelRelation(deviceID types.DeviceID, labels []*types.Label, replace bool) error {
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Model(&types.Device{Model: types.Model{ID: deviceID}})
	if replace {
		return tx.Association("Labels").Replace(labels)
	}
	return tx.Association("Labels").Append(labels)
}

func DeviceByIP(namespace, ip string) (*types.Device, error) {
	w, err := WgInfoByIP(namespace, ip)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceNotExists
		}
		return nil, err
	}
	d := &types.Device{}
	if err := postgres.SelectOne(d, "namespace = ? and id = ?", namespace, w.DeviceID); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceNotExists
		}
		return nil, err
	}
	return d, nil
}

func GetWgInfoOfDevice(namespace string, deviceID types.DeviceID) (*types.WgInfo, error) {
	ret := &types.WgInfo{}
	err := postgres.SelectOne(ret, &types.WgInfo{Namespace: namespace, DeviceID: deviceID})
	if err == nil {
		return ret, nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrDeviceWgInfoNotExists
	}
	return nil, err
}
func WgInfoByIP(namespace, ip string) (*types.WgInfo, error) {
	ret := &types.WgInfo{}
	if err := postgres.SelectOne(ret, "namespace = ? and addresses like ?", namespace, ip); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceWgInfoNotExists
		}
		return nil, err
	}
	return ret, nil
}
func WgInfoByMachineKey(namespace string, userID types.UserID, machineKey string) (*types.WgInfo, error) {
	ret := &types.WgInfo{}
	if err := postgres.SelectOne(ret, &types.WgInfo{
		UserID:     userID,
		MachineKey: &machineKey,
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceWgInfoNotExists
		}
		return nil, err
	}
	if ret.Namespace != namespace {
		return nil, ErrNamespaceMismatch
	}
	return ret, nil
}
func WgInfoByMachineAndNodeKeys(machineKey, nodeKeyHex string) (*types.WgInfo, error) {
	ret := &types.WgInfo{}
	if err := postgres.SelectOne(ret, &types.WgInfo{
		MachineKey:   &machineKey,
		PublicKeyHex: nodeKeyHex,
	}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceWgInfoNotExists
		}
		return nil, err
	}
	return ret, nil
}
func WgInfoByNodeID(nodeID uint64) (*types.WgInfo, error) {
	ret := &types.WgInfo{}
	if err := postgres.SelectOne(ret, &types.WgInfo{NodeID: &nodeID}); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrDeviceWgInfoNotExists
		}
		return nil, err
	}
	return ret, nil
}
func GetWgInfoListByWgName(namespace, wgName string) ([]*types.WgInfo, error) {
	tx, err := getPGconn()
	if err != nil {
		return nil, err
	}
	ret := []*types.WgInfo{}
	tx = tx.Model(&types.WgInfo{}).Where("namespace = ? and wg_name = ?", namespace, wgName)
	if err := tx.Find(&ret).Error; err != nil {
		return nil, err
	}
	return ret, nil
}
func GetWgInfoList(
	namespace *string, userID *types.UserID, contain *string,
	isWireguardOnly *bool, page, pageSize *int,
) ([]*types.WgInfo, int64, error) {
	pg, err := postgres.Connect()
	if err != nil {
		return nil, 0, err
	}
	pg = pg.Model(&types.WgInfo{})
	if namespace != nil {
		pg = pg.Where("namespace = ? ", *namespace)
	}
	if userID != nil {
		pg = pg.Where("user_id = ?", *userID)
	}
	if contain != nil {
		c := like(*contain)
		pg = pg.Where("wg_name like ? or namespace like ?", c, c)
	}
	if isWireguardOnly != nil {
		pg = pg.Where("is_wireguard_only = ?", *isWireguardOnly)
	}
	var total int64
	if err = pg.Count(&total).Error; err != nil {
		return nil, 0, ErrInternalErr
	}
	ret := []*types.WgInfo{}
	pg = postgres.Page(pg, total, page, pageSize)
	if err = pg.Find(&ret).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, 0, ErrDeviceWgInfoNotExists
		}
	}
	return ret, total, nil
}
func GetWgInfoListByUserID(namespace string, userID *types.UserID, rst interface{}) error {
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	query := &types.WgInfo{Namespace: namespace}
	if userID != nil {
		query.UserID = *userID
	}
	pg = pg.Model(&types.WgInfo{}).Where(query)
	err = pg.Find(rst).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = ErrDeviceWgInfoNotExists
	}
	return err
}

func GetWgInfoListByUserIDList(namespace string, userIDList []types.UserID) ([]types.WgInfo, error) {
	tx, err := getPGconn()
	if err != nil {
		return nil, err
	}
	result := []types.WgInfo{}
	tx = tx.Model(&types.WgInfo{}).Where("namespace = ? and user_id in ?", namespace, userIDList)
	if err := tx.Find(&result).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return nil, ErrDeviceWgInfoNotExists
	}
	return result, nil
}

func GetWgNodeIDListByUserID(namespace string, userID *types.UserID) ([]uint64, error) {
	ret := []uint64{}
	pg, err := postgres.Connect()
	if err != nil {
		return nil, err
	}
	query := &types.WgInfo{Namespace: namespace}
	if userID != nil {
		query.UserID = *userID
	}
	pg = pg.Model(&types.WgInfo{}).Select("node_id").Where(query)
	err = pg.Find(&ret).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		err = ErrDeviceWgInfoNotExists
	}
	return ret, err
}

func GetWgNodeIDListByUserIDList(namespace string, userIDList []types.UserID) ([]uint64, error) {
	tx, err := getPGconn()
	if err != nil {
		return nil, err
	}
	result := []uint64{}
	tx = tx.Model(&types.WgInfo{}).
		Select("node_id").
		Where("namespace = ? and user_id in ?", namespace, userIDList)
	if err := tx.Find(&result).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		return nil, ErrDeviceWgInfoNotExists
	}
	return result, nil
}

func GetWgNodeIDListByVpnLabels(namespace string, labels []types.Label) ([]uint64, error) {
	tx, err := getPGconn()
	if err != nil {
		return nil, err
	}
	deviceIDs := []types.DeviceID{}
	idList := types.LabelList(labels).IDList()
	if len(idList) <= 0 {
		return nil, nil
	}

	q := "select device_id from device_vpn_labels_relation where label_id in ?"
	if err := tx.Raw(q, idList).Find(&deviceIDs).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if len(deviceIDs) <= 0 {
		return nil, nil
	}

	result := []uint64{}
	tx = tx.Model(&types.WgInfo{}).
		Select("node_id").
		Where("namespace = ? and id in ?", namespace, deviceIDs).
		Find(&result)
	if err = tx.Error; err != nil {
		return nil, err
	}
	return result, nil
}

func GetWgInfoListByUserIDFast(namespace string, userID types.UserID) ([]types.WgInfo, error) {
	ret := []types.WgInfo{}
	if err := getDataFromCache(
		namespace, userWgInfoListCacheByUserIDPath, &userID, nil, &ret,
		func(namespace string, userID *types.UserID, _ *string, result interface{}) error {
			if userID == nil {
				return errors.New("nil user id")
			}
			return GetWgInfoListByUserID(namespace, userID, result)
		}); err != nil {
		if errors.Is(err, errCacheNotFound) {
			return nil, ErrDeviceWgInfoNotExists
		}
		return nil, err
	}
	return ret, nil
}
func UpdateDeviceLastSeen(namespace string, userID types.UserID, deviceID types.DeviceID, lastSeen int64) error {
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	tx := pg.Begin()
	defer tx.Rollback()
	if err := tx.Model(&types.User{}).
		Where("id = ? and namespace = ?", userID, namespace).
		Update("last_seen", lastSeen).Error; err != nil {
		return err
	}
	if err := tx.Model(&types.Device{}).
		Where("id = ? and namespace = ?", deviceID, namespace).
		Update("last_seen", lastSeen).Error; err != nil {
		return err
	}
	return tx.Commit().Error
}

func UpdateWgInfo(tx *gorm.DB, deviceID types.DeviceID, updateWgInfo *types.WgInfo) error {
	if !updateWgInfo.ID.IsNil() ||
		!updateWgInfo.DeviceID.IsNil() ||
		!updateWgInfo.UserID.IsNil() {
		return ErrBadParams
	}
	if tx == nil {
		pg, err := postgres.Connect()
		if err != nil {
			return err
		}
		tx = pg
	}
	if err := updateWgInfo.BeforeSave(tx); err != nil {
		return err
	}
	return tx.
		Model(&types.WgInfo{Model: types.Model{ID: deviceID}}).
		Updates(*updateWgInfo).Error
}

func UpdateWgInfoWgNode(deviceID types.DeviceID, newWgID, newWgName string) error {
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	return pg.
		Model(&types.WgInfo{Model: types.Model{ID: deviceID}}).
		Updates(map[string]interface{}{
			"wg_id":   newWgID,
			"wg_name": newWgName,
		}).Error
}

func getCapability(tx *gorm.DB, namespace, capability string) (*types.DeviceCapability, error) {
	cap := types.DeviceCapability{}
	err := tx.First(
		&cap, "namespace = ? and name = ?",
		types.NormalizeNamespace(namespace), types.NormalizeNamespace(capability),
	).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			err = ErrDeviceCapabilityNotExists
		}
		return nil, err
	}
	return &cap, nil
}

func getLabelIDs(tx *gorm.DB, namespace string, labels types.LabelList) error {
	for i := range labels {
		l := &labels[i]
		l.Namespace = namespace
		if !l.ID.IsNil() {
			continue
		}
		ret := types.Label{}
		tx = tx.Model(&ret).Where("namespace = ? and name = ? and category = ?", namespace, l.Name, l.Category)
		tx = whereCheckNil(tx, "scope", l.Scope)
		if err := tx.First(&ret).Error; err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				return err
			}
			if l.ID, err = types.NewID(); err != nil {
				return err
			}
			continue
		}
		labels[i] = ret
	}
	return nil
}

func UpdateDevice(tx *gorm.DB, namespace string, userID types.UserID, deviceID types.DeviceID, update *types.Device) error {
	lockCache(userID.String())
	defer unlockCache(userID.String())
	if err := clearDeviceCache(namespace, userID, deviceID); err != nil {
		return err
	}
	if tx == nil {
		pg, err := postgres.Connect()
		if err != nil {
			return err
		}
		tx = pg
	}
	return tx.Model(&types.Device{Model: types.Model{ID: deviceID}}).
		Where("namespace = ? and user_id = ?", namespace, userID).
		Updates(update).Error
}

func UpdateDeviceFromAPI(namespace string, userID types.UserID, deviceID types.DeviceID, u *models.DeviceUpdate) error {
	if namespace == "" || deviceID.IsNil() || userID.IsNil() {
		return ErrBadParams
	}
	m := map[string]interface{}{}
	update := false
	if u.Name != nil {
		m["name"] = u.Name
		update = true
	}
	if u.NameAlias != nil {
		m["name_alias"] = u.NameAlias
		update = true
	}

	lockCache(userID.String())
	defer unlockCache(userID.String())
	if err := clearDeviceCache(namespace, userID, deviceID); err != nil {
		return err
	}

	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	tx := pg.Begin()
	defer tx.Rollback()
	db := tx.Model(&types.Device{Model: types.Model{ID: deviceID}})
	if update {
		if err := db.Updates(m).Error; err != nil {
			tx.Rollback()
			return err
		}
	}
	if u.AddLabels != nil && len(*u.AddLabels) > 0 {
		var labels types.LabelList
		labels = labels.FromModel(namespace, u.AddLabels)
		if err := getLabelIDs(tx, namespace, labels); err != nil {
			return err
		}
		vpnLabels := types.SliceFilter(labels, func(l types.Label) bool {
			return l.Category == types.LabelCategoryVPN
		})
		otherLabels := types.SliceFilter(labels, func(l types.Label) bool {
			return l.Category != types.LabelCategoryVPN
		})
		if len(vpnLabels) > 0 {
			if err := db.Association("VpnLabels").Append(vpnLabels); err != nil {
				return err
			}
		}
		if len(otherLabels) > 0 {
			if err := db.Association("Labels").Append(otherLabels); err != nil {
				return err
			}
		}
	}
	if u.DelLabels != nil && len(*u.DelLabels) > 0 {
		var labels types.LabelList
		labels = labels.FromModel(namespace, u.DelLabels)
		if err := getLabelIDs(tx, namespace, labels); err != nil {
			return err
		}
		vpnLabels := types.SliceFilter(labels, func(l types.Label) bool {
			return l.Category == types.LabelCategoryVPN
		})
		otherLabels := types.SliceFilter(labels, func(l types.Label) bool {
			return l.Category != types.LabelCategoryVPN
		})
		if len(vpnLabels) > 0 {
			if err := db.Association("VpnLabels").Delete(vpnLabels); err != nil {
				return err
			}
		}
		if len(otherLabels) > 0 {
			if err := db.Association("Labels").Delete(otherLabels); err != nil {
				return err
			}
		}
	}
	if u.AddCapability != nil && *u.AddCapability != "" {
		cap := *u.AddCapability
		c, err := getCapability(tx, namespace, cap)
		if err != nil {
			if errors.Is(err, ErrDeviceCapabilityNotExists) {
				c, err = NewDeviceCapability(namespace, cap)
			}
		}
		if err != nil {
			return err
		}
		if err = db.Association("Capabilities").Append(c); err != nil {
			return err
		}
	}
	if u.DelCapability != nil && *u.DelCapability != "" {
		c, err := getCapability(tx, namespace, *u.AddCapability)
		if err != nil {
			if errors.Is(err, ErrDeviceCapabilityNotExists) {
				// Skip error for not existing capability.
			}
			return err
		} else {
			if err = db.Association("Capabilities").Delete(c); err != nil {
				return err
			}
		}
	}
	return tx.Commit().Error
}
func CreateWgInfo(wgInfo *types.WgInfo) error {
	if wgInfo == nil || wgInfo.Namespace == "" || wgInfo.DeviceID.IsNil() {
		return ErrBadParams
	}
	namespace := wgInfo.Namespace
	userID := wgInfo.UserID
	deviceID := wgInfo.DeviceID
	_, err := GetUserDeviceFast(namespace, userID, deviceID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return ErrDeviceNotExists
		}
		return err
	}
	lockCache(userID.String())
	defer unlockCache(userID.String())
	tx, err := getPGconn()
	if err != nil {
		return err
	}
	tx = tx.Begin()
	defer tx.Rollback()

	if err = clearDeviceCache(namespace, userID, deviceID); err != nil {
		return err
	}
	wgInfo.ID = wgInfo.DeviceID
	err = tx.
		Model(&types.Device{Model: types.Model{ID: deviceID}}).
		Where(&types.Device{Namespace: namespace}).
		Association("WgInfo").Append(wgInfo)
	if err != nil {
		return err
	}
	return tx.Commit().Error
}
func DeleteWgInfo(namespace string, deviceID types.DeviceID) error {
	pg, err := postgres.Connect()
	if err != nil {
		return err
	}
	return pg.
		Model(&types.WgInfo{Model: types.Model{ID: deviceID}}).
		Where("namespace = ?", namespace).
		Delete(&types.WgInfo{}).Error
}

func NewDeviceCapability(namespace, capability string) (*types.DeviceCapability, error) {
	id, err := types.NewID()
	if err != nil {
		return nil, err
	}
	return &types.DeviceCapability{
		Model:     types.Model{ID: id},
		Namespace: namespace,
		Name:      capability,
	}, nil
}

// UserDeviceExists check if a user device exists or not.
// It returns ErrUserNotExists if user does not exist and
// ErrDeviceNotExists if the device does not exist.
func UserDeviceExists(namespace string, userID types.UserID, deviceID types.DeviceID) (bool, error) {
	_, err := GetUserFast(namespace, userID, false)
	if err != nil {
		if errors.Is(err, ErrUserNotExists) {
			return false, nil
		}
		return false, err
	}
	_, err = GetUserDeviceFast(namespace, userID, deviceID)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ErrDeviceNotExists) {
		return false, nil
	}
	return false, err
}
