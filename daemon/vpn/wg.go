// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package vpn

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/logging/logfields"
	"cylonix/sase/pkg/optional"
	"errors"

	"github.com/cylonix/utils/ipdrawer"
	ulog "github.com/cylonix/utils/log"

	"github.com/sirupsen/logrus"
)

type wgHandlerImpl struct {
	daemon    interfaces.DaemonInterface
	fwService fwconfig.ConfigService
	logger    *logrus.Entry
}

func newWgHandlerImpl(daemon interfaces.DaemonInterface, fwService fwconfig.ConfigService, logger *logrus.Entry) *wgHandlerImpl {
	return &wgHandlerImpl{
		daemon:    daemon,
		fwService: fwService,
		logger:    logger.WithField(logfields.LogSubsys, "wg-handler"),
	}
}

func (w *wgHandlerImpl) List(auth interface{}, requestObject api.ListVpnDeviceRequestObject) (*models.WgDeviceList, error) {
	token, namespace, userID, logger := common.ParseToken(auth, "list-wg-device", "List wg device", w.logger)
	if token == nil {
		return nil, common.ErrModelUnauthorized
	}

	var (
		ofUserID *types.UserID
		ofNamespace *string
	)
	if !token.IsAdminUser {
		ofUserID = &userID
	}
	if !token.IsSysAdmin {
		ofNamespace = &namespace
	}
	params := requestObject.Params
	list, num, err := db.GetWgInfoList(ofNamespace, ofUserID, params.Contain, params.Page, params.PageSize)
	if err != nil {
		logger.WithError(err).Errorln("Failed to list wg devices from db.")
		return nil, err
	}
	wgDevices, _ := types.SliceMap(list, func(w *types.WgInfo) (models.WgDevice, error) {
		return *w.ToModel(), nil
	})
	online := int64(0)
	for _, w := range wgDevices {
		if w.Name == "" {
			logger.Warnln("Invalid wg device name.")
			continue
		}
		log := logger.WithField("name", w.Name)
		if err := common.SetWgDeviceStats(&w); err != nil {
			log.Warnln("Can't set wg device stats.")
			continue
		}
		if common.IsLastSeenOnline(optional.Int64(w.LastSeen)) {
			online += 1
		}
	}
	return &models.WgDeviceList{
		Devices: wgDevices,
		Online:  int(online),
		Total:   int(num),
	}, nil
}

// Delete deletes the wg devices. Only admin can delete other user's device.
func (w *wgHandlerImpl) Delete(auth interface{}, requestObject api.DeleteVpnDevicesRequestObject) error {
	token, namespace, userID, logger := common.ParseToken(auth, "delete-wg-devices", "Delete wg devices", w.logger)
	if token == nil {
		return common.ErrModelUnauthorized
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	for _, id := range idList {
		log := logger.WithField(ulog.DeviceID, id)
		wgInfo, err := db.GetWgInfoOfDevice(namespace, id)
		if err != nil {
			if errors.Is(err, db.ErrDeviceWgInfoNotExists) {
				continue
			}
			log.WithError(err).Errorln("Failed to get wg info from db.")
			return common.ErrInternalErr
		}
		if wgInfo.UserID != userID && !token.IsAdminUser {
			log.Warnln("Non admin user trying to delete other user's device.")
			return common.ErrModelUnauthorized
		}
		if err = w.deleteWgDevice(namespace, id, wgInfo); err != nil {
			log.WithError(err).Errorln("Failed to delete wg device.")
			return common.ErrInternalErr
		}
	}
	return nil
}

func (w *wgHandlerImpl) Add(auth interface{}, requestObject api.AddVpnDeviceRequestObject) error {
	token, namespace, userID, logger := common.ParseToken(auth, "add-wg-device", "Add wg device", w.logger)
	if token == nil {
		return common.ErrModelUnauthorized
	}
	if requestObject.Body == nil {
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	params := requestObject.Params
	if params.UserID != nil && *params.UserID != userID.String() {
		logger = logger.WithField("target-user-id", *params.UserID)
		if !token.IsAdminUser {
			logger.Warnln("Non admin user trying to add wg device to other user.")
			return common.ErrModelUnauthorized
		}
		id, err := types.ParseID(*params.UserID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to parse user ID.")
			return common.NewBadParamsErr(err)
		}
		userID = id
	}

	// Check if the db has this user yet e.g. registered and enabled.
	user, err := db.GetUserFast(namespace, userID, false)
	if err != nil {
		logger.WithError(err).Errorln("failed to get user")
		if errors.Is(err, db.ErrUserNotExists) {
			return common.ErrModelUserNotExists
		}
		return common.ErrInternalErr
	}
	logger = logger.WithField(ulog.Username, user.UserBaseInfo.DisplayName)

	// TODO: Check if the WgInfo is correct. nil pointers et al.
	wgInfo := &types.WgInfo{}
	if err = wgInfo.FromModel(requestObject.Body); err != nil {
		logger.WithError(err).Errorln("Failed to parse wg info.")
		return common.NewBadParamsErr(err)
	}
	if err = db.CreateWgInfo(wgInfo); err != nil {
		common.DeleteDeviceInWgAgent(requestObject.Body)
		logger.WithError(err).Errorln("Failed to add new wg device.")
		if errors.Is(err, db.ErrDeviceNotExists) {
			return common.ErrModelDeviceNotExists
		}
		return common.ErrInternalErr
	}
	if wgInfo.WgName == "" {
		return nil
	}

	logger = logger.WithField(ulog.DeviceID, wgInfo.DeviceID).WithField(ulog.IP, wgInfo.IP)
	if err = w.fwService.AddEndpoint(namespace, userID, wgInfo.DeviceID, optional.String(wgInfo.IP()), wgInfo.WgName); err != nil {
		common.DeleteDeviceInWgAgent(requestObject.Body)
		db.DeleteWgInfo(namespace, wgInfo.DeviceID)
		logger.WithError(err).Errorln("Failed to add ep.")
		return common.ErrInternalErr
	}
	return nil
}

func (w *wgHandlerImpl) deleteWgDevice(namespace string, deviceID types.DeviceID, wgInfo *types.WgInfo) error {
	if err := db.DeleteWgInfo(namespace, deviceID); err != nil {
		return err
	}

	deviceIDstr := deviceID.String()
	for _, v := range wgInfo.Addresses {
		ip := v.Addr().String()
		if err := ipdrawer.ReleaseIPAddr(namespace, wgInfo.WgName, ip); err != nil {
			return err
		}
		if err := w.fwService.DelEndpoint(namespace, deviceIDstr, ip, wgInfo.Name); err != nil {
			return err
		}
	}

	// Continue to try to delete other info related to this wg device.
	wgDevice := wgInfo.ToModel()
	if err := common.DeleteDeviceInWgAgent(wgDevice); err != nil {
		return err
	}
	return nil
}

func (w *wgHandlerImpl) ListNodes(auth interface{}, requestObject api.ListWgNodesRequestObject) (total int, list []models.WgNode, err error) {
	token, namespace, _, logger := common.ParseToken(auth, "list-wg-nodes", "List wg nodes", w.logger)
	if token == nil || !token.IsAdminUser {
		err = common.ErrModelUnauthorized
		return
	}

	forNamespace := &namespace
	if token.IsSysAdmin {
		forNamespace = nil
	}
	params := requestObject.Params
	var wgNodes []*types.WgNode
	total, wgNodes, err = db.ListWgNodes(forNamespace, params.Page, params.PageSize)
	if err != nil {
		logger.WithError(err).Errorln("Failed to list wg nodes from db.")
		err = common.ErrInternalErr
		return
	}
	list, err = types.SliceMap(wgNodes, func(wgNode *types.WgNode) (models.WgNode, error){
		return *wgNode.ToModel(), nil
	})
	return
}

// Delete deletes the wg devices. Only admin can delete other user's device.
func (w *wgHandlerImpl) DeleteNodes(auth interface{}, requestObject api.DeleteWgNodesRequestObject) error {
	token, namespace, _, logger := common.ParseToken(auth, "delete-wg-nodes", "Delete wg nodes", w.logger)
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	for _, id := range idList {
		log := logger.WithField("wg-node-id", id)
		wgNode, err := db.GetWgNodeByID(id)
		if err != nil {
			if errors.Is(err, db.ErrWgNodeNotExists) {
				continue
			}
			log.WithError(err).Errorln("Failed to get wg node from db.")
			return common.ErrInternalErr
		}
		if wgNode.Namespace != namespace && !token.IsSysAdmin {
			log.Warnln("Non sys-admin trying to delete other namespace's wg node.")
			return common.ErrModelUnauthorized
		}
		if err = db.DeleteWgNode(id); err != nil {
			log.WithError(err).Errorln("Failed to delete wg node.")
			return common.ErrInternalErr
		}
	}
	return nil
}
