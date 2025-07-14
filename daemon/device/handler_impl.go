// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package device

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/vpn"
	"errors"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"github.com/google/uuid"

	"github.com/sirupsen/logrus"
)

type handlerImpl struct {
	fwService fwconfig.ConfigService
	logger    *logrus.Entry
}

func newHandlerImpl(fwService fwconfig.ConfigService, logger *logrus.Entry) *handlerImpl {
	return &handlerImpl{
		fwService: fwService,
		logger:    logger,
	}
}

func (h *handlerImpl) parseToken(
	auth interface{}, caller, description string,
) (token *utils.UserTokenData, namespace string, userID types.UserID, logger *logrus.Entry) {
	return common.ParseToken(auth, caller, description, h.logger)
}

func (h *handlerImpl) GetDevices(auth interface{}, requestObject api.GetDevicesRequestObject) (*models.DeviceList, error) {
	token, namespace, userID, logger := h.parseToken(auth, "get-devices", "Get devices")
	params := requestObject.Params
	if params.UserID == nil && !token.IsAdminUser {
		return nil, common.ErrModelUnauthorized
	}
	if params.UserID != nil {
		if *params.UserID != userID.String() {
			logger = logger.WithField("target-user-id", *params.UserID)
			if !token.IsAdminUser {
				return nil, common.ErrModelUnauthorized
			}
		}
	}

	// Get a specific device with user ID and device ID.
	// Need user ID to check permission.
	if params.DeviceID != nil {
		if params.UserID == nil {
			err := errors.New("missing user id")
			return nil, common.NewBadParamsErr(err)
		}
		logger = logger.WithField(ulog.DeviceID, *params.DeviceID)
		deviceID, err := types.ParseID(*params.DeviceID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get parse device ID.")
			return nil, common.NewBadParamsErr(err)
		}
		userID, err := types.ParseID(*params.UserID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get parse user ID.")
			return nil, common.NewBadParamsErr(err)
		}
		device, err := db.GetUserDeviceFast(namespace, userID, deviceID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get specific device.")
			return nil, err
		}
		return &models.DeviceList{
			Devices: []models.Device{*device.ToModel()},
		}, nil
	}

	var targetUserID *types.UserID
	if params.UserID != nil && *params.UserID != "" {
		id, err := types.ParseID(*params.UserID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get parse user ID.")
			return nil, common.NewBadParamsErr(err)
		}
		targetUserID = &id
	} else if !token.IsAdminUser {
		targetUserID = &userID
	}

	var namespaceP *string
	if !token.IsSysAdmin {
		namespaceP = &namespace
	}
	devices, total, err := db.ListDevice(
		namespaceP, targetUserID, params.Capability,
		params.FilterBy, params.FilterValue, params.SortBy, params.SortDesc,
		params.Page, params.PageSize,
	)
	if err != nil {
		if errors.Is(err, db.ErrDeviceNotExistsInUser) {
			return nil, common.ErrModelDeviceNotExists
		}
		logger.WithError(err).Errorln("Failed to get sorted device list.")
		return nil, common.ErrInternalErr
	}
	return &models.DeviceList{
		Total:   int(total),
		Devices: types.DeviceList(devices).ToModel(),
	}, nil
}

func (h *handlerImpl) PutDevice(auth interface{}, requestObject api.PutDeviceRequestObject) (err error) {
	token, namespace, userID, logger := h.parseToken(auth, "put-device", "Put device")
	update := requestObject.Body
	params := requestObject.Params
	if update == nil || params.DeviceID == "" {
		return common.NewBadParamsErr(err)
	}
	log := logger.WithField(ulog.DeviceID, params.DeviceID)
	var deviceID types.DeviceID
	deviceID, err = types.ParseID(params.DeviceID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to parse device ID.")
		return common.NewBadParamsErr(err)
	}
	device := &types.Device{}
	forNamespace := namespace
	if token.IsSysAdmin {
		forNamespace = ""
	}
	err = db.GetUserDevice(forNamespace, deviceID, device)
	if err != nil {
		if errors.Is(err, db.ErrDeviceNotExists) {
			return common.ErrModelDeviceNotExists
		}
		log.WithError(err).Errorln("Failed to get existing device")
		err = common.ErrInternalErr
		return
	}
	if device.UserID != userID && !token.IsAdminUser {
		err = common.ErrModelUnauthorized
		return
	}

	namespace = device.Namespace
	if device.WgInfo != nil && device.WgInfo.NodeID != nil {
		nodeID := *device.WgInfo.NodeID
		if update.AddCapability != nil || update.DelCapability != nil {
			var add, del []string
			if update.AddCapability != nil {
				add = []string{*update.AddCapability}
			}
			if update.DelCapability != nil {
				del = []string{*update.DelCapability}
			}
			if err = vpn.UpdateNodeCapabilities(namespace, nodeID, add, del); err != nil {
				log.WithError(err).Errorln("Failed to update vpn node capabilities.")
				err = common.ErrInternalErr
				return
			}
			defer func() {
				if err != nil {
					if newErr := vpn.UpdateNodeCapabilities(namespace, nodeID, del, add); newErr != nil {
						log.WithError(newErr).Errorln("Failed to rollback vpn node capabilities.")
					}
				}
			}()
		}
	}

	// Update postgres db.
	err = db.UpdateDevice(namespace, device.UserID, deviceID, update)
	if err != nil {
		log.WithError(err).Error("Update device failed")
		err = common.ErrInternalErr
		return
	}
	return
}

// Post device creates a new device that will be assigned with a new device ID.
func (h *handlerImpl) PostDevice(auth interface{}, requestObject api.PostDeviceRequestObject) error {
	token, namespace, _, logger := h.parseToken(auth, "post-device", "Post device")
	if !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	r := requestObject.Body
	if r == nil || r.ID != uuid.Nil || r.UserID == uuid.Nil {
		err := errors.New("missing input or missing id or user id")
		return common.NewBadParamsErr(err)
	}

	userID := types.UUIDToID(r.UserID)
	logger = logger.WithField("target-user-id", userID.String())
	user, err := db.GetUserBaseInfoFast(namespace, userID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get user.")
		if errors.Is(err, db.ErrUserNotExists) {
			return common.ErrModelUserNotExists
		}
		return common.ErrInternalErr
	}

	device := &types.Device{}
	if err := device.FromModel(namespace, r); err != nil {
		logger.WithError(err).Errorln("Failed to parse device.")
		return common.NewBadParamsErr(err)
	}
	device.ID, err = types.NewID()
	if err != nil {
		logger.WithError(err).Errorln("Failed to get new device ID.")
		return common.ErrInternalErr
	}
	err = db.AddUserDevice(namespace, userID, device)
	if err != nil {
		logger.WithError(err).Errorln("failed to create new device")
		return common.ErrInternalErr
	}
	defer func() {
		if err == nil {
			return
		}
		if newErr := db.DeleteUserDevices(namespace, userID, []types.DeviceID{device.ID}); newErr != nil {
			logger.WithError(err).Errorln("Failed to delete the failed device.")
		}
	}()

	if device.WgInfo != nil && common.IsGatewaySupportedForUser(namespace, userID) && device.WgInfo.WgID != "" {
		w := device.WgInfo.ToModel()
		if err = common.CreateDeviceInWgAgent(w); err != nil {
			logger.WithError(err).Errorln("Failed to add device to wg agent.")
			return common.ErrInternalErr
		}
		defer func() {
			if err == nil {
				return
			}
			if newErr := common.DeleteDeviceInWgAgent(w); newErr != nil {
				logger.WithError(err).Errorln("Failed to delete the failed wg device.")
			}
		}()
		wgName := device.WgInfo.WgName
		for _, ip := range device.WgInfo.Addresses {
			logger = logger.WithField(ulog.IP, ip.String())
			if err := h.fwService.AddEndpoint(namespace, user.UserID, device.ID, ip.String(), wgName); err != nil {
				logger.WithError(err).Errorln("Failed to add ep to fw.")
				return common.ErrInternalErr
			}
		}
	}

	return nil
}

func (h *handlerImpl) DeleteDevices(auth interface{}, requestObject api.DeleteDevicesRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "delete-devices", "Delete devices")
	if requestObject.Body == nil {
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	params := requestObject.Params
	alsoDeleteApprovalRecord := false
	if params.AlsoDeleteApprovalRecord != nil {
		alsoDeleteApprovalRecord = *params.AlsoDeleteApprovalRecord
	}
	forNamespace := namespace
	if token.IsSysAdmin {
		forNamespace = ""
	}
	for _, id := range idList {
		log := logger.WithField(ulog.DeviceID, id)
		device := &types.Device{}
		err := db.GetUserDevice(forNamespace, id, device)
		if err != nil {
			if errors.Is(err, db.ErrDeviceNotExists) {
				continue
			}
			log.WithError(err).Errorln("Failed to get device")
			return err
		}
		if device.UserID != userID && !token.IsAdminUser {
			return common.ErrModelUnauthorized
		}
		namespace = device.Namespace
		if alsoDeleteApprovalRecord && device.DeviceApprovalID != nil {
			if err := db.DeleteDeviceApproval(namespace, nil, *device.DeviceApprovalID); err != nil {
				log.WithError(err).Errorln("delete device approval info failed")
				return common.ErrInternalErr
			}
		}
		if err := DeleteDeviceInAllForPG(namespace, device.UserID, id, h.fwService); err != nil {
			log.WithError(err).Errorln("Delete device in all database failed")
			return common.ErrInternalErr
		}
	}
	return nil
}

func (h *handlerImpl) GetApprovalRecords(auth interface{}, requestObject api.ListDeviceApprovalRecordsRequestObject) (int, []models.DeviceApprovalRecord, error) {
	token, namespace, userID, logger := h.parseToken(auth, "get-device-approval-records", "Get device approval records")
	var ofUserID *types.UserID
	if !token.IsAdminUser {
		ofUserID = &userID
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	params := requestObject.Params
	total, list, err := db.GetDeviceApprovalList(namespace, ofUserID,
		params.ApprovalState, params.Contain, params.FilterBy,
		params.FilterValue, params.SortBy, params.SortDesc, idList,
		params.Page, params.PageSize,
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get approval records from the db.")
		return 0, nil, common.ErrInternalErr
	}
	logger.WithField("total", total).WithField("len", len(list)).Debugln("Success.")
	return total, list, nil
}
func (h *handlerImpl) ApproveDevices(auth interface{}, requestObject api.ApproveDevicesRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "approve-devices", "Approve devices")
	state := requestObject.Params.ApprovalState
	note := requestObject.Params.Note
	logger = logger.WithField("approval-state", state)
	if requestObject.Body == nil {
		logger.Warnln("BadParameters with empty request list.")
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	var ofUserID *types.UserID
	if !token.IsAdminUser {
		ofUserID = &userID
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	for _, id := range idList {
		_, err := db.GetDeviceApproval(namespace, ofUserID, id)
		log := logger.WithField("approval-id", id.String())
		if err != nil {
			log.WithError(err).Errorln("Failed to get approval record.")
			if errors.Is(err, db.ErrDeviceApprovalNotExists) {
				return common.NewBadParamsErr(err)
			}
			return common.ErrInternalErr
		}
		if err := db.SetDeviceApprovalState(
			namespace, ofUserID, id, userID, token.Username,
			note, types.ApprovalState(state),
		); err != nil {
			log.WithError(err).Errorln("Failed to set approval state in db.")
			return common.ErrInternalErr
		}
		log.Debugln("Device approved.")
	}
	return nil
}
func (h *handlerImpl) DeleteApprovalRecords(auth interface{}, requestObject api.DeleteDeviceApprovalRecordsRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "delete-approval-records", "Delete approval records")
	var ofUserID *types.UserID
	if !token.IsAdminUser {
		ofUserID = &userID
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	for _, id := range idList {
		log := logger.WithField("approval-id", id.String())
		if err := db.DeleteDeviceApproval(namespace, ofUserID, id); err != nil {
			log.WithError(err).Errorln("Failed to delete device approval.")
			return common.ErrInternalErr
		}
	}
	return nil
}
