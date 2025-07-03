package accesskey

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"errors"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type handlerImpl struct {
	logger *logrus.Entry
}

func newHandlerImpl(logger *logrus.Entry) *handlerImpl {
	return &handlerImpl{
		logger: logger,
	}
}

func (h *handlerImpl) List(auth interface{}, params models.ListAccessKeyParams) (int, *[]models.AccessKey, error) {
	token, namespace, userID, logger := common.ParseToken(auth, "list-access-key", "List access keys", h.logger)
	if token == nil {
		return 0, nil, common.ErrModelUnauthorized
	}
	var ofUserID *types.UserID
	if !token.IsAdminUser {
		ofUserID = &userID
	}
	if params.UserID != nil && *params.UserID != userID.String() && *params.UserID != "" {
		if !token.IsAdminUser {
			logger.Warnln("Non-admin user trying to list access keys of another user.")
			return 0, nil, common.ErrModelUnauthorized
		}
		id, err := types.ParseID(*params.UserID)
		if err != nil {
			logger.WithError(err).WithField(ulog.UserID, *params.UserID).Errorln("Failed to parse user ID.")
		}
		ofUserID = &id
		logger = logger.WithField("target-user-id", *params.UserID)
	}

	total, keys, err := db.ListAccessKey(namespace, ofUserID, params.Contain,
		params.FilterBy, params.FilterValue, params.SortBy, params.SortDesc,
		params.Page, params.PageSize,
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to list the access keys.")
		return 0, nil, common.ErrInternalErr
	}
	return total, keys, nil
}

func (h *handlerImpl) Get(auth interface{}, accessKeyID string) (*models.AccessKey, error) {
	token, namespace, userID, logger := common.ParseToken(auth, "get-access-key", "Get access key", h.logger)
	if token == nil {
		return nil, common.ErrModelUnauthorized
	}
	if accessKeyID == "" {
		err := errors.New("empty access key")
		return nil, common.NewBadParamsErr(err)
	}
	logger = logger.WithField("access-key", utils.ShortString(accessKeyID))
	key, err := db.GetAccessKey(namespace, accessKeyID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get access key.")
		if errors.Is(err, db.ErrAccessKeyInvalid) {
			return nil, common.NewBadParamsErr(err)
		}
		return nil, common.ErrInternalErr
	}
	if key.UserID != userID && !token.IsAdminUser {
		logger.Warnln("Non-admin user trying to get access key of another user.")
		// TODO probably should delete the key too as it is compromised already.
		return nil, common.ErrInternalErr
	}
	return key.ToModel(), nil
}

func (h *handlerImpl) Create(auth interface{}, input *models.AccessKey) (*models.AccessKey, error) {
	token, namespace, userID, logger := common.ParseToken(auth, "create-access-key", "Create access keys", h.logger)
	if token == nil {
		return nil, common.ErrModelUnauthorized
	}
	if input == nil {
		err := errors.New("empty access key")
		logger.Warnln("Nil access key input.")
		return nil, common.NewBadParamsErr(err)
	}
	if input.UserID != uuid.Nil && input.UserID != userID.UUID() {
		logger = logger.WithField("target-user-id", input.UserID)
		if !token.IsAdminUser {
			logger.Warnln("Non-admin user trying to create access key of another user.")
			return nil, common.ErrModelUnauthorized
		}
		userID = types.UUIDToID(input.UserID)
	}
	su, err := db.GetUserBaseInfoFast(namespace, userID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get user from db.")
		if errors.Is(err, db.ErrUserNotExists) {
			return nil, common.ErrModelUserNotExists
		}
		return nil, common.ErrInternalErr
	}
	key, err := db.CreateAccessKey(namespace, userID, su.DisplayName, input.Note, input.Scope, input.ExpiresAt)
	if err != nil {
		logger.WithError(err).Errorf("Failed to create access key.")
		return nil, common.ErrInternalErr
	}
	return key.ToModel(), nil
}

func (h *handlerImpl) Delete(auth interface{}, accessKeyID string) error {
	token, namespace, userID, logger := common.ParseToken(auth, "delete-access-key", "Delete access key", h.logger)
	if token == nil {
		return common.ErrModelUnauthorized
	}
	if accessKeyID == "" {
		err := errors.New("empty access key")
		return common.NewBadParamsErr(err)
	}
	logger = logger.WithField("access-key", utils.ShortString(accessKeyID))
	key, err := db.GetAccessKey(namespace, accessKeyID)
	if err != nil {
		if errors.Is(err, db.ErrAccessKeyInvalid) {
			return nil
		}
		logger.WithError(err).Errorln("Failed to get access key.")
		return common.ErrInternalErr
	}
	if key.UserID != userID && !token.IsAdminUser {
		logger.Warnln("Non-admin user trying to delete other user's access key.")
		// TODO probably should delete the key anyway as it is compromised already.
		return common.ErrInternalErr
	}
	if err := db.DeleteAccessKey(namespace, accessKeyID); err != nil {
		logger.WithError(err).Errorln("Failed to delete access key.")
		return common.ErrInternalErr
	}
	return nil
}
