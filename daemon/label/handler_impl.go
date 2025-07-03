package label

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"errors"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
)

type handlerImpl struct {
	fwService fwconfig.ConfigService
	logger    *logrus.Entry
}

func newHandlerImpl(logger *logrus.Entry, fw fwconfig.ConfigService) *handlerImpl {
	return &handlerImpl{
		fwService: fw,
		logger:    logger,
	}
}

func (h *handlerImpl) processToken(
	auth interface{}, caller, description string,
) (token *utils.UserTokenData, namespace string, userID types.UserID, logger *logrus.Entry) {
	return common.ParseToken(auth, caller, description, h.logger)
}

// ListLabel return the list the labels. No record is not an error.
func (h *handlerImpl) ListLabel(auth interface{}, requestObject api.ListLabelRequestObject) (int64, []models.Label, error) {
	token, namespace, userID, logger := h.processToken(auth, "list-labels", "List labels")
	if token == nil {
		return 0, nil, common.ErrModelUnauthorized
	}

	forNamespace := &namespace
	if token.IsSysAdmin {
		forNamespace = nil
	}

	var scopes []*types.ID
	if !token.IsAdminUser {
		// Include user's own labels and unscoped aka public labels.
		scopes = []*types.ID{nil, &userID}
	}

	params := requestObject.Params
	if params.UserID != nil && *params.UserID != "" {
		id, err := types.ParseID(*params.UserID)
		if err != nil {
			return 0, nil, common.NewBadParamsErr(err)
		}
		if id != userID && !token.IsAdminUser {
			return 0, nil, common.ErrModelUnauthorized
		}
		scopes = []*types.ID{&id}
	}
	total, labels, err := db.GetLabelList(forNamespace, scopes,
		params.Name, (*string)(params.Category), params.FilterBy, params.FilterValue,
		params.SortBy, params.SortDesc, params.Page, params.PageSize,
	)
	if err == nil {
		return total, labels.ToModel(), nil
	}
	if errors.Is(err, common.ErrModelLabelNotExists) {
		return 0, nil, nil
	}
	logger.WithError(err).Errorln("Get labels failed")
	return 0, nil, common.ErrInternalErr
}

func (h *handlerImpl) CreateLabels(auth interface{}, requestObject api.CreateLabelsRequestObject) error {
	token, namespace, userID, logger := h.processToken(auth, "create-labels", "Create labels")

	var scope *types.ID
	if !token.IsAdminUser {
		scope = &userID
	}
	var list []*types.Label
	labels := requestObject.Body
	if labels == nil {
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	for _, label := range *labels {
		l := &types.Label{}
		l = l.FromModel(namespace, &label)
		l.Scope = scope
		list = append(list, l)
	}
	if err := db.CreateLabel(list...); err != nil {
		logger.WithError(err).Errorln("failed to create labels")
		return common.ErrInternalErr
	}
	return nil
}

// UpdateLabels update the labels.
// Note since labels relationships are based on the label IDs, updating labels
// do not change the relationships between labels and policyes, users or devices.
func (h *handlerImpl) UpdateLabels(auth interface{}, requestObject api.UpdateLabelsRequestObject) error {
	token, namespace, userID, logger := h.processToken(auth, "update-labels", "Update labels")
	if token == nil {
		return common.ErrModelUnauthorized
	}
	params := requestObject.Body
	if params == nil || params.Update == nil || params.IDList == nil ||
		len(*params.IDList) <= 0 {
		err := errors.New("missing input or update or id list")
		return common.NewBadParamsErr(err)
	}
	var scope *types.ID
	if !token.IsAdminUser {
		scope = &userID
	}
	var update *types.Label
	update = update.FromModel(namespace, params.Update)
	idList := types.UUIDListToIDList(params.IDList)
	if err := db.UpdateLabels(namespace, &scope, idList, *update); err != nil {
		logger.WithError(err).Errorln("Failed to update.")
		return common.ErrInternalErr
	}
	return nil
}

// DeleteLabels delete labels and update the device in Tai if necessary.
func (h *handlerImpl) DeleteLabels(auth interface{}, requestObject api.DeleteLabelsRequestObject) error {
	token, namespace, userID, logger := h.processToken(auth, "delete-labels", "Delete labels")
	if token == nil {
		return common.ErrModelUnauthorized
	}
	params := requestObject.Body
	if params == nil || len(*params) <= 0 {
		return nil
	}
	var scope *types.ID
	if !token.IsAdminUser {
		scope = &userID
	}
	idList := types.UUIDListToIDList(params)
	if err := db.DeleteLabels(namespace, &scope, idList); err != nil {
		logger.WithError(err).Errorln("Failed to delete.")
		return common.ErrInternalErr
	}
	return nil
}

func (h *handlerImpl) GetLabel(auth interface{}, requestObject api.GetLabelRequestObject) (*models.Label, error) {
	token, namespace, userID, logger := h.processToken(auth, "get-label", "Get a label")
	if token == nil {
		return nil, common.ErrModelUnauthorized
	}
	logger = logger.WithField("label-id", requestObject.LabelID)
	id, err := types.ParseID(requestObject.LabelID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to parse label ID.")
		return nil, common.NewBadParamsErr(err)
	}
	var scope *types.ID
	if !token.IsAdminUser {
		scope = &userID
	}
	label, err := db.GetLabel(namespace, &scope, id)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get label with ID")
		if errors.Is(err, db.ErrLabelNotExists) {
			return nil, common.NewBadParamsErr(err)
		}
		return nil, common.ErrInternalErr
	}
	return label.ToModel(), nil
}

func (h *handlerImpl) UpdateLabel(auth interface{}, requestObject api.UpdateLabelRequestObject) error {
	token, namespace, userID, logger := h.processToken(auth, "update-label", "Update a label")
	if token == nil {
		return common.ErrModelUnauthorized
	}
	if requestObject.Body == nil {
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	logger = logger.WithField("label-id", requestObject.LabelID)
	id, err := types.ParseID(requestObject.LabelID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to parse label ID.")
		return common.NewBadParamsErr(err)
	}
	var update *types.Label
	update = update.FromModel(namespace, requestObject.Body)

	var scope *types.ID
	if !token.IsAdminUser {
		scope = &userID
	}
	if err := db.UpdateLabel(namespace, &scope, id, *update); err != nil {
		logger.WithError(err).Errorln("Failed to update the label in the db.")
		if errors.Is(err, db.ErrLabelNotExists) {
			return common.NewBadParamsErr(err)
		}
		return common.ErrInternalErr
	}
	return nil
}

// Delete a label
func (h *handlerImpl) DeleteLabel(auth interface{}, requestObject api.DeleteLabelRequestObject) error {
	token, namespace, userID, logger := h.processToken(auth, "delete-label", "Delete a label")
	if token == nil {
		return common.ErrModelUnauthorized
	}
	params := requestObject
	id, err := types.ParseID(params.LabelID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to parse label ID")
		return common.NewBadParamsErr(err)
	}
	var scope *types.ID
	if !token.IsAdminUser {
		scope = &userID
	}
	if err := db.DeleteLabel(namespace, &scope, id); err != nil {
		logger.WithError(err).Errorln("Failed to delete.")
		return common.ErrInternalErr
	}
	return nil
}
