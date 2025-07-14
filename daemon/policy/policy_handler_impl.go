// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package policy

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/daemon/policy/cilium"
	"cylonix/sase/pkg/fwconfig"
	"errors"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

type policyHandlerImpl struct {
	fwService fwconfig.ConfigService
	logger    *logrus.Entry
}

func newPolicyHandlerImpl(fwService fwconfig.ConfigService, logger *logrus.Entry) *policyHandlerImpl {
	return &policyHandlerImpl{
		fwService: fwService,
		logger:    logger,
	}
}

func (h *policyHandlerImpl) Get(auth interface{}, requestObject api.GetPolicyRequestObject) (*models.Policy, error) {
	token, namespace, _, logger := common.ParseToken(auth, "get-policy", "Get policy", h.logger)
	if token == nil || !token.IsAdminUser {
		return nil, common.ErrModelUnauthorized
	}
	params := requestObject
	logger = logger.WithField("policy-id", params.PolicyID)
	id, err := types.ParseID(params.PolicyID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to parse policy ID.")
	}
	p, err := db.GetPolicy(namespace, id)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get policy.")
		return nil, common.ErrInternalErr
	}
	return p.ToModel(), nil
}
func (h *policyHandlerImpl) Count(auth interface{}, requestObject api.PolicyCountRequestObject) (total int64, err error) {
	token, namespace, _, logger := common.ParseToken(auth, "list-policy", "List policy", h.logger)
	if token == nil || !token.IsAdminUser {
		err = common.ErrModelUnauthorized
		return
	}
	total, err = db.PolicyCount(namespace)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get policy count from db.")
		err = common.ErrInternalErr
		return
	}
	return
}
func (h *policyHandlerImpl) List(auth interface{}, requestObject api.ListPolicyRequestObject) (total int64, list []models.Policy, err error) {
	token, namespace, _, logger := common.ParseToken(auth, "list-policy", "List policy", h.logger)
	if token == nil || !token.IsAdminUser {
		err = common.ErrModelUnauthorized
		return
	}
	var policyList []types.Policy
	params := requestObject.Params
	total, policyList, err = db.GetPolicyList(namespace,
		params.Contain, params.FilterBy, params.FilterValue,
		params.SortBy, params.SortDesc, params.Page, params.PageSize)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get policy list from db.")
		err = common.ErrInternalErr
		return
	}
	list = types.PolicyList(policyList).ToModel()
	return
}

func (h *policyHandlerImpl) Create(auth interface{}, requestObject api.CreatePolicyRequestObject) error {
	token, namespace, _, logger := common.ParseToken(auth, "create-policy", "Create policy", h.logger)
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	params := requestObject.Body
	if params == nil || params.TargetID == nil || *params.TargetID == uuid.Nil {
		logger.Warnln("Nil policy target.")
		err := errors.New("missing policy input or target id")
		return common.NewBadParamsErr(err)
	}

	var p *types.Policy
	p = p.FromModel(namespace, params)
	if err := db.CreatePolicy(p); err != nil {
		logger.WithError(err).Errorln("Failed to create new policy.")
		return common.ErrInternalErr
	}
	logger = logger.WithField("policy-id", p.ID.String())
	target, err := db.GetPolicyTarget(namespace, *p.PolicyTargetID)
	if err != nil {
		logger.WithError(err).Error("Failed to get policy target.")
		return common.ErrInternalErr
	}
	if err = cilium.CreateOrUpdatePolicy(
		namespace, params, target.ToModel(), nil, false,
		includeAllLabel(params), h.fwService,
	); err != nil {
		logger.WithError(err).Errorln("Failed to add policy to cilium")
		db.DeletePolicy(namespace, p.ID)
		if errors.Is(err, cilium.ErrPolicyNotSupported) {
			return common.ErrModelPolicyNotSupported
		}
		return common.ErrInternalErr
	}
	return nil
}

func (h *policyHandlerImpl) Update(auth interface{}, requestObject api.UpdatePolicyRequestObject) error {
	token, namespace, _, logger := common.ParseToken(auth, "update-policy", "Update policy", h.logger)
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	params := requestObject
	logger = logger.WithField("policy-id", params.PolicyID)
	policyID, err := types.ParseID(params.PolicyID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to parse policy ID.")
	}
	p, err := db.GetPolicy(namespace, policyID)
	if err != nil {
		logger.WithError(err).Error("Failed to fetch policy from db.")
		if errors.Is(err, db.ErrPolicyNotExists) {
			return common.ErrModelPolicyNotExists
		}
		return common.ErrInternalErr
	}
	up := params.Body
	if up == nil || up.TargetID == nil || *up.TargetID == uuid.Nil {
		logger.Warnln("Nil target.")
		return common.NewBadParamsErr(err)
	}
	target, err := db.GetPolicyTarget(namespace, types.UUIDToID(*up.TargetID))
	if err != nil {
		logger.WithError(err).Error("Failed to get the policy target.")
		if errors.Is(err, db.ErrPolicyTargetNotExists) {
			return common.ErrModelPolicyTargetNotExists
		}
		return common.ErrInternalErr
	}

	// Refresh path select.
	ps := up.PathSelect
	if ps != nil && ps.ID != uuid.Nil {
		if err = common.RefreshDiversionPolicy(namespace, p.ID, false); err != nil {
			logger.WithError(err).Errorln("Failed to refresh path select.")
			return common.ErrInternalErr
		}
	}
	if err = cilium.CreateOrUpdatePolicy(
		namespace, up, target.ToModel(), nil, true,
		includeAllLabel(up), h.fwService,
	); err != nil {
		logger.WithError(err).Errorln("Failed to update policy in cilium.")
		if errors.Is(err, cilium.ErrPolicyNotSupported) {
			return common.ErrModelPolicyNotSupported
		}
		return common.ErrInternalErr
	}
	if err = db.UpdatePolicy(namespace, p.ID, up); err != nil {
		logger.WithError(err).Errorln("Failed to update policy in db.")
		return common.ErrInternalErr
	}
	return nil
}

func (h *policyHandlerImpl) Delete(auth interface{}, requestObject api.DeletePolicyRequestObject) (ret error) {
	token, namespace, _, logger := common.ParseToken(auth, "delete-policy", "Delete policy", h.logger)
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	params := requestObject
	logger = logger.WithField("policy-id", params.PolicyID)
	policyID, err := types.ParseID(params.PolicyID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to parse policy ID.")
	}
	if err := cilium.Delete(namespace, params.PolicyID, "", nil, h.fwService); err != nil {
		logger.WithError(err).Errorln("Failed to delete policy in cilium.")
		ret = common.ErrInternalErr
	}
	if err := common.RefreshDiversionPolicy(namespace, policyID, true); err != nil {
		logger.WithError(err).Errorln("Failed to refresh path select.")
		ret = common.ErrInternalErr
	}
	if err := db.DeletePolicy(namespace, policyID); err != nil {
		logger.WithError(err).Errorln("Failed to delete policy in db.")
		ret = common.ErrInternalErr
	}
	return
}

func (h *policyHandlerImpl) DeleteList(auth interface{}, requestObject api.DeletePolicyListRequestObject) (ret error) {
	token, namespace, _, logger := common.ParseToken(auth, "delete-policy-list", "Delete policy list", h.logger)
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	if requestObject.Body == nil {
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	for _, policyID := range *requestObject.Body {
		log := logger.WithField("policy-id", policyID.String())
		if err := cilium.Delete(namespace, policyID.String(), "", nil, h.fwService); err != nil {
			log.WithError(err).Errorln("Failed to delete policy in cilium.")
			ret = common.ErrInternalErr
		}
		if err := common.RefreshDiversionPolicy(namespace, types.UUIDToID(policyID), true); err != nil {
			log.WithError(err).Errorln("Failed to refresh path select.")
			ret = common.ErrInternalErr
		}
	}
	if err := db.DeletePolicyList(namespace, types.UUIDListToIDList(requestObject.Body)); err != nil {
		logger.WithError(err).Errorln("Failed to delete policy list.")
		ret = common.ErrInternalErr
	}
	return
}

func (h *policyHandlerImpl) ListTemplate(auth interface{}, requestObject api.ListPolicyTemplateRequestObject) (total int64, list []models.PolicyTemplate, err error) {
	token, _, _, _ := common.ParseToken(auth, "list-policy-template", "List policy template", h.logger)
	if token == nil || !token.IsAdminUser {
		err = common.ErrModelUnauthorized
		return
	}
	err = common.ErrInternalErr
	return
}

func (h *policyHandlerImpl) PacFileList(interface{}, api.GetPacFileListRequestObject) (models.PacFileList, error) {
	var tags models.PacFileList
	for _, f := range utils.GetPacFileList() {
		if f.IsValid {
			name := f.Name
			id := ""
			t := models.Tag{
				ID:   id,
				Name: name,
			}
			tags = append(tags, t)
		}
	}
	return tags, nil
}

func includeAllLabel(policy *models.Policy) bool {
	for _, label := range policy.Sources {
		if label.Name != "" &&
			label.Name == utils.PathSelectionModeGlobalLabel {
			return true
		}
	}
	return false
}
