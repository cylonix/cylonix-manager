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
	"fmt"
	"strings"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
)

var (
	errPolicyTargetInUse = errors.New("policy target is in use")
)

type targetHandlerImpl struct {
	fwService fwconfig.ConfigService
	logger    *logrus.Entry
}

func newTargetHandlerImpl(fwService fwconfig.ConfigService, logger *logrus.Entry) *targetHandlerImpl {
	return &targetHandlerImpl{
		fwService: fwService,
		logger:    logger,
	}
}
func checkPolicyTarget(target *models.PolicyTarget) (err error) {
	for _, r := range *target.FQDNRuleList {
		if r.MatchValue == "" {
			continue
		}
		v := r.MatchValue
		switch r.MatchType {
		case models.MatchTypePac:
			found := false
			files := utils.GetPacFileList()
			for _, f := range files {
				if f.Name != v {
					continue
				}
				if !f.IsValid {
					err = fmt.Errorf("pac content is invalid for %v", v)
					continue
				}
				found = true
				break
			}
			if !found && err == nil && !strings.Contains(v, "FindProxyForURL") {
				err = fmt.Errorf("cannot found pac for %v", v)
			}
		}
	}
	return
}

func (h *targetHandlerImpl) List(auth interface{}, requestObject api.ListPolicyTargetRequestObject) (*models.PolicyTargetList, error) {
	token, namespace, _, logger := common.ParseToken(auth, "list-policy-target", "List policy target", h.logger)
	if token == nil || !token.IsAdminUser {
		return nil, common.ErrModelUnauthorized
	}
	params := requestObject.Params
	total, list, err := db.ListPolicyTarget(namespace,
		params.Contain, params.FilterBy, params.FilterValue,
		params.SortBy, params.SortDesc, params.Page, params.PageSize,
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get policy target from db.")
		return nil, common.ErrInternalErr
	}
	var targetList []models.PolicyTarget
	for _, v := range list {
		targetList = append(targetList, *v.ToModel())
	}
	return &models.PolicyTargetList{
		Total: int(total),
		Items: &targetList,
	}, nil
}

// Don't allow delete if there is a policy referring to the target.
func (h *targetHandlerImpl) delete(namespace string, id types.PolicyTargetID) error {
	count, err := db.TargetPolicyCount(namespace, id)
	if err != nil {
		return err
	}
	if count > 0 {
		return errPolicyTargetInUse
	}
	return db.DeletePolicyTarget(namespace, id, false)
}

func (h *targetHandlerImpl) DeleteList(auth interface{}, requestObject api.DeletePolicyTargetListRequestObject) (ret error) {
	token, namespace, _, logger := common.ParseToken(auth, "delete-policy-target-list", "Delete policy target list", h.logger)
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	if requestObject.Body == nil {
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	for _, id := range *requestObject.Body {
		log := logger.WithField("policy-target-id", id)
		if err := h.delete(namespace, types.UUIDToID(id)); err != nil {
			log.WithError(err).Errorln("Failed to delete policy target in db.")
			ret = err
		}
	}
	return nil
}

func (h *targetHandlerImpl) Delete(auth interface{}, requestObject api.DeletePolicyTargetRequestObject) (ret error) {
	token, namespace, _, logger := common.ParseToken(auth, "delete-policy-target", "Delete policy target", h.logger)
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	log := logger.WithField("policy-target-id", requestObject.TargetID)
	id, err := types.ParseID(requestObject.TargetID)
	if err != nil {
		log.WithError(err).Errorln("Failed to parse target ID.")
		return common.NewBadParamsErr(err)
	}
	if err := h.delete(namespace, id); err != nil {
		log.WithError(err).Errorln("Failed to delete policy target in db.")
		if errors.Is(err, errPolicyTargetInUse) {
			return common.ErrModelPolicyTargetInUse
		}
		return common.ErrInternalErr
	}
	return nil
}

func (h *targetHandlerImpl) Get(auth interface{}, requestObject api.GetPolicyTargetRequestObject) (*models.PolicyTarget, error) {
	token, namespace, _, logger := common.ParseToken(auth, "get-policy-target", "Get policy target", h.logger)
	if token == nil || !token.IsAdminUser {
		return nil, common.ErrModelUnauthorized
	}
	logger = logger.WithField("policy-target-id", requestObject.TargetID)
	id, err := types.ParseID(requestObject.TargetID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to parse target ID.")
		return nil, common.NewBadParamsErr(err)
	}
	t, err := db.GetPolicyTarget(namespace, id)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get target from db.")
		if errors.Is(err, db.ErrPolicyTargetNotExists) {
			return nil, common.ErrModelPolicyTargetNotExists
		}
		return nil, common.ErrInternalErr
	}
	return t.ToModel(), nil
}

func (h *targetHandlerImpl) Create(auth interface{}, requestObject api.CreatePolicyTargetRequestObject) error {
	token, namespace, _, logger := common.ParseToken(auth, "create-policy-target", "create policy target", h.logger)
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	target := requestObject.Body
	if target == nil || target.Name == "" {
		err := errors.New("missing target input or target name")
		logger.Warnln("Invalid policy target name.")
		return common.NewBadParamsErr(err)
	}
	logger = logger.WithField("policy-target-name", target.Name)
	if err := checkPolicyTarget(target); err != nil {
		logger.WithError(err).Errorln("Invalid policy target")
		return common.NewBadParamsErr(err)
	}
	_, err := db.GetPolicyTargetByName(namespace, target.Name)
	if err == nil {
		err = common.ErrModelPolicyTargetExists
		logger.WithError(err).Errorln("Failed.")
		return err
	}
	if !errors.Is(err, db.ErrPolicyTargetNotExists) {
		logger.WithError(err).Errorln("Failed to access db.")
		return common.ErrInternalErr
	}
	var t *types.PolicyTarget
	t = t.FromModel(namespace, target)
	if err := db.CreatePolicyTarget(t); err != nil {
		logger.WithError(err).Errorln("Failed to create target in db.")
		return common.ErrInternalErr
	}
	return nil
}

func (h *targetHandlerImpl) Update(auth interface{}, requestObject api.UpdatePolicyTargetRequestObject) error {
	token, namespace, _, logger := common.ParseToken(auth, "update-policy-target", "update policy target", h.logger)
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	params := requestObject
	target := params.Body
	if params.TargetID == "" {
		logger.Warnln("Nil policy target ID.")
		err := errors.New("missing target id")
		return common.NewBadParamsErr(err)
	}
	logger = logger.WithField("policy-target-id", params.TargetID)
	targetID, err := types.ParseID(params.TargetID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to parse target ID.")
		return common.NewBadParamsErr(err)
	}

	if err := checkPolicyTarget(target); err != nil {
		logger.WithError(err).Errorln("Invalid policy target")
		return common.NewBadParamsErr(err)
	}

	var update *types.PolicyTarget
	update = update.FromModel(namespace, target)
	if err := db.UpdatePolicyTarget(namespace, targetID, update); err != nil {
		logger.WithError(err).Errorln("Failed to update target to db")
		return common.ErrInternalErr
	}

	policyList, err := db.PolicyListOfTargetID(namespace, targetID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get policies of the target.")
		return common.ErrInternalErr
	}

	for _, p := range policyList {
		m := p.ToModel()
		log := logger.WithField("policy-id", p.ID)
		if err = cilium.CreateOrUpdatePolicy(namespace, m, target, nil, true,
			includeAllLabel(m), h.fwService); err != nil {
			// TODO: Should we roll back the target?
			log.WithError(err).Errorln("Failed to update policy in cilium.")
			if errors.Is(err, cilium.ErrPolicyNotSupported) {
				return common.ErrModelPolicyNotSupported
			}
			return common.ErrInternalErr
		}
	}
	return nil
}
