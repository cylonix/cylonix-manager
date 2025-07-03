package policy

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/logging/logfields"
	"errors"

	"github.com/sirupsen/logrus"
)

type policyHandler interface {
	Create(auth interface{}, requestObject api.CreatePolicyRequestObject) error
	Get(auth interface{}, requestObject api.GetPolicyRequestObject) (*models.Policy, error)
	Count(auth interface{}, requestObject api.PolicyCountRequestObject) (int64, error)
	List(auth interface{}, requestObject api.ListPolicyRequestObject) (int64, []models.Policy, error)
	Update(auth interface{}, requestObject api.UpdatePolicyRequestObject) error
	Delete(auth interface{}, requestObject api.DeletePolicyRequestObject) error
	DeleteList(auth interface{}, requestObject api.DeletePolicyListRequestObject) error
	ListTemplate(auth interface{}, requestObject api.ListPolicyTemplateRequestObject) (int64, []models.PolicyTemplate, error)
	PacFileList(auth interface{}, requestObject api.GetPacFileListRequestObject) (models.PacFileList, error)
}
type policyTargetHandler interface {
	Create(auth interface{}, requestObject api.CreatePolicyTargetRequestObject) error
	Get(auth interface{}, requestObject api.GetPolicyTargetRequestObject) (*models.PolicyTarget, error)
	List(auth interface{}, requestObject api.ListPolicyTargetRequestObject) (*models.PolicyTargetList, error)
	Update(auth interface{}, requestObject api.UpdatePolicyTargetRequestObject) error
	Delete(auth interface{}, requestObject api.DeletePolicyTargetRequestObject) error
	DeleteList(auth interface{}, requestObject api.DeletePolicyTargetListRequestObject) error
}

type policyService struct {
	fwService fwconfig.ConfigService
	logger    *logrus.Entry
	policy    policyHandler
	target    policyTargetHandler
}

// Register Implements the daemon register interface
func (s *policyService) Register(d *api.StrictServer) error {
	s.logger.Infoln("Register policy API handlers.")

	d.CreatePolicyHandler = s.createPolicy
	d.GetPolicyHandler = s.getPolicy
	d.PolicyCountHandler = s.policyCount
	d.ListPolicyHandler = s.listPolicy
	d.UpdatePolicyHandler = s.updatePolicy
	d.DeletePolicyHandler = s.deletePolicy
	d.DeletePolicyListHandler = s.deletePolicyList
	d.ListPolicyTemplateHandler = s.listTemplate
	d.GetPacFileListHandler = s.getPacFileList

	d.CreatePolicyTargetHandler = s.createTarget
	d.GetPolicyTargetHandler = s.getTarget
	d.ListPolicyTargetHandler = s.listTarget
	d.UpdatePolicyTargetHandler = s.updateTarget
	d.DeletePolicyTargetHandler = s.deleteTarget
	d.DeletePolicyTargetListHandler = s.deleteTargetList

	return nil
}

func NewService(fwService fwconfig.ConfigService, logger *logrus.Entry) *policyService {
	logger = logger.WithField(logfields.LogSubsys, "policy-handler")
	return &policyService{
		fwService: fwService,
		logger:    logger,
		policy:    newPolicyHandlerImpl(fwService, logger),
		target:    newTargetHandlerImpl(fwService, logger),
	}
}

func (s *policyService) Logger() *logrus.Entry {
	return s.logger
}

func (s *policyService) Name() string {
	return "policy api handler"
}

func (s *policyService) Start() error {
	return nil
}

func (s *policyService) Stop() {
	// no-op
}

func (s *policyService) createPolicy(ctx context.Context, requestObject api.CreatePolicyRequestObject) (api.CreatePolicyResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.policy.Create(auth, requestObject)
	if err == nil {
		return api.CreatePolicy200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.CreatePolicy500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.CreatePolicy401Response{}, nil
	}
	return api.CreatePolicy400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) getPolicy(ctx context.Context, requestObject api.GetPolicyRequestObject) (api.GetPolicyResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.policy.Get(auth, requestObject)
	if err == nil {
		return api.GetPolicy200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetPolicy500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetPolicy401Response{}, nil
	}
	return api.GetPolicy400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) listPolicy(ctx context.Context, requestObject api.ListPolicyRequestObject) (api.ListPolicyResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	total, list, err := s.policy.List(auth, requestObject)
	if err == nil {
		return api.ListPolicy200JSONResponse(models.PolicyList{
			Total: int(total),
			Items: &list,
		}), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListPolicy500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListPolicy401Response{}, nil
	}
	return api.ListPolicy400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) policyCount(ctx context.Context, requestObject api.PolicyCountRequestObject) (api.PolicyCountResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.policy.Count(auth, requestObject)
	if err == nil {
		return api.PolicyCount200JSONResponse(ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.PolicyCount500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.PolicyCount401Response{}, nil
	}
	return api.PolicyCount400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) updatePolicy(ctx context.Context, requestObject api.UpdatePolicyRequestObject) (api.UpdatePolicyResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.policy.Update(auth, requestObject)
	if err == nil {
		return api.UpdatePolicy200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdatePolicy500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdatePolicy401Response{}, nil
	}
	return api.UpdatePolicy400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) deletePolicy(ctx context.Context, requestObject api.DeletePolicyRequestObject) (api.DeletePolicyResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.policy.Delete(auth, requestObject)
	if err == nil {
		return api.DeletePolicy200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeletePolicy500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeletePolicy401Response{}, nil
	}
	return api.DeletePolicy400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) deletePolicyList(ctx context.Context, requestObject api.DeletePolicyListRequestObject) (api.DeletePolicyListResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.policy.DeleteList(auth, requestObject)
	if err == nil {
		return api.DeletePolicyList200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeletePolicyList500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeletePolicyList401Response{}, nil
	}
	return api.DeletePolicyList400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) listTemplate(ctx context.Context, requestObject api.ListPolicyTemplateRequestObject) (api.ListPolicyTemplateResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	total, list, err := s.policy.ListTemplate(auth, requestObject)
	if err == nil {
		return api.ListPolicyTemplate200JSONResponse(models.PolicyTemplateList{
			Total: int(total),
			Items: &list,
		}), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListPolicyTemplate500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListPolicyTemplate401Response{}, nil
	}
	return api.ListPolicyTemplate400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) getPacFileList(ctx context.Context, requestObject api.GetPacFileListRequestObject) (api.GetPacFileListResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	list, err := s.policy.PacFileList(auth, requestObject)
	if err == nil {
		return api.GetPacFileList200JSONResponse(list), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetPacFileList500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetPacFileList401Response{}, nil
	}
	return api.GetPacFileList400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) createTarget(ctx context.Context, requestObject api.CreatePolicyTargetRequestObject) (api.CreatePolicyTargetResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.target.Create(auth, requestObject)
	if err == nil {
		return api.CreatePolicyTarget200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.CreatePolicyTarget500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.CreatePolicyTarget401Response{}, nil
	}
	return api.CreatePolicyTarget400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) getTarget(ctx context.Context, requestObject api.GetPolicyTargetRequestObject) (api.GetPolicyTargetResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.target.Get(auth, requestObject)
	if err == nil {
		return api.GetPolicyTarget200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetPolicyTarget500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetPolicyTarget401Response{}, nil
	}
	return api.GetPolicyTarget400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) listTarget(ctx context.Context, requestObject api.ListPolicyTargetRequestObject) (api.ListPolicyTargetResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	list, err := s.target.List(auth, requestObject)
	if err == nil {
		return api.ListPolicyTarget200JSONResponse(*list), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListPolicyTarget500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListPolicyTarget401Response{}, nil
	}
	return api.ListPolicyTarget400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) updateTarget(ctx context.Context, requestObject api.UpdatePolicyTargetRequestObject) (api.UpdatePolicyTargetResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.target.Update(auth, requestObject)
	if err == nil {
		return api.UpdatePolicyTarget200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdatePolicyTarget500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdatePolicyTarget401Response{}, nil
	}
	return api.UpdatePolicyTarget400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) deleteTarget(ctx context.Context, requestObject api.DeletePolicyTargetRequestObject) (api.DeletePolicyTargetResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.target.Delete(auth, requestObject)
	if err == nil {
		return api.DeletePolicyTarget200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeletePolicyTarget500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeletePolicyTarget401Response{}, nil
	}
	return api.DeletePolicyTarget400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *policyService) deleteTargetList(ctx context.Context, requestObject api.DeletePolicyTargetListRequestObject) (api.DeletePolicyTargetListResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.target.DeleteList(auth, requestObject)
	if err == nil {
		return api.DeletePolicyTargetList200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeletePolicyTargetList500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeletePolicyTargetList401Response{}, nil
	}
	return api.DeletePolicyTargetList400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
