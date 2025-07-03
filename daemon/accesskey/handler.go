package accesskey

import (
	"context"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/logging/logfields"
	"errors"

	api "cylonix/sase/api/v2"

	"github.com/sirupsen/logrus"
)

type serviceHandler interface {
	Get(auth interface{}, accessKeyID string) (*models.AccessKey, error)
	List(auth interface{}, params models.ListAccessKeyParams) (int, *[]models.AccessKey, error)
	Create(auth interface{}, accessKey *models.AccessKey) (*models.AccessKey, error)
	Delete(auth interface{}, accessKeyID string) error
}

type AccessKeyService struct {
	logger  *logrus.Entry
	handler serviceHandler
}

func (s *AccessKeyService) Register(d *api.StrictServer) error {
	s.logger.Infoln("Registering the access key API handlers.")
	d.GetAccessKeyHandler = s.get
	d.ListAccessKeyHandler = s.list
	d.CreateAccessKeyHandler = s.create
	d.DeleteAccessKeyHandler = s.delete
	return nil
}

func NewService(logger *logrus.Entry) *AccessKeyService {
	logger = logger.WithField(logfields.LogSubsys, "access-key-handler")
	return &AccessKeyService{
		handler: newHandlerImpl(logger),
		logger:  logger,
	}
}

func (s *AccessKeyService) Logger() *logrus.Entry {
	return s.logger
}

func (s *AccessKeyService) Name() string {
	return "access api handler"
}

func (s *AccessKeyService) Start() error {
	return nil
}

func (s *AccessKeyService) Stop() {
	// no-op
}

func (s *AccessKeyService) list(ctx context.Context, request api.ListAccessKeyRequestObject) (api.ListAccessKeyResponseObject, error) {
	params := request.Params
	auth := ctx.Value(api.SecurityAuthContextKey)
	total, list, err := s.handler.List(auth, params)
	if err == nil {
		return api.ListAccessKey200JSONResponse{
			Total: total,
			Items: list,
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListAccessKey500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListAccessKey401Response{}, nil
	}
	return api.ListAccessKey400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *AccessKeyService) get(ctx context.Context, request api.GetAccessKeyRequestObject) (api.GetAccessKeyResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.handler.Get(auth, request.AccessKeyID)
	if err == nil {
		return api.GetAccessKey200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetAccessKey500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetAccessKey401Response{}, nil
	}
	return api.GetAccessKey400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *AccessKeyService) create(ctx context.Context, request api.CreateAccessKeyRequestObject) (api.CreateAccessKeyResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.handler.Create(auth, request.Body)
	if err == nil {
		return api.CreateAccessKey200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.CreateAccessKey500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.CreateAccessKey401Response{}, nil
	}
	return api.CreateAccessKey400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *AccessKeyService) delete(ctx context.Context, request api.DeleteAccessKeyRequestObject) (api.DeleteAccessKeyResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.Delete(auth, request.AccessKeyID)
	if err == nil {
		return api.DeleteAccessKey200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteAccessKey500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteAccessKey401Response{}, nil
	}
	return api.DeleteAccessKey400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
