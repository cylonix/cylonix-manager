package device

// Device handlers handle the api request for the device(s) of a tenant
// (namespace) of the sase network.

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/fwconfig"
	ulog "cylonix/sase/pkg/logging/logfields"
	"errors"

	"github.com/sirupsen/logrus"
)

type serviceHandler interface {
	GetDevices(auth interface{}, requestObject api.GetDevicesRequestObject) (*models.DeviceList, error)
	PutDevice(auth interface{}, requestObject api.PutDeviceRequestObject) error
	PostDevice(auth interface{}, requestObject api.PostDeviceRequestObject) error
	DeleteDevices(auth interface{}, requestObject api.DeleteDevicesRequestObject) error
	GetApprovalRecords(auth interface{}, requestObject api.ListDeviceApprovalRecordsRequestObject) (int, []models.DeviceApprovalRecord, error)
	ApproveDevices(auth interface{}, requestObject api.ApproveDevicesRequestObject) error
	DeleteApprovalRecords(auth interface{}, requestObject api.DeleteDeviceApprovalRecordsRequestObject) error
}

type DeviceService struct {
	fwService fwconfig.ConfigService
	handler   serviceHandler
	logger    *logrus.Entry
}

// Register Implements the daemon register interface
func (s *DeviceService) Register(d *api.StrictServer) error {
	s.logger.Infoln("Register device API handlers.")

	d.DeleteDevicesHandler = s.deleteDevices
	d.GetDevicesHandler = s.getDevices
	d.PostDeviceHandler = s.postDevice
	d.PutDeviceHandler = s.putDevice
	d.ListDeviceApprovalRecordsHandler = s.getApprovalRecords
	d.ApproveDevicesHandler = s.approveDevices
	d.DeleteDeviceApprovalRecordsHandler = s.deleteApprovalRecords

	return nil
}

func NewService(fwService fwconfig.ConfigService, logger *logrus.Entry) *DeviceService {
	logger = logger.WithField(ulog.LogSubsys, "device-handler")
	return &DeviceService{
		fwService: fwService,
		handler:   newHandlerImpl(fwService, logger),
		logger:    logger,
	}
}

func (s *DeviceService) Logger() *logrus.Entry {
	return s.logger
}

func (s *DeviceService) Name() string {
	return "device api handler"
}

func (s *DeviceService) Start() error {
	return nil
}

func (s *DeviceService) Stop() {
	// no-op
}

func (s *DeviceService) getDevices(ctx context.Context, requestObject api.GetDevicesRequestObject) (api.GetDevicesResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.handler.GetDevices(auth, requestObject)
	if err == nil {
		return api.GetDevices200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetDevices500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetDevices401Response{}, nil
	}
	return api.GetDevices400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *DeviceService) putDevice(ctx context.Context, requestObject api.PutDeviceRequestObject) (api.PutDeviceResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.PutDevice(auth, requestObject)
	if err == nil {
		return api.PutDevice200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.PutDevice500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.PutDevice401Response{}, nil
	}
	return api.PutDevice400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *DeviceService) postDevice(ctx context.Context, requestObject api.PostDeviceRequestObject) (api.PostDeviceResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.PostDevice(auth, requestObject)
	if err == nil {
		return api.PostDevice200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.PostDevice500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.PostDevice401Response{}, nil
	}
	return api.PostDevice400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *DeviceService) deleteDevices(ctx context.Context, requestObject api.DeleteDevicesRequestObject) (api.DeleteDevicesResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.DeleteDevices(auth, requestObject)
	if err == nil {
		return api.DeleteDevices200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteDevices500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteDevices401Response{}, nil
	}
	return api.DeleteDevices400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *DeviceService) deleteApprovalRecords(ctx context.Context, requestObject api.DeleteDeviceApprovalRecordsRequestObject) (api.DeleteDeviceApprovalRecordsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.DeleteApprovalRecords(auth, requestObject)
	if err == nil {
		return api.DeleteDeviceApprovalRecords200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteDeviceApprovalRecords500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteDeviceApprovalRecords401Response{}, nil
	}
	return api.DeleteDeviceApprovalRecords400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *DeviceService) getApprovalRecords(ctx context.Context, requestObject api.ListDeviceApprovalRecordsRequestObject) (api.ListDeviceApprovalRecordsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	total, list, err := s.handler.GetApprovalRecords(auth, requestObject)
	if err == nil {
		return api.ListDeviceApprovalRecords200JSONResponse{
			Total:   total,
			Records: &list,
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListDeviceApprovalRecords500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListDeviceApprovalRecords401Response{}, nil
	}
	return api.ListDeviceApprovalRecords400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *DeviceService) approveDevices(ctx context.Context, requestObject api.ApproveDevicesRequestObject) (api.ApproveDevicesResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.ApproveDevices(auth, requestObject)
	if err == nil {
		return api.ApproveDevices200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ApproveDevices500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ApproveDevices401Response{}, nil
	}
	return api.ApproveDevices400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
