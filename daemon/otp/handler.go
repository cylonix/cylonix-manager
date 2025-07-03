package otp

// OTP handlers handle the api request for the OTP operations.

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/logging/logfields"
	"errors"

	"github.com/sirupsen/logrus"
)

type serviceHandler interface {
	SendCode(api.SendCodeRequestObject) (bool, *models.OneTimeCodeSendResult, error)
	Verify(api.VerifyCodeRequestObject) (*models.ApprovalState, error)
}

type OTPService struct {
	handler serviceHandler
	logger  *logrus.Entry
}

// Register Implements the daemon register interface
func (s *OTPService) Register(d *api.StrictServer) error {
	s.logger.Infoln("Register OTP API handlers.")

	d.SendCodeHandler = s.sendCode
	d.VerifyCodeHandler = s.verify
	return nil
}

func NewService(logger *logrus.Entry) *OTPService {
	logger = logger.WithField(logfields.LogSubsys, "phone-handler")
	return &OTPService{
		handler: newHandlerImpl(logger),
		logger:  logger,
	}
}

func (s *OTPService) Logger() *logrus.Entry {
	return s.logger
}

func (s *OTPService) Name() string {
	return "OTP api handler"
}

func (s *OTPService) Start() error {
	return nil
}

func (s *OTPService) Stop() {
	// no-op
}

func (s *OTPService) sendCode(ctx context.Context, requestObject api.SendCodeRequestObject) (api.SendCodeResponseObject, error) {
	sent, result, err := s.handler.SendCode(requestObject)
	if err == nil {
		if sent {
			return api.SendCode200JSONResponse(*result), nil
		}
		return api.SendCode202JSONResponse(*result), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.SendCode500JSONResponse{}, nil
	}
	return api.SendCode400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *OTPService) verify(ctx context.Context, requestObject api.VerifyCodeRequestObject) (api.VerifyCodeResponseObject, error) {
	ret, err := s.handler.Verify(requestObject)
	if err == nil {
		if ret != nil {
			return api.VerifyCode200TextResponse(*ret), nil
		}
		return api.VerifyCode200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.VerifyCode500JSONResponse{}, nil
	}
	return api.VerifyCode400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
