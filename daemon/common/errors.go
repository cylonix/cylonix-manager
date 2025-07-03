package common

import (
	"cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"errors"
)

var (
	// Please keep alphabetical order
	ErrInternalErr                        = errors.New("internal error")
	ErrModelAuthenticationFailed          = errors.New(string(models.BadRequestErrorCodeErrAuthenticationFailed))
	ErrModelBadParameters                 = errors.New(string(models.BadRequestErrorCodeErrBadParams))
	ErrModelBadUserInfo                   = errors.New(string(models.BadRequestErrorCodeErrBadUserInfo))
	ErrModelCompanyConfigurationNotExists = errors.New(string(models.BadRequestErrorCodeErrCompanyConfigurationNotExists))
	ErrModelCompanyExists                 = errors.New(string(models.BadRequestErrorCodeErrCompanyExists))
	ErrModelCompanyNameNotAvailable       = errors.New(string(models.BadRequestErrorCodeErrCompanyNameNotAvailable))
	ErrModelCompanyNamespaceNotAvailable  = errors.New(string(models.BadRequestErrorCodeErrCompanyNamespaceNotAvailable))
	ErrModelCompanyNotExists              = errors.New(string(models.BadRequestErrorCodeErrCompanyNotExists))
	ErrModelCompanyRegistrationExists     = errors.New(string(models.BadRequestErrorCodeErrCompanyRegistrationExists))
	ErrModelCompanyRegistrationNotExists  = errors.New(string(models.BadRequestErrorCodeErrCompanyRegistrationNotExists))
	ErrModelDeviceNotExists               = errors.New(string(models.BadRequestErrorCodeErrDeviceNotExists))
	ErrModelEmailExists                   = errors.New(string(models.BadRequestErrorCodeErrEmailExists))
	ErrModelEmailInvalid                  = errors.New(string(models.BadRequestErrorCodeErrEmailInvalid))
	ErrModelFriendRequestExists           = errors.New(string(models.BadRequestErrorCodeErrFriendRequestExists))
	ErrModelFriendRequestNotExists        = errors.New(string(models.BadRequestErrorCodeErrFriendRequestNotExists))
	ErrModelInvalidPasswordHistory        = errors.New(string(models.BadRequestErrorCodeErrInvalidPasswordHistory))
	ErrModelInvalidSmsCode                = errors.New(string(models.BadRequestErrorCodeErrInvalidSmsCode))
	ErrModelLabelNotExists                = errors.New(string(models.BadRequestErrorCodeErrLabelNotExists))
	ErrModelMeetingConfigInvalid          = errors.New(string(models.BadRequestErrorCodeErrMeetingConfigInvalid))
	ErrModelMeetingExists                 = errors.New(string(models.BadRequestErrorCodeErrMeetingExists))
	ErrModelMeetingHostCodeNotExists      = errors.New(string(models.BadRequestErrorCodeErrMeetingHostCodeNotExists))
	ErrModelMeetingNotExists              = errors.New(string(models.BadRequestErrorCodeErrMeetingNotExists))
	ErrModelMeetingPasswordInvalid        = errors.New(string(models.BadRequestErrorCodeErrMeetingPasswordInvalid))
	ErrModelNotAdminUser                  = errors.New(string(models.BadRequestErrorCodeErrNotAdminUser))
	ErrModelOneTimeCodeInvalid            = errors.New(string(models.BadRequestErrorCodeErrOneTimeCodeInvalid))
	ErrModelOperationNotAuthorized        = errors.New(string(models.BadRequestErrorCodeErrOperationNotAuthorized))
	ErrModelOperationNotSupported         = errors.New(string(models.BadRequestErrorCodeErrOperationNotSupported))
	ErrModelPasswordPolicyNotMet          = errors.New(string(models.BadRequestErrorCodeErrPasswordPolicyNotMet))
	ErrModelPhoneInvalid                  = errors.New(string(models.BadRequestErrorCodeErrPhoneInvalid))
	ErrModelPhoneNotRegistered            = errors.New(string(models.BadRequestErrorCodeErrPhoneUnregistered))
	ErrModelPhoneRegistered               = errors.New(string(models.BadRequestErrorCodeErrPhoneRegistered))
	ErrModelPhoneRegisterNotFinished      = errors.New(string(models.BadRequestErrorCodeErrPhoneUnfinished))
	ErrModelPhoneNotApproved              = errors.New(string(models.BadRequestErrorCodeErrPhoneNotApproved))
	ErrModelPolicyExists                  = errors.New(string(models.BadRequestErrorCodeErrPolicyExists))
	ErrModelPolicyNotExists               = errors.New(string(models.BadRequestErrorCodeErrPolicyNotExists))
	ErrModelPolicyNotSupported            = errors.New(string(models.BadRequestErrorCodeErrPolicyNotSupported))
	ErrModelPolicyTargetExists            = errors.New(string(models.BadRequestErrorCodeErrPolicyTargetExists))
	ErrModelPolicyTargetInUse             = errors.New(string(models.BadRequestErrorCodeErrPolicyTargetInUse))
	ErrModelPolicyTargetNotExists         = errors.New(string(models.BadRequestErrorCodeErrPolicyTargetNotExists))
	ErrModelQrCodeExpired                 = errors.New(string(models.BadRequestErrorCodeErrQrCodeExpired))
	ErrModelQrCodeNotConfirmed            = errors.New(string(models.BadRequestErrorCodeErrQrCodeNotConfirmed))
	ErrModelQrCodeNotScanned              = errors.New(string(models.BadRequestErrorCodeErrQrCodeNotScanned))
	ErrModelSamePassword                  = errors.New(string(models.BadRequestErrorCodeErrSamePassword))
	ErrModelSameUsername                  = errors.New(string(models.BadRequestErrorCodeErrSameUsername))
	ErrModelTokenInvalid                  = errors.New(string(models.BadRequestErrorCodeErrTokenInvalid))
	ErrModelUnauthorized                  = errors.New(string(models.BadRequestErrorCodeErrUnauthorized))
	ErrModelUpdateInfoFailed              = errors.New(string(models.BadRequestErrorCodeErrUpdateInfoFailed))
	ErrModelUserBoundAlready              = errors.New(string(models.BadRequestErrorCodeErrUserBoundAlready))
	ErrModelUserExists                    = errors.New(string(models.BadRequestErrorCodeErrUserExists))
	ErrModelUserNotExists                 = errors.New(string(models.BadRequestErrorCodeErrUserNotExists))
	ErrModelUserLoginExists               = errors.New(string(models.BadRequestErrorCodeErrUserLoginExists))
	ErrModelUsernameInvalid               = errors.New(string(models.BadRequestErrorCodeErrUsernameInvalid))
	ErrModelEmailRegistered               = errors.New(string(models.BadRequestErrorCodeErrEmailRegistered))
	ErrModelGmailRegistered               = errors.New(string(models.BadRequestErrorCodeErrGmailRegistered))
	ErrModelUserRegistered                = errors.New(string(models.BadRequestErrorCodeErrUserRegistered))
	ErrModelUsernameRegistered            = errors.New(string(models.BadRequestErrorCodeErrUsernameRegistered))
	ErrModelWechatNotBinding              = errors.New(string(models.BadRequestErrorCodeErrWechatNotBinding))
	ErrModelWeChatRegistered              = errors.New(string(models.BadRequestErrorCodeErrWechatRegistered))
	ErrResourceServiceInvalid             = errors.New("resourceService service is invalid")
)

func NewBadRequestErrorCode(err error) *models.BadRequestErrorCode {
	errCode := models.BadRequestErrorCode(err.Error())
	return &errCode
}

func NewBadRequestJSONResponse(err error) api.BadRequestJSONResponse {
	if e, ok := err.(CodedError); ok {
		code := models.BadRequestErrorCode(e.Code())
		msg := e.Error()
		return api.BadRequestJSONResponse{
			ErrorCode: &code,
			ErrorMessage: &msg,
		}
	}
	return api.BadRequestJSONResponse{
		ErrorCode: NewBadRequestErrorCode(err),
	}
}

type CodedError interface {
	error
	Code() string
}

type BadParamsErr struct {
	err error
}

func (e BadParamsErr) Error() string {
	return e.err.Error()
}
func (e BadParamsErr) Code() string {
	return string(models.BadRequestErrorCodeErrBadParams)
}

func NewBadParamsErr(err error) BadParamsErr {
	return BadParamsErr{err: err}
}