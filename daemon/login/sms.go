package login

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db/types"

	ulog "github.com/cylonix/utils/log"

	"github.com/sirupsen/logrus"
)

type smsLogin struct {
	namespace   string
	code        string
	phone       string
	redirectURL *string
	forSession  string
	logger      *logrus.Entry
}

func newSmsLogin(namespace, phoneNum, smsCode string, redirectURL *string, forSession string, logger *logrus.Entry) (*smsLogin, error) {
	logger = logger.WithField(ulog.Phone, phoneNum).WithField(ulog.Namespace, namespace)
	if valid, err := common.CheckSmsCode(phoneNum, smsCode); err != nil || !valid {
		if err != nil {
			logger.WithError(err).Errorln("Failed to check sms code.")
			return nil, common.ErrInternalErr
		}
		return nil, common.ErrModelInvalidSmsCode
	}
	logger = logger.WithFields(logrus.Fields{
		ulog.Code:      smsCode,
		ulog.SubHandle: "sms-login",
	})
	return &smsLogin{
		namespace:   namespace,
		code:        smsCode,
		phone:       phoneNum,
		redirectURL: redirectURL,
		forSession:  forSession,
		logger:      logger,
	}, nil
}

func (s *smsLogin) userLogin() *types.UserLogin {
	return types.NewPhoneLogin(s.namespace, s.phone, "", "")
}

func (s *smsLogin) doLogin() (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	l, approvalState, err := newLoginSession(s.namespace, s.redirectURL, s.userLogin(), s.forSession, s.logger)
	if approvalState != nil || err != nil {
		return nil, nil, approvalState, err
	}
	loginSuccess, redirect, err := l.result()
	return loginSuccess, redirect, nil, err
}

func smsCodeLogin(namespace, phone, smsCode string, redirectURL *string, forSession string, logger *logrus.Entry) (*models.LoginSuccess, *models.RedirectURLConfig, *models.ApprovalState, error) {
	smsLogin, err := newSmsLogin(namespace, phone, smsCode, redirectURL, forSession, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	return smsLogin.doLogin()
}
