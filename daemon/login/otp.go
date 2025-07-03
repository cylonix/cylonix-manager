package login

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"errors"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
)

// Login with an OTP i.e. a temp token and a short one-time code.
func otpTokenLogin(token, code string, redirectURL *string, forSession string, logger *logrus.Entry) (*models.LoginSuccess, *models.RedirectURLConfig, error) {
	t := &utils.OtpToken{
		Token: token,
	}

	// Otp is deleted on check.
	valid, state, err := t.IsValid(code)
	if err != nil {
		logger.WithError(err).Errorln("Failed to check otp.")
		return nil, nil, common.ErrInternalErr
	}
	if !valid {
		// Don't log.
		return nil, nil, common.ErrModelUnauthorized
	}

	// For otp login, state is stored with auth-granter's api key.
	_, tokenData, err := utils.GetUserOrAdminTokenWithKey(state)
	if err != nil {
		if errors.Is(err, utils.ErrTokenNotExists) || errors.Is(err, utils.ErrTokenExpired) {
			return nil, nil, common.ErrModelUnauthorized
		}
		logger.WithError(err).Errorln("Failed to get auth-granter's token data.")
		return nil, nil, common.ErrInternalErr
	}
	if !tokenData.IsAdminUser || !tokenData.FromApprovedDevice {
		return nil, nil, common.ErrModelUnauthorized
	}

	newToken, err := tokenData.Clone()
	if err != nil {
		logger.WithError(err).Errorln("Failed to clone auth-granter's token.")
		return nil, nil, common.ErrInternalErr
	}

	namespace := tokenData.Namespace
	logger = logger.WithFields(logrus.Fields{
		ulog.Namespace: namespace,
		ulog.Username:  tokenData.Username,
	})

	user, err := db.GetUserFast(namespace, types.UUIDToID(newToken.UserID), true)
	if err != nil {
		logger.WithError(err).Errorln("Failed to user of the token.")
		return nil, nil, common.ErrInternalErr
	}

	var login *types.UserLogin
	if len(user.UserLogins) > 0 {
		login = &user.UserLogins[0]
	}
	l := &loginSession{
		namespace:   namespace,
		forSession:  forSession,
		tokenData:   newToken,
		user:        user,
		login:       login,
		loginType:   "otp",
		redirectURL: redirectURL,
		logger:      logger,
	}
	return l.result()
}
