package common

import (
	"cylonix/sase/daemon/db/types"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
)

var longDashes = "===================="

func LogWithLongDashes(msg string, logger *logrus.Entry) {
	logger.Infoln(longDashes, msg, longDashes)
}

func ParseToken(auth interface{}, caller, description string, inLogger *logrus.Entry) (token *utils.UserTokenData, namespace string, userID types.UserID, logger *logrus.Entry) {
	logger = inLogger.WithFields(logrus.Fields{
		ulog.Handle: caller,
	})
	if auth != nil {
		ok := false
		if token, ok = auth.(*utils.UserTokenData); ok {
			if token.Token == "" {
				token = nil
			} else {
				namespace = token.Namespace
				userID = types.UUIDToID(token.UserID)
				username := token.Username
				logger = logger.WithFields(logrus.Fields{
					ulog.Namespace: namespace,
					ulog.Username:  username,
					ulog.UserID:    userID.String(),
				})
			}
		}
	}

	LogWithLongDashes(description, logger)
	return
}
