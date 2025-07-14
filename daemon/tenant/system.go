// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tenant

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/optional"
	"cylonix/sase/pkg/wslog"
	"encoding/json"
	"errors"

	"github.com/cilium/cilium/api/v1/flow"

	ulog "github.com/cylonix/utils/log"
	"github.com/sirupsen/logrus"
)

type systemHandlerImpl struct {
	logger *logrus.Entry
}

func newSystemHandlerImpl(logger *logrus.Entry) *systemHandlerImpl {
	return &systemHandlerImpl{
		logger: logger,
	}
}

// ListPathSelect lists the traffic diversion path selection resources.
func (h *systemHandlerImpl) ListPathSelect(auth interface{}, requestObject api.ListPathSelectRequestObject) (*models.PathSelectList, error) {
	token, namespace, _, logger := common.ParseToken(auth, "list-path-select", "List path select", h.logger)
	if !token.IsAdminUser {
		logger.Warnln("Non-admin user listing path select resources is not allowed.")
		return nil, common.ErrModelUnauthorized
	}

	list, err := common.GetTrafficDiversionPoints(namespace)
	if err != nil {
		logger.WithError(err).Errorln("Cannot get traffic diversion points.")
		return nil, common.ErrInternalErr
	}
	pathSelectList := []models.PathSelect{}
	for _, s := range list {
		if s != nil {
			pathSelectList = append(pathSelectList, *s)
		}
	}
	return &models.PathSelectList{
		Total: len(list),
		Items: &pathSelectList,
	}, nil
}

func (h *systemHandlerImpl) PutLogs(auth interface{}, requestObject api.PutLogsRequestObject) error {
	_, namespace, userID, logger := common.ParseToken(auth, "put-logs", "Put logs", h.logger)
	params := requestObject.Body
	if params == nil {
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	for _, logItem := range *params {
		if logItem.Source == nil || logItem.Log == nil {
			continue
		}
		log := logger.WithFields(logrus.Fields{
			ulog.Namespace: namespace,
			ulog.UserID:    userID,
			"log-source":   *logItem.Source,
		})
		switch *logItem.Source {
		case "firewall":
			item, v := &flow.Flow{}, []byte(*logItem.Log)
			if err := json.Unmarshal(v, item); err != nil {
				log.WithError(err).WithField("log", *logItem.Log).Debugln("Failed to marshal the log.")
				continue
			}
			if logItem.Namespace != nil && *logItem.Namespace != "" && namespace != *logItem.Namespace {
				log.WithField("log-namespace", *logItem.Namespace).Debugln("Wrong namespace.")
				continue
			}
			if item.L7 != nil && item.L7.Type.String() == "HTTP_TYPE" {
				wslog.Send(namespace, userID.String(), wslog.FwL7, v)
			} else {
				wslog.Send(namespace, userID.String(), wslog.FwL3, v)
			}
		case "cylonix-app":
			log.Debugln("Receive cylonix-app log. Ignored for now.")
		default:
			log.Debugln("Unknown log type. Ignored.")
		}
	}
	return nil
}

func (h *systemHandlerImpl) HealthStatus(auth interface{}, requestObject api.GetHealthStatusRequestObject) (*models.HealthStatus, error) {
	return &models.HealthStatus{
		Status: optional.BoolP(true),
	}, nil
}
