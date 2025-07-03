package analysis

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"

	"github.com/sirupsen/logrus"
)

type topoHandlerImpl struct {
	logger *logrus.Entry
}

func newTopoHandlerImpl(logger *logrus.Entry) *topoHandlerImpl {
	return &topoHandlerImpl{
		logger: logger,
	}
}

func (h *topoHandlerImpl) NetworkTopo(auth interface{}, requestObject api.NetworkTopoRequestObject) ([]models.NetworkTopo, error) {
	token, namespace, _, logger := common.ParseToken(auth, "network-topo", "Network topo", h.logger)

	// Only support listing from admin user for now.
	if !token.IsAdminUser {
		logger.Warnln("Non-admin user listing network topology.")
		return nil, common.ErrModelUnauthorized
	}

	list, err := common.PopNetworkTopo(namespace)
	if err != nil {
		logger.WithError(err).Errorln("Failed to list pop network topology.")
		return nil, common.ErrInternalErr
	}
	return list, nil
}
