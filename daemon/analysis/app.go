package analysis

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/interfaces"

	"github.com/sirupsen/logrus"
)

type appHandlerImpl struct {
	daemon interfaces.DaemonInterface
	logger *logrus.Entry
}

func newAppHandlerImpl(daemon interfaces.DaemonInterface, logger *logrus.Entry) *appHandlerImpl {
	return &appHandlerImpl{
		daemon: daemon,
		logger: logger,
	}
}

func (h *appHandlerImpl) ListEvent(auth interface{}, params api.ListAppEventRequestObject) (*models.AppAccessEventList, error) {
	token, _, _, logger := common.ParseToken(auth, "list-event", "List event", h.logger)
	if !token.IsAdminUser {
		logger.Warnln("Non-admin user has no access for app events for now.")
		return nil, common.ErrModelUnauthorized
	}
	// TODO: events collection is not yet implemented.
	return nil, common.ErrInternalErr
}

func (h *appHandlerImpl) TopCategories(auth interface{}, params api.TopCategoriesRequestObject) ([]models.AppStats, error) {
	token, namespace, _, logger := common.ParseToken(auth, "top-categories", "Top categories", h.logger)
	if !token.IsAdminUser {
		logger.Warnln("Non-admin user has no access for top categories for now.")
		return nil, common.ErrModelUnauthorized
	}
	appTask := h.daemon.AppTask()
	if appTask == nil {
		logger.Warnln("App task is not setup.")
		return nil, common.ErrInternalErr
	}
	return appTask.TopCategories(namespace), nil
}

func (h *appHandlerImpl) TopClouds(auth interface{}, params api.TopCloudsRequestObject) ([]models.AppCloud, error) {
	token, namespace, _, logger := common.ParseToken(auth, "top-clouds", "Top clouds", h.logger)
	if !token.IsAdminUser {
		logger.Warnln("Non-admin user has no access for top clouds for now.")
		return nil, common.ErrModelUnauthorized
	}
	appTask := h.daemon.AppTask()
	if appTask == nil {
		logger.Warnln("App task is not setup.")
		return nil, common.ErrInternalErr
	}
	return appTask.TopClouds(namespace), nil
}

func (h *appHandlerImpl) TopDomains(auth interface{}, params api.TopDomainsRequestObject) ([]models.AppStats, error) {
	token, namespace, _, logger := common.ParseToken(auth, "top-domains", "Top domains", h.logger)
	if !token.IsAdminUser {
		logger.Warnln("Non-admin user has no access for top domains for now.")
		return nil, common.ErrModelUnauthorized
	}
	appTask := h.daemon.AppTask()
	if appTask == nil {
		logger.Warnln("App task is not setup.")
		return nil, common.ErrInternalErr
	}
	return appTask.TopDomains(namespace), nil
}

func (h *appHandlerImpl) TopFlows(auth interface{}, params api.TopFlowsRequestObject) (*models.TopUserFlows, error) {
	token, namespace, _, logger := common.ParseToken(auth, "top-flows", "Top flows", h.logger)
	if !token.IsAdminUser {
		logger.Warnln("Non-admin user has no access for top flows for now.")
		return nil, common.ErrModelUnauthorized
	}
	appTask := h.daemon.AppTask()
	if appTask == nil {
		logger.Warnln("App task is not setup.")
		return nil, common.ErrInternalErr
	}
	return appTask.TopFlows(namespace), nil
}
