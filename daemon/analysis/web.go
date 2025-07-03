package analysis

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/pkg/interfaces"
	"slices"

	"github.com/cylonix/utils/paging"
	"github.com/sirupsen/logrus"
)

type webHandlerImpl struct {
	daemon interfaces.DaemonInterface
	logger *logrus.Entry
}

func newWebHandlerImpl(daemon interfaces.DaemonInterface, logger *logrus.Entry) *webHandlerImpl {
	return &webHandlerImpl{
		daemon: daemon,
		logger: logger,
	}
}

// ListCategory list all the web URLs (in FQDN) visited from all the Tai's.
// TODO: Collect the category stats to prometheus periodically instead.
func (h *webHandlerImpl) ListCategory(auth interface{}, requestObject api.ListWebCategoryRequestObject) (*models.WebCategoryList, error) {
	token, namespace, _, logger := common.ParseToken(auth, "list-web-category", "List web category", h.logger)
	// Only support admin access for now. Add user access once Tai stats is
	// collected per-device.
	if token == nil {
		return nil, common.ErrModelUnauthorized
	}
	if !token.IsAdminUser {
		logger.Warnln("Non-admin access is not allowed for now.")
		return nil, common.ErrModelUnauthorized
	}
	params := requestObject.Params
	var list []string
	for _, t := range h.daemon.FwConfigService().List(namespace, false) {
		names, err := t.ListWebCategory(namespace)
		if err != nil {
			logger.WithError(err).Warnln("Failed to list web categories.")
			// Could be one of the agent not responding. Skip and continue.
			continue
		}
		list = append(list, names...)
	}
	slices.Sort(list)
	list = slices.Compact(list)
	total := len(list)
	start, stop := paging.StartStop(params.Page, params.PageSize, total)
	var items []models.WebCategory
	for _, v := range list[start:stop] {
		name := v
		items = append(items, models.WebCategory{
			Name: name,
		})
	}
	return &models.WebCategoryList{
		Total: total,
		Items: &items,
	}, nil
}
