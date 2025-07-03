package common

import (
	"cylonix/sase/pkg/interfaces"

	"github.com/cylonix/utils/fabric"
	"github.com/sirupsen/logrus"
)

var (
	// Global variable for resource server handler
	resourceService    interfaces.ResourceServiceInterface
	_resourceLogger 	*logrus.Entry
)

// Startup point for the service in daemon when it is done to load ETCD resource
func onEtcdResourceReady(resource interface{}, typ string, name string, action fabric.ActionType) {
	resourceService = resource.(interfaces.ResourceServiceInterface)
	onEtcdResourceReadyForSupervisorService(action)
}

func onSupervisorResourceReady(resource interface{}, typ string, name string, action fabric.ActionType) {
	startWgService(action, _resourceLogger)
}

func StartResourceInstance(logger *logrus.Entry) interfaces.ResourceServiceInterface {
	_resourceLogger = logger
	fabric.RegisterCallback(fabric.EtcdResourceType, ".*", onEtcdResourceReady, logger)
	fabric.RegisterCallback(fabric.SupervisorServiceType, ".*", onSupervisorResourceReady, logger)
	return resourceService
}

func SetResourceInstance(resource interfaces.ResourceServiceInterface) {
	resourceService = resource
}