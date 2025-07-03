package interfaces

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"

	"github.com/cylonix/supervisor"
	"github.com/sirupsen/logrus"
	gviper "github.com/spf13/viper"
)

type DaemonInterface interface {
	AddDnsRecord(hostname, ip string) error
	DelDnsRecord(hostname, ip string) error
	AppTask() AppSumTaskInterface
	DefaultMeshMode(string, *logrus.Entry) string
	EsClient() EsClientInterface
	FwConfigService() fwconfig.ConfigService
	GlobalConfig() GlobalConfigInterface
	IsExitNodeSupported(namespace string, userID types.UserID, deviceID types.DeviceID) bool
	NamespaceInfo(namespace string) (*supervisor.FullNamespace, error)
	ResourceService() ResourceServiceInterface
	Viper() *gviper.Viper
}
