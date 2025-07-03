package interfaces

import (
	"cylonix/sase/api/v2/models"

	"github.com/cylonix/wg_agent"
	"github.com/sirupsen/logrus"

	"github.com/cylonix/supervisor"

	"tailscale.com/tailcfg"
)

type DerperServers struct {
	Namespace string
	Servers   map[int]*tailcfg.DERPRegion
}
type ResourceServiceInterface interface {
	AllowedIPs(string, string) (*[]string, error)
	AccessPoints(string) (models.AccessPointList, error)
	NamespaceList() ([]*supervisor.FullNamespace, error)
	PopNameForWg(namespace, wgName string) (string, error)
	RelayServers(string) (*DerperServers, error)
	Run() error
	SetLogLevel(logrus.Level)
	SubnetRouterDeviceID(namespace, wgName string) (string, error)
	WgAccessPoints(string, string) ([]string, error)
	WgNameByDeviceID(namespace, deviceID string) (string, error)
	WgResourceDetail(namespace, wgName string) (*wg_agent.WgNamespaceDetail, error)
}
