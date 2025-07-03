package daemon_test

import (
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/interfaces"
	"cylonix/sase/pkg/test"

	"github.com/cylonix/supervisor"

	"github.com/sirupsen/logrus"
	gviper "github.com/spf13/viper"
)

type Emulator struct {
	FwService fwconfig.ConfigService
	Resource  interfaces.ResourceServiceInterface
}

func NewEmulator() *Emulator {
	return &Emulator{}
}

// Emulator implements the daemon interface
func (e *Emulator) AddDnsRecord(hostname, ip string) error         { return nil }
func (e *Emulator) DelDnsRecord(hostname, ip string) error         { return nil }
func (e *Emulator) AppTask() interfaces.AppSumTaskInterface        { return nil }
func (e *Emulator) DefaultMeshMode(string, *logrus.Entry) string   { return "" }
func (e *Emulator) EsClient() interfaces.EsClientInterface         { return nil }
func (e *Emulator) FwConfigService() fwconfig.ConfigService        { return e.FwService }
func (e *Emulator) GlobalConfig() interfaces.GlobalConfigInterface { return nil }
func (e *Emulator) IsExitNodeSupported(namespace string, userID types.UserID, deviceID types.DeviceID) bool {
	return false
}
func (e *Emulator) NamespaceInfo(namespace string) (*supervisor.FullNamespace, error) {
	return nil, test.ErrNotImplemented("NamespaceInfo")
}
func (e *Emulator) ResourceService() interfaces.ResourceServiceInterface { return e.Resource }
func (e *Emulator) Viper() *gviper.Viper                                 { return gviper.GetViper() }
