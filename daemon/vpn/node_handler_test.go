package vpn

import (
	"cylonix/sase/pkg/fwconfig"
	dt "cylonix/sase/pkg/test/daemon"
	vpnpkg "cylonix/sase/pkg/vpn"
	"testing"

	hstypes "github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
)

func TestNodeHandlers(t *testing.T) {
	var (
		d  = dt.NewEmulator()
		f  = fwconfig.NewServiceEmulator()
		s  = NewService(d, f, testLogger)
		nh = NewNodeHandler(s)

		namespace = testNamespace
		userID    = testUserID
		userInfo  = &vpnpkg.UserInfo{Namespace: namespace, UserID: userID}
	)
	nodeUser, err := userInfo.NodeUser()
	if !assert.Nil(t, err) {
		return
	}
	t.Run("Profiles", func(t *testing.T) {
		node := hstypes.Node{
			User: *nodeUser,
		}
		list, err := nh.Profiles([]*hstypes.Node{&node})
		assert.Nil(t, err)
		if assert.Equal(t, 1, len(list)) {
			assert.Equal(t, testUsername, list[0].LoginName)
		}
	})
	t.Run("UserLogin", func(t *testing.T) {
		login := nh.UserLogin(nodeUser)
		if assert.NotNil(t, login) {
			assert.Equal(t, testUsername, login.LoginName)
		}
	})
	t.Run("UserProfile", func(t *testing.T) {
		profile := nh.UserProfile(nodeUser)
		if assert.NotNil(t, profile) {
			assert.Equal(t, testUsername, profile.DisplayName)
		}
	})
}
