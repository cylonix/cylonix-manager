package resources

import (
	"cylonix/sase/pkg/optional"
	"fmt"
	"testing"

	"github.com/cylonix/wg_agent"

	"github.com/stretchr/testify/assert"
)

func TestListAccessPoint(t *testing.T) {
	testNamespace := "test_namespace"
	testIPs0 := []string{"192.168.2.0/24"}
	testIPs1 := []string{"192.168.1.0/24"}
	testIPs2 := []string{"192.168.0.0/24"}

	wg0 := "wg_0"
	wg1 := "wg_1"
	wg2 := "wg_2"

	priority0 := int32(0)
	priority1 := int32(1)
	priority2 := int32(2)

	service := ResourceService{
		wgResource: map[string]map[string]*WgNamespaceRes{
			testNamespace: {
				wg0: {
					Active:       true,
					AccessPoints: []string{"test"},
					Config: &WgConfig{
						Config: wg_agent.WgNamespace{
							AllowedIPs: testIPs0,
							Priority:   &priority0,
							IP:         optional.StringP(""),
						},
					},
				},
				wg1: {
					Active:       true,
					AccessPoints: []string{"test"},
					Config: &WgConfig{
						Config: wg_agent.WgNamespace{
							AllowedIPs: testIPs1,
							Priority:   &priority1,
							IP:         optional.StringP(""),
						},
					},
				},
				wg2: {
					Active:       true,
					AccessPoints: []string{"test"},
					Config: &WgConfig{
						Config: wg_agent.WgNamespace{
							AllowedIPs: testIPs2,
							Priority:   &priority2,
							IP:         optional.StringP(""),
						},
					},
				},
			},
		},
	}

	_, err := service.AccessPoints("fake_namespace")
	assert.NotNil(t, err)

	res, err := service.AccessPoints(testNamespace)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, 3, len(res))
	for i, v := range res {
		assert.Equal(t, fmt.Sprintf("192.168.%d.0/24", i), (*v.AllowedIps)[0])
	}
}
