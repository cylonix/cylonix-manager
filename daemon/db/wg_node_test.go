package db

import (
	"cylonix/sase/daemon/db/types"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUpdateWgNode(t *testing.T) {
	node := &types.WgNode{
		AllowedIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
	}
	if !assert.Nil(t, CreateWgNode(node)) {
		return
	}
	node.AllowedIPs = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}
	if assert.Nil(t, UpdateWgNode(node.ID, node)) {
		v, err := GetWgNodeByID(node.ID)
		if assert.Nil(t, err) {
			assert.Equal(t, v.AllowedIPs, node.AllowedIPs)
		}
	}
}