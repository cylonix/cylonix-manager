package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDBGlobalKey(t *testing.T) {
	_, err := VpnHandlerPrivateKeyText(false)
	assert.NotNil(t, err)
	assert.Equal(t, err, ErrVpnHandlerPrivateKeyNotExists)

	testKey := "test_vpn_key"
	err = SetVpnHandlerPrivateKeyText(false, testKey)
	assert.Nil(t, err)

	key, err := VpnHandlerPrivateKeyText(false)
	assert.Nil(t, err)
	assert.Equal(t, key, testKey)
}
