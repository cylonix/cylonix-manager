package db

// Global DB for no-namespace-specific miscellaneous KV store.

import (
	"errors"

	"github.com/cylonix/utils/etcd"
)

var (
	globalPath                       = "global"
	saseVpnObjectType                = "sase-vpn"
	saseVpnHandlerPrivateKey         = "handler-private-key"
	saseVpnHandlerNoisePrivateKey    = "handler-noise-private-key"
	ErrGlobalKeyNotExists            = errors.New("global key does not exists")
	ErrVpnHandlerPrivateKeyNotExists = errors.New("vpn handler private key not exists")
)

func SetGlobalKey(objectType, key string, value string) error {
	return etcd.Put(globalPath, objectType, key, value)
}
func DeleteGlobalKey(objectType, key string) error {
	return etcd.Delete(globalPath, objectType, key)
}
func GetGlobalKey(objectType, key string) (string, error) {
	res, err := etcd.Get(globalPath, objectType, key)
	if err != nil {
		return "", err
	}
	if len(res.Kvs) <= 0 {
		return "", ErrGlobalKeyNotExists
	}

	return string(res.Kvs[0].Value), nil
}
func UpdateGlobalKey(objectType, key string, value string) error {
	_, err := GetGlobalKey(objectType, key)
	if err != nil {
		return err
	}
	err = DeleteGlobalKey(objectType, key)
	if err != nil {
		return err
	}
	return SetGlobalKey(objectType, key, value)
}

func VpnHandlerPrivateKeyText(isNoise bool) (keyText string, err error) {
	dbKey := saseVpnHandlerPrivateKey
	if isNoise {
		dbKey = saseVpnHandlerNoisePrivateKey
	}
	keyText, err = GetGlobalKey(saseVpnObjectType, dbKey)
	if err != nil {
		if errors.Is(err, ErrGlobalKeyNotExists) {
			err = ErrVpnHandlerPrivateKeyNotExists
		}
	}
	return
}

func SetVpnHandlerPrivateKeyText(isNoise bool, keyText string) error {
	dbKey := saseVpnHandlerPrivateKey
	if isNoise {
		dbKey = saseVpnHandlerNoisePrivateKey
	}
	return SetGlobalKey(saseVpnObjectType, dbKey, keyText)
}
