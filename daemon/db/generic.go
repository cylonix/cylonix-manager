package db

// Generic DB for namespace specific miscellaneous KV store.

import (
	"encoding/json"
	"errors"

	"github.com/cylonix/utils/etcd"
)

var (
	ErrEntryNotExist = errors.New("entry does not exist")
)

func GetGenericKey(namespace, objectType, id string, result interface{}) error {
	res, err := etcd.Get(namespace, objectType, id)
	if err != nil {
		return err
	}
	if len(res.Kvs) <= 0 {
		return ErrEntryNotExist
	}

	return json.Unmarshal(res.Kvs[0].Value, result)
}

func SetGenericKey(namespace, objectType, id string, result interface{}) error {
	gJson, err := json.Marshal(result)
	if err != nil {
		return err
	}
	return etcd.Put(namespace, objectType, id, string(gJson))
}
func DeleteGenericKey(namespace, objectType, id string) error {
	return etcd.Delete(namespace, objectType, id)
}
