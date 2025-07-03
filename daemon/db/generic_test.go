package db

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestDBGenericKey(t *testing.T) {
	notExistsEntry := "entry does not exist"
	namespace := "test_namespace"
	typ := "test_type"
	id := uuid.NewString()
	set := "set"
	get := ""

	err := SetGenericKey(namespace, typ, id, set)
	assert.Nil(t, err)

	err = GetGenericKey(namespace, typ, id, &get)
	assert.Nil(t, err)
	assert.Equal(t, set, get)

	err = DeleteGenericKey(namespace, typ, id)
	assert.Nil(t, err)

	err = GetGenericKey(namespace, typ, id, &get)
	assert.NotNil(t, err)
	assert.Equal(t, notExistsEntry, err.Error())
}
