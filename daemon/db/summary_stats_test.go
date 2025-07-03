package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSummaryStats(t *testing.T) {
	namespace := "test_namespace"
	nameSummary := &models.SummaryStats{}

	err := CreateOrUpdateNamespaceSummaryStat(namespace, nameSummary)
	assert.Nil(t, err)

	_, err = LastNamespaceSummaryStat(namespace)
	assert.Nil(t, err)

	userSummary := models.SummaryStats{}
	err = CreateOrUpdateUserSummaryStat(namespace, types.NilID, &userSummary)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, ErrBadParams, err)
	}

	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}
	err = CreateOrUpdateUserSummaryStat(namespace, userID, &userSummary)
	assert.Nil(t, err)

	_, err = LastUserSummaryStat(userID)
	assert.Nil(t, err)
}
