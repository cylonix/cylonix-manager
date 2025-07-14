// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package label

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/optional"
	dbt "cylonix/sase/pkg/test/db"
	"fmt"

	"flag"
	"log"
	"os"
	"testing"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	testLogger = logrus.NewEntry(logrus.New())
)

func testSetup() error {
	utils.Init(nil)
	if err := db.InitEmulator(testing.Verbose()); err != nil {
		return err
	}
	return nil
}

func createTestLabels(namespace string, scope *types.ID, num int) ([]types.LabelID, error) {
	red := "red"
	var idList []types.LabelID
	var labelList []*types.Label
	for i := 0; i < num; i++ {
		id, err := types.NewID()
		if err != nil {
			return idList, err
		}
		idList = append(idList, id)
		name := fmt.Sprintf("label-name-00%v", i)
		label := types.Label{Model: types.Model{ID: id}, Namespace: namespace, Scope: scope, Name: name, Color: red}
		labelList = append(labelList, &label)
	}
	return idList, db.CreateLabel(labelList...)
}

func deleteTestLabels(t *testing.T, namespace string, idList []types.LabelID) {
	assert.Nil(t, db.DeleteLabels(namespace, nil, idList))
}

func TestLabel(t *testing.T) {
	namespace := "test-label-namespace"
	username := "test-label-user"
	userID, err := types.NewID()
	if !assert.Nil(t, err) {
		return
	}

	_, tokenData := dbt.CreateTokenForTest(namespace, userID, username, false, nil)
	defer tokenData.Delete()
	handler := newHandlerImpl(testLogger, &fwconfig.ServiceEmulator{})

	t.Run("create", func(t *testing.T) {
		red := "red"
		var idList []types.LabelID
		var labelList []models.Label
		defer func() {
			assert.Nil(t, db.DeleteLabels(namespace, nil, idList))
		}()
		for i := 0; i < 4; i++ {
			id, err := types.NewID()
			if !assert.Nil(t, err) {
				return
			}
			idList = append(idList, id)
			name := fmt.Sprintf("label-name-00%v", i)
			label := models.Label{ID: id.UUID(), Name: name, Color: &red}
			labelList = append(labelList, label)
		}

		createParam := api.CreateLabelsRequestObject{Body: &labelList}
		err = handler.CreateLabels(tokenData, createParam)
		assert.Nil(t, err)

		total, list, err := db.GetLabelList(&namespace, nil, nil, nil, nil, nil, nil, nil, nil, nil)
		assert.Nil(t, err)
		assert.Equal(t, int(total), 4)
		if assert.Equal(t, 4, len(list)) {
			assert.Equal(t, idList[0], list[0].ID)
		}
	})

	t.Run("list-labels", func(t *testing.T) {
		idList, err := createTestLabels(namespace, &userID, 4)
		defer deleteTestLabels(t, namespace, idList)
		if !assert.Nil(t, err) {
			return
		}
		listParams := api.ListLabelRequestObject{
			Params: models.ListLabelParams{
				Page:     optional.IntP(1),
				PageSize: optional.IntP(10),
				UserID:   optional.StringP(userID.String()),
			},
		}
		size, list, err := handler.ListLabel(tokenData, listParams)
		if assert.Nil(t, err) {
			assert.Equal(t, int64(4), size)
			if assert.Equal(t, 4, len(list)) {
				assert.Equal(t, idList[0].UUID(), list[0].ID)
			}
		}
	})

	t.Run("get", func(t *testing.T) {
		idList, err := createTestLabels(namespace, &userID, 4)
		defer deleteTestLabels(t, namespace, idList)
		if !assert.Nil(t, err) {
			return
		}

		getParam := api.GetLabelRequestObject{
			LabelID: idList[0].String(),
		}
		getLabel, err := handler.GetLabel(tokenData, getParam)
		assert.Nil(t, err)
		assert.Equal(t, idList[0].UUID(), getLabel.ID)

		getParam.LabelID = "label-id"
		_, err = handler.GetLabel(tokenData, getParam)
		assert.ErrorAs(t, err, &common.BadParamsErr{})
	})

	t.Run("update", func(t *testing.T) {
		idList, err := createTestLabels(namespace, &userID, 4)
		defer deleteTestLabels(t, namespace, idList)
		if !assert.Nil(t, err) {
			return
		}

		name := "change-label-name"
		green := "green"
		update := models.Label{Name: name, Color: &green}
		updateParams := api.UpdateLabelRequestObject{
			Body:    &update,
			LabelID: idList[2].String(),
		}
		err = handler.UpdateLabel(tokenData, updateParams)
		assert.Nil(t, err)
		label, err := db.GetLabel(namespace, nil, idList[2])
		assert.Nil(t, err)
		if assert.NotNil(t, label) {
			assert.Equal(t, name, label.Name)
			assert.Equal(t, green, label.Color)
		}
	})

	t.Run("batch-update", func(t *testing.T) {
		idList, err := createTestLabels(namespace, &userID, 4)
		defer deleteTestLabels(t, namespace, idList)
		if !assert.Nil(t, err) {
			return
		}

		green := "green"
		update := models.Label{Color: &green}
		updateLabelsParam := api.UpdateLabelsRequestObject{
			Body: &models.UpdateLabelsJSONRequestBody{
				Update: &update,
				IDList: &[]uuid.UUID{idList[1].UUID(), idList[2].UUID()},
			},
		}

		err = handler.UpdateLabels(tokenData, updateLabelsParam)
		assert.Nil(t, err)
		label, err := db.GetLabel(namespace, nil, idList[2])
		assert.Nil(t, err)
		if assert.NotNil(t, label) {
			assert.Equal(t, green, label.Color)
		}
	})

	t.Run("delete", func(t *testing.T) {
		idList, err := createTestLabels(namespace, &userID, 10)
		defer deleteTestLabels(t, namespace, idList)
		if !assert.Nil(t, err) {
			return
		}

		deleteParams := api.DeleteLabelRequestObject{
			LabelID: idList[3].String(),
		}
		err = handler.DeleteLabel(tokenData, deleteParams)
		assert.Nil(t, err)
		_, err = db.GetLabel(namespace, nil, idList[3])
		assert.ErrorIs(t, err, db.ErrLabelNotExists)

		// Delete again is not an error.
		err = handler.DeleteLabel(tokenData, deleteParams)
		assert.Nil(t, err)

		// Bad id that can't be parsed.
		deleteParams.LabelID = "delete-label-bad-id"
		err = handler.DeleteLabel(tokenData, deleteParams)
		assert.ErrorAs(t, err, &common.BadParamsErr{})
	})
	t.Run("batch-delete", func(t *testing.T) {
		idList, err := createTestLabels(namespace, &userID, 20)
		defer deleteTestLabels(t, namespace, idList)
		if !assert.Nil(t, err) {
			return
		}

		deleteLabelsParam := api.DeleteLabelsRequestObject{
			Body: &[]uuid.UUID{idList[6].UUID(), idList[19].UUID(), idList[7].UUID()},
		}

		err = handler.DeleteLabels(tokenData, deleteLabelsParam)
		assert.Nil(t, err)

		_, err = db.GetLabel(namespace, nil, idList[6])
		assert.ErrorIs(t, err, db.ErrLabelNotExists)

		_, err = db.GetLabel(namespace, nil, idList[7])
		assert.ErrorIs(t, err, db.ErrLabelNotExists)

		_, err = db.GetLabel(namespace, nil, idList[19])
		assert.ErrorIs(t, err, db.ErrLabelNotExists)

		// Delete again is not an error
		err = handler.DeleteLabels(tokenData, deleteLabelsParam)
		assert.Nil(t, err)
	})
}

func testCleanup() {
	db.CleanupEmulator()
}
func TestMain(m *testing.M) {
	flag.Parse()
	if err := testSetup(); err != nil {
		log.Fatalf("Failed to setup test: %v.", err)
	}
	code := m.Run()
	testCleanup()
	os.Exit(code)
}
