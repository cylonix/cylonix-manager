package db

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/db/types"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAlarm(t *testing.T) {
	namespace := "test_namespace"
	testUsername := "test-username"
	userIDs, usernames := make([]types.UserID, 10), make([]string, 10)
	deviceIDs, alarmIDs := make([]types.DeviceID, 10), make([]types.ID, 10)
	for i := 0; i < 10; i++ {
		id, err := types.NewID()
		if !assert.Nil(t, err) {
			return
		}
		deviceIDs[i] = id
		id, err = types.NewID()
		if !assert.Nil(t, err) {
			return
		}
		userIDs[i] = id
		usernames[i] = fmt.Sprintf("%v-%v", testUsername, i)
		level := models.NoticeLevelCritical
		if i == 0 {
			level = models.NoticeLevelInfo
		}
		typ := models.NoticeTypeAlarm
		a, err := AddAlarm(namespace, &models.Notice{
			DeviceID: deviceIDs[i].UUIDP(),
			Level:    &level,
			Type:     typ,
			UserID:   userIDs[i].UUIDP(),
			Username: &usernames[i],
			State:    models.NoticeStateUnread,
		})
		if !assert.Nil(t, err) || !assert.NotNil(t, a) {
			t.Fatalf("Failed to add new alarm: %v", err)
		}
		alarmIDs[i] = a.ID
	}
	defer func() { assert.Nil(t, DeleteAlarms(&namespace, nil, nil, nil, alarmIDs)) }()

	list, err := GetAlarmList(&namespace, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		assert.Equal(t, 10, list.Total)
	}

	list, err = GetAlarmList(&namespace, nil, &userIDs[0], nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		if assert.Equal(t, 1, list.Total) {
			assert.Equal(t, models.NoticeStateUnread, (*list.List)[0].State)
		}
	}

	level := models.NoticeLevelInfo
	list, err = GetAlarmList(&namespace, nil, nil, &level, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		if assert.Equal(t, 1, list.Total) && assert.NotNil(t, list.List) {
			assert.Equal(t, models.NoticeStateUnread, (*list.List)[0].State)
		}
	}

	sortBy, sortDesc := "user_id", "desc"
	page, pageSize := 2, 5
	list, err = getAlarmList(&namespace, nil, nil, nil, nil, nil, nil, &page, &pageSize, &sortBy, &sortDesc, nil)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		if assert.Equal(t, 10, list.Total) && assert.NotNil(t, list.List) {
			if assert.Equal(t, 5, len(*list.List)) && assert.NotNil(t, (*list.List)[4].UserID) {
				if !assert.Equal(t, userIDs[0].UUID(), *((*list.List)[4].UserID)) {
					for _, id := range userIDs {
						t.Logf("UserID: %v", id.UUID())
					}
					for _, alarm := range *list.List {
						t.Logf("Alarm: %v, UserID: %v", alarm.ID, alarm.UserID)
					}
				}
			}
		}
	}

	err = UpdateAlarmState(namespace, nil, alarmIDs[3:5], types.NilID, "", "test", types.NoticeState(models.NoticeStateRead))
	assert.Nil(t, err)
	read, unread, err := AlarmCount(namespace, userIDs[1])
	assert.Nil(t, err)
	assert.Equal(t, 1, int(unread))
	assert.Equal(t, 0, int(read))

	read, unread, err = AlarmCount(namespace, userIDs[3])
	assert.Nil(t, err)
	assert.Equal(t, 0, int(unread))
	assert.Equal(t, 1, int(read))

	err = DeleteAlarms(&namespace, nil, nil, nil, []types.ID{alarmIDs[2]})
	assert.Nil(t, err)
	read, unread, err = AlarmCount(namespace, userIDs[2])
	assert.Nil(t, err)
	assert.Equal(t, 0, int(unread))
	assert.Equal(t, 0, int(read))

	// Delete all messages with 'day' for tomorrow.
	err = DeleteOldAlarmMessages(namespace, 0, 0, -1 /* tomorrow */)
	assert.Nil(t, err)
	list, err = GetAlarmList(&namespace, nil, nil, nil, nil, nil, nil, nil, nil, nil)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		assert.Equal(t, 0, list.Total)
	}
}

func TestAddLogAlarm(t *testing.T) {
	namespace := "test-add-log-alarm-namespace"

	m, err := AddLogAlarm(namespace, nil, nil, "info", "error test")
	assert.Nil(t, err)
	if assert.NotNil(t, m) {
		defer func() {
			assert.Nil(t, DeleteAlarms(&namespace, nil, nil, nil, []types.ID{types.UUIDToID(m.ID)}))
		}()
	}
}
