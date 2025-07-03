package accesskey

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	tu "cylonix/sase/pkg/test/user"
	"flag"
	"fmt"
	"log"
	"os"
	"testing"

	"github.com/cylonix/utils"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

var (
	testNamespace = "test-namespace"
	testUserID    types.UserID
	testUsername  = "test-user"
	testUserToken *utils.UserTokenData
	testLogger    = logrus.NewEntry(logrus.New())
)

func TestListAccessKey(t *testing.T) {
	namespace := testNamespace
	params := models.ListAccessKeyParams{}
	auth := testUserToken
	handler := newHandlerImpl(testLogger)
	service := NewService(testLogger)

	total, list, err := handler.List(nil, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
		assert.Equal(t, 0, int(total))
		assert.Nil(t, list)
	}
	r, err := service.list(context.Background(), api.ListAccessKeyRequestObject{})
	assert.Nil(t, err)
	assert.IsType(t, api.ListAccessKey401Response{}, r)

	other := uuid.New().String()
	params.UserID = &other
	total, list, err = handler.List(auth, params)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
		assert.Equal(t, 0, int(total))
		assert.Nil(t, list)
	}
	auth.IsAdminUser = true
	defer func() { auth.IsAdminUser = false }()
	total, list, err = handler.List(auth, params)
	if assert.Nil(t, err) && list != nil {
		assert.Equal(t, 0, int(total))
		assert.Equal(t, 0, len(*list))
	}
	auth.IsAdminUser = false

	params = models.ListAccessKeyParams{}
	total, list, err = handler.List(auth, params)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		assert.Equal(t, 0, int(total))
		assert.Equal(t, 0, len(*list))
	}
	ctx := context.WithValue(context.Background(), api.SecurityAuthContextKey, auth)
	r, err = service.list(ctx, api.ListAccessKeyRequestObject{})
	assert.Nil(t, err)
	assert.IsType(t, api.ListAccessKey200JSONResponse{}, r)

	ids, names := make([]types.AccessKeyID, 10), make([]string, 10)
	for i := 0; i < 10; i++ {
		names[i] = fmt.Sprintf("%v-%v", testUsername, i)
		a, err := db.CreateAccessKey(namespace, testUserID, names[i], nil, nil, optional.Int64P(0))
		if !assert.Nil(t, err) && assert.NotNil(t, a) {
			t.Fatalf("Failed to create new access key: %v", err)
		}
		ids[i] = a.ID
	}
	defer func() {
		for _, id := range ids {
			assert.Nil(t, db.DeleteAccessKey(namespace, id.String()))
		}
	}()

	params = models.ListAccessKeyParams{Contain: &testUsername}
	total, list, err = handler.List(auth, params)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		assert.Equal(t, 10, int(total))
		assert.Equal(t, 10, len(*list))
	}

	by := "username"
	params = models.ListAccessKeyParams{FilterBy: &by, FilterValue: &names[5]}
	total, list, err = handler.List(auth, params)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		assert.Equal(t, 1, int(total))
		if assert.Equal(t, 1, len(*list)) {
			assert.Equal(t, names[5], (*list)[0].Username)
		}
	}

	sortBy, sortDesc := "username", "desc"
	params = models.ListAccessKeyParams{SortBy: &sortBy, SortDesc: &sortDesc}
	total, list, err = handler.List(auth, params)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		assert.Equal(t, 10, int(total))
		if assert.Equal(t, 10, len(*list)) {
			assert.Equal(t, names[9], (*list)[0].Username)
		}
	}
	page, pageSize := int(2), int(5)
	params = models.ListAccessKeyParams{SortBy: &sortBy, SortDesc: &sortDesc, Page: &page, PageSize: &pageSize}
	total, list, err = handler.List(auth, params)
	if assert.Nil(t, err) && assert.NotNil(t, list) {
		assert.Equal(t, 10, int(total))
		if assert.Equal(t, 5, len(*list)) {
			assert.Equal(t, names[0], (*list)[4].Username)
		}
	}
}

func TestGetAccessKey(t *testing.T) {
	namespace := testNamespace
	accessKeyID := "access-key-id"
	auth := testUserToken
	handler := newHandlerImpl(testLogger)
	service := NewService(testLogger)

	a, err := handler.Get(nil, accessKeyID)
	if assert.NotNil(t, err) {
		assert.Nil(t, a)
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
	}
	getAccessParams := api.GetAccessKeyRequestObject{}
	r, err := service.get(context.Background(), getAccessParams)
	assert.IsType(t, api.GetAccessKey401Response{}, r)
	assert.Nil(t, err)

	a, err = handler.Get(auth, accessKeyID)
	if assert.NotNil(t, err) {
		assert.Nil(t, a)
		assert.ErrorAs(t, err, &common.BadParamsErr{})
	}
	ctx := context.WithValue(context.Background(), api.SecurityAuthContextKey, auth)
	r, err = service.get(ctx, getAccessParams)
	assert.Nil(t, err)
	assert.IsType(t, api.GetAccessKey400JSONResponse{}, r)

	accessKeyID = "not-exists"
	getAccessParams.AccessKeyID = accessKeyID
	a, err = handler.Get(auth, accessKeyID)
	if assert.NotNil(t, err) {
		assert.Nil(t, a)
		assert.ErrorAs(t, err, &common.BadParamsErr{})
	}
	key, err := db.CreateAccessKey(namespace, testUserID, "", nil, nil, optional.Int64P(0))
	if !assert.Nil(t, err) && assert.NotNil(t, key) {
		t.Fatalf("Failed to create new access key: %v", err)
	}
	a = key.ToModel()
	defer func() { assert.Nil(t, db.DeleteAccessKey(namespace, a.ID.String())) }()
	accessKeyID = a.ID.String()
	a, err = handler.Get(auth, accessKeyID)
	if assert.Nil(t, err) && assert.NotNil(t, a) {
		assert.Equal(t, testUserID.UUID(), a.UserID)
	}
	getAccessParams.AccessKeyID = accessKeyID
	r, err = service.get(ctx, getAccessParams)
	assert.Nil(t, err)
	assert.IsType(t, api.GetAccessKey200JSONResponse{}, r)
}

func TestCreateAccessKey(t *testing.T) {
	namespace := testNamespace
	params := api.CreateAccessKeyRequestObject{}
	handleParams := &models.AccessKey{}
	auth := testUserToken
	handler := newHandlerImpl(testLogger)
	service := NewService(testLogger)

	a, err := handler.Create(nil, handleParams)
	if assert.NotNil(t, err) {
		assert.Nil(t, a)
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
	}
	ctx := context.WithValue(context.Background(), api.SecurityAuthContextKey, auth)
	r, err := service.create(context.Background(), params)
	assert.Nil(t, err)
	assert.IsType(t, api.CreateAccessKey401Response{}, r)

	a, err = handler.Create(auth, nil)
	if assert.NotNil(t, err) {
		assert.Nil(t, a)
		assert.ErrorAs(t, err, &common.BadParamsErr{})
	}
	r, err = service.create(ctx, params)
	assert.Nil(t, err)
	assert.IsType(t, api.CreateAccessKey400JSONResponse{}, r)

	handleParams = &models.AccessKey{UserID: uuid.New()}
	params = api.CreateAccessKeyRequestObject{
		Body: handleParams,
	}
	a, err = handler.Create(auth, handleParams)
	if assert.NotNil(t, err) {
		assert.Nil(t, a)
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
	}
	handleParams = &models.AccessKey{}
	a, err = handler.Create(auth, handleParams)
	if assert.NotNil(t, err) {
		assert.Nil(t, a)
		assert.ErrorIs(t, err, common.ErrModelUserNotExists)
	}
	u, err := tu.New(namespace, testUsername, "")
	if !assert.Nil(t, err) || !assert.NotNil(t, u) {
		t.Fatalf("Failed to create user for test: %v", err)
	}
	auth.UserID = u.ID.UUID()
	defer func() {
		tu.Delete(namespace, u.ID)
		auth.UserID = testUserID.UUID()
	}()
	a, err = handler.Create(auth, handleParams)
	assert.Nil(t, err)
	assert.NotNil(t, a)
	ctx = context.WithValue(context.Background(), api.SecurityAuthContextKey, auth)
	params.Body = &models.AccessKey{}
	r, err = service.create(ctx, params)
	assert.Nil(t, err)
	assert.IsType(t, api.CreateAccessKey200JSONResponse{}, r)
}

func TestDeleteAccessKey(t *testing.T) {
	namespace := testNamespace
	params := api.DeleteAccessKeyRequestObject{}
	handleParams := ""
	auth := testUserToken
	handler := newHandlerImpl(testLogger)
	service := NewService(testLogger)

	err := handler.Delete(nil, handleParams)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrModelUnauthorized)
	}
	ctx := context.WithValue(context.Background(), api.SecurityAuthContextKey, auth)
	r, err := service.delete(context.Background(), params)
	assert.Nil(t, err)
	assert.IsType(t, api.CreateAccessKey401Response{}, r)

	err = handler.Delete(auth, handleParams)
	if assert.NotNil(t, err) {
		assert.ErrorAs(t, err, &common.BadParamsErr{})
	}
	r, err = service.delete(ctx, params)
	assert.Nil(t, err)
	assert.IsType(t, api.DeleteAccessKey400JSONResponse{}, r)

	a, err := db.CreateAccessKey(namespace, testUserID, "", nil, nil, optional.Int64P(0))
	if !assert.Nil(t, err) && assert.NotNil(t, a) {
		t.Fatalf("Failed to create new access key: %v", err)
	}
	defer func() { assert.Nil(t, db.DeleteAccessKey(namespace, a.ID.String())) }()
	auth.UserID = uuid.New()
	defer func() { auth.UserID = testUserID.UUID() }()
	handleParams = a.ID.String()
	params = api.DeleteAccessKeyRequestObject{AccessKeyID: handleParams}
	err = handler.Delete(auth, handleParams)
	if assert.NotNil(t, err) {
		assert.ErrorIs(t, err, common.ErrInternalErr)
	}
	auth.UserID = testUserID.UUID()
	err = handler.Delete(auth, handleParams)
	assert.Nil(t, err)
	r, err = service.delete(ctx, params)
	assert.Nil(t, err)
	assert.IsType(t, api.DeleteAccessKey200TextResponse(""), r)
}

func TestService(t *testing.T) {
	service := NewService(testLogger)
	err := service.Register(&api.StrictServer{})
	assert.Nil(t, err)
	logger := service.Logger()
	assert.NotNil(t, logger)
	name := service.Name()
	assert.NotEmpty(t, name)
	err = service.Start()
	assert.Nil(t, err)
}

func testSetup() error {
	utils.Init(nil)
	if err := db.InitEmulator(testing.Verbose()); err != nil {
		return err
	}
	if !testing.Verbose() {
		testLogger.Logger.SetLevel(logrus.ErrorLevel)
	}
	id, err := types.NewID()
	if err != nil {
		return err
	}
	testUserID = id
	token := utils.NewUserToken(testNamespace)
	testUserToken = &utils.UserTokenData{
		Token:         token.Token,
		TokenTypeName: token.Name(),
		Namespace:     testNamespace,
		UserID:        testUserID.UUID(),
	}
	if err := token.Create(testUserToken); err != nil {
		return err
	}
	return nil
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
