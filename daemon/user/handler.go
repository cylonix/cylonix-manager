// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

// User handlers handle the api request for the users of a tenant (namespace)
// of the sase network.

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	ulog "cylonix/sase/pkg/logging/logfields"
	"errors"

	"github.com/sirupsen/logrus"
)

type serviceHandler interface {
	// User CRUD.
	GetUserList(auth interface{}, requestObject api.GetUserListRequestObject) (*models.UserList, error)
	SearchUser(auth interface{}, requestObject api.SearchUserRequestObject) (*models.UserShortInfo, error)
	UpdateUser(auth interface{}, requestObject api.UpdateUserRequestObject) error
	PostUser(auth interface{}, requestObject api.PostUserRequestObject) error
	DeleteUsers(auth interface{}, requestObject api.DeleteUsersRequestObject) error

	// Approval records.
	RegisterUser(auth interface{}, requestObject api.RegisterUserRequestObject) error
	UpdateApprovals(auth interface{}, requestObject api.UpdateUserApprovalRequestObject) error
	DeleteApprovals(auth interface{}, requestObject api.DeleteUserApprovalsRequestObject) error
	ApprovalRecords(auth interface{}, requestObject api.GetUserApprovalsRequestObject) (int, []models.UserApprovalInfo, error)

	// Password. Including admin password changes.
	SendUsername(requestObject api.SendUsernameRequestObject) error
	ResetPassword(requestObject api.ResetPasswordRequestObject) error
	ChangePassword(auth interface{}, requestObject api.ChangePasswordRequestObject) (*string, error)

	// Alert/alarm notices.
	ListNotice(auth interface{}, requestObject api.ListNoticeRequestObject) (*models.NoticeList, error)
	UpdateNotices(auth interface{}, requestObject api.UpdateNoticesRequestObject) error
	DeleteNotices(auth interface{}, requestObject api.DeleteNoticesRequestObject) error

	// Stats.
	UserSummary(auth interface{}, requestObject api.GetUserSummaryRequestObject) (models.SummaryStatsList, error)
	UserDeviceSummary(auth interface{}, requestObject api.GetUserDeviceSummaryRequestObject) ([]models.DeviceSummary, error)
	UserDeviceTraffic(auth interface{}, requestObject api.GetDeviceTrafficRequestObject) ([]models.DeviceTrafficStats, error)

	// Profile images.
	ProfileImg(auth interface{}, requestObject api.GetProfileImgRequestObject) (*models.UserProfile, error)
	UpdateProfileImg(auth interface{}, requestObject api.UpdateProfileImgRequestObject) error
	DeleteProfileImg(auth interface{}, requestObject api.DeleteProfileImgRequestObject) error

	// Access points.
	ListAccessPoint(auth interface{}, requestObject api.ListAccessPointRequestObject) (models.AccessPointList, error)
	ChangeAccessPoint(auth interface{}, requestObject api.ChangeAccessPointRequestObject) (*models.AccessPoint, error)

	// Network domain.
	GenerateNetworkDomain(auth interface{}, requestObject api.GenerateNetworkDomainRequestObject) (string, error)
	SetNetworkDomain(auth interface{}, requestObject api.SetNetworkDomainRequestObject) error

	// Misc.
	IsUsernameAvailable(params api.CheckUsernameRequestObject) (bool, error)
	UserIDToken(params api.GetIDTokenRequestObject) (*models.UserIDToken, error)
	GetUserRoles(auth interface{}, params api.GetUserRolesRequestObject) ([]models.Role, error)
}

type friendHandler interface {
	List(auth interface{}, requestObject api.ListFriendRequestObject) (*models.UserFriends, error)
	Delete(auth interface{}, requestObject api.DeleteFriendsRequestObject) error
	CreateRequest(auth interface{}, requestObject api.CreateFriendRequestRequestObject) error
	ListRequests(auth interface{}, requestObject api.ListFriendRequestsRequestObject) (models.FriendRequestList, error)
	UpdateRequests(auth interface{}, requestObject api.UpdateFriendRequestsRequestObject) error
	DeleteRequests(auth interface{}, requestObject api.DeleteFriendRequestsRequestObject) error
}

type UserService struct {
	handler       serviceHandler
	friendHandler friendHandler
	logger        *logrus.Entry
}

// Register Implements the daemon register interface
func (s *UserService) Register(d *api.StrictServer) error {
	s.logger.Infoln("Register user API handlers.")

	// User CRUD operations.
	d.DeleteUsersHandler = s.deleteUsers
	d.GetUserListHandler = s.getUser
	d.PostUserHandler = s.postUser
	d.SearchUserHandler = s.searchUser
	d.UpdateUserHandler = s.updateUser

	// User approval CRUD operations.
	d.RegisterUserHandler = s.registerUser
	d.GetUserApprovalsHandler = s.approvalRecords
	d.UpdateUserApprovalHandler = s.updateApprovals
	d.DeleteUserApprovalsHandler = s.deleteApprovals

	// Password.
	d.SendUsernameHandler = s.sendUsername
	d.ResetPasswordHandler = s.resetPassword
	d.ChangePasswordHandler = s.changePassword

	// Alert/Alarms
	d.ListNoticeHandler = s.listNotice
	d.UpdateNoticesHandler = s.updateNotices
	d.DeleteNoticesHandler = s.deleteNotices

	// Stats.
	d.GetUserSummaryHandler = s.userSummary
	d.GetUserDeviceSummaryHandler = s.userDeviceSummary
	d.GetDeviceTrafficHandler = s.userDeviceTraffic

	// Profile images.
	d.GetProfileImgHandler = s.userProfileImg
	d.UpdateProfileImgHandler = s.updateUserProfileImg
	d.DeleteProfileImgHandler = s.deleteUserProfileImg

	// Access points.
	d.ListAccessPointHandler = s.listAccessPoint
	d.ChangeAccessPointHandler = s.changeAccessPoint

	// Network domain.
	d.GenerateNetworkDomainHandler = s.generateNetworkDomain
	d.SetNetworkDomainHandler = s.setNetworkDomain

	// Friends.
	d.ListFriendHandler = s.listFriend
	d.DeleteFriendsHandler = s.deleteFriends
	d.ListFriendRequestsHandler = s.listFriendRequest
	d.CreateFriendRequestHandler = s.createFriendRequest
	d.DeleteFriendRequestsHandler = s.deleteFriendRequest
	d.UpdateFriendRequestsHandler = s.updateFriendRequests

	// Misc.
	d.CheckUsernameHandler = s.checkUsername
	d.GetIDTokenHandler = s.userIDToken
	d.GetUserRolesHandler = s.getUserRoles

	return nil
}

func NewService(logger *logrus.Entry) *UserService {
	logger = logger.WithField(ulog.LogSubsys, "user-handler")
	return &UserService{
		handler:       newHandlerImpl(logger),
		friendHandler: newFriendHandlerImpl(logger),
		logger:        logger,
	}
}

func (s *UserService) Logger() *logrus.Entry {
	return s.logger
}

func (s *UserService) Name() string {
	return "user api handler"
}

func (s *UserService) Start() error {
	return nil
}

func (s *UserService) Stop() {
	// no-op
}

func (s *UserService) getUser(ctx context.Context, requestObject api.GetUserListRequestObject) (api.GetUserListResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.handler.GetUserList(auth, requestObject)
	if err == nil {
		return api.GetUserList200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetUserList500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetUserList401Response{}, nil
	}
	return api.GetUserList400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) updateUser(ctx context.Context, requestObject api.UpdateUserRequestObject) (api.UpdateUserResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.UpdateUser(auth, requestObject)
	if err == nil {
		return api.UpdateUser200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateUser500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateUser401Response{}, nil
	}
	return api.UpdateUser400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) postUser(ctx context.Context, requestObject api.PostUserRequestObject) (api.PostUserResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.PostUser(auth, requestObject)
	if err == nil {
		return api.PostUser200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.PostUser500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.PostUser401Response{}, nil
	}
	return api.PostUser400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) searchUser(ctx context.Context, requestObject api.SearchUserRequestObject) (api.SearchUserResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.handler.SearchUser(auth, requestObject)
	if err == nil {
		return api.SearchUser200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.SearchUser500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.SearchUser401Response{}, nil
	}
	return api.SearchUser400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) deleteUsers(ctx context.Context, requestObject api.DeleteUsersRequestObject) (api.DeleteUsersResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.DeleteUsers(auth, requestObject)
	if err == nil {
		return api.DeleteUsers200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteUsers500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteUsers401Response{}, nil
	}
	return api.DeleteUsers400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) registerUser(ctx context.Context, requestObject api.RegisterUserRequestObject) (api.RegisterUserResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.RegisterUser(auth, requestObject)
	if err == nil {
		return api.RegisterUser200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.RegisterUser500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.RegisterUser401Response{}, nil
	}
	return api.RegisterUser400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *UserService) approvalRecords(ctx context.Context, requestObject api.GetUserApprovalsRequestObject) (api.GetUserApprovalsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	total, list, err := s.handler.ApprovalRecords(auth, requestObject)
	if err == nil {
		return api.GetUserApprovals200JSONResponse{
			Items: &list,
			Total: total,
		}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetUserApprovals500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetUserApprovals401Response{}, nil
	}
	return api.GetUserApprovals400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *UserService) updateApprovals(ctx context.Context, requestObject api.UpdateUserApprovalRequestObject) (api.UpdateUserApprovalResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.UpdateApprovals(auth, requestObject)
	if err == nil {
		return api.UpdateUserApproval200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateUserApproval500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateUserApproval401Response{}, nil
	}
	return api.UpdateUserApproval400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
func (s *UserService) deleteApprovals(ctx context.Context, requestObject api.DeleteUserApprovalsRequestObject) (api.DeleteUserApprovalsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.DeleteApprovals(auth, requestObject)
	if err == nil {
		return api.DeleteUserApprovals200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteUserApprovals500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteUserApprovals401Response{}, nil
	}
	return api.DeleteUserApprovals400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) sendUsername(ctx context.Context, requestObject api.SendUsernameRequestObject) (api.SendUsernameResponseObject, error) {
	err := s.handler.SendUsername(requestObject)
	if err == nil {
		return api.SendUsername200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.SendUsername500JSONResponse{}, nil
	}
	return api.SendUsername400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) resetPassword(ctx context.Context, requestObject api.ResetPasswordRequestObject) (api.ResetPasswordResponseObject, error) {
	err := s.handler.ResetPassword(requestObject)
	if err == nil {
		return api.ResetPassword200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ResetPassword500JSONResponse{}, nil
	}
	return api.ResetPassword400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) changePassword(ctx context.Context, requestObject api.ChangePasswordRequestObject) (api.ChangePasswordResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	_, err := s.handler.ChangePassword(auth, requestObject)
	if err == nil {
		return api.ChangePassword200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ChangePassword500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ChangePassword401Response{}, nil
	}
	return api.ChangePassword400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) checkUsername(ctx context.Context, requestObject api.CheckUsernameRequestObject) (api.CheckUsernameResponseObject, error) {
	ret, err := s.handler.IsUsernameAvailable(requestObject)
	if err == nil {
		return api.CheckUsername200JSONResponse(ret), nil
	}
	return api.CheckUsername500JSONResponse{}, nil
}

func (s *UserService) listNotice(ctx context.Context, requestObject api.ListNoticeRequestObject) (api.ListNoticeResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	list, err := s.handler.ListNotice(auth, requestObject)
	if err == nil {
		return api.ListNotice200JSONResponse(*list), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListNotice500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListNotice401Response{}, nil
	}
	return api.ListNotice400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) updateNotices(ctx context.Context, requestObject api.UpdateNoticesRequestObject) (api.UpdateNoticesResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.UpdateNotices(auth, requestObject)
	if err == nil {
		return api.UpdateNotices200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateNotices500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateNotices401Response{}, nil
	}
	return api.UpdateNotices400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) deleteNotices(ctx context.Context, requestObject api.DeleteNoticesRequestObject) (api.DeleteNoticesResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.DeleteNotices(auth, requestObject)
	if err == nil {
		return api.DeleteNotices200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteNotices500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteNotices401Response{}, nil
	}
	return api.DeleteNotices400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) userSummary(ctx context.Context, requestObject api.GetUserSummaryRequestObject) (api.GetUserSummaryResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	list, err := s.handler.UserSummary(auth, requestObject)
	if err == nil {
		return api.GetUserSummary200JSONResponse(list), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetUserSummary500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetUserSummary401Response{}, nil
	}
	return api.GetUserSummary400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) userDeviceSummary(ctx context.Context, requestObject api.GetUserDeviceSummaryRequestObject) (api.GetUserDeviceSummaryResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	list, err := s.handler.UserDeviceSummary(auth, requestObject)
	if err == nil {
		return api.GetUserDeviceSummary200JSONResponse(list), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetUserDeviceSummary500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetUserDeviceSummary401Response{}, nil
	}
	return api.GetUserDeviceSummary400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) userDeviceTraffic(ctx context.Context, requestObject api.GetDeviceTrafficRequestObject) (api.GetDeviceTrafficResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	list, err := s.handler.UserDeviceTraffic(auth, requestObject)
	if err == nil {
		return api.GetDeviceTraffic200JSONResponse(list), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetDeviceTraffic500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetDeviceTraffic401Response{}, nil
	}
	return api.GetDeviceTraffic400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) userIDToken(ctx context.Context, requestObject api.GetIDTokenRequestObject) (api.GetIDTokenResponseObject, error) {
	token, err := s.handler.UserIDToken(requestObject)
	if err == nil {
		return api.GetIDToken200JSONResponse(*token), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetIDToken500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetIDToken401Response{}, nil
	}
	return api.GetIDToken400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) getUserRoles(ctx context.Context, requestObject api.GetUserRolesRequestObject) (api.GetUserRolesResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	roles, err := s.handler.GetUserRoles(auth, requestObject)
	if err == nil {
		return api.GetUserRoles200JSONResponse(roles), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetUserRoles500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetUserRoles401Response{}, nil
	}
	return api.GetUserRoles400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) userProfileImg(ctx context.Context, requestObject api.GetProfileImgRequestObject) (api.GetProfileImgResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ret, err := s.handler.ProfileImg(auth, requestObject)
	if err == nil {
		return api.GetProfileImg200JSONResponse(*ret), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GetProfileImg500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GetProfileImg401Response{}, nil
	}
	return api.GetProfileImg400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) updateUserProfileImg(ctx context.Context, requestObject api.UpdateProfileImgRequestObject) (api.UpdateProfileImgResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.UpdateProfileImg(auth, requestObject)
	if err == nil {
		return api.UpdateProfileImg200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateProfileImg500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateProfileImg401Response{}, nil
	}
	return api.UpdateProfileImg400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) deleteUserProfileImg(ctx context.Context, requestObject api.DeleteProfileImgRequestObject) (api.DeleteProfileImgResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.DeleteProfileImg(auth, requestObject)
	if err == nil {
		return api.DeleteProfileImg200TextResponse(""), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteProfileImg500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteProfileImg401Response{}, nil
	}
	return api.DeleteProfileImg400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) listAccessPoint(ctx context.Context, requestObject api.ListAccessPointRequestObject) (api.ListAccessPointResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	list, err := s.handler.ListAccessPoint(auth, requestObject)
	if err == nil {
		return api.ListAccessPoint200JSONResponse(list), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListAccessPoint500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListAccessPoint401Response{}, nil
	}
	return api.ListAccessPoint400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) changeAccessPoint(ctx context.Context, requestObject api.ChangeAccessPointRequestObject) (api.ChangeAccessPointResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	ap, err := s.handler.ChangeAccessPoint(auth, requestObject)
	if err == nil {
		return api.ChangeAccessPoint200JSONResponse(*ap), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ChangeAccessPoint500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ChangeAccessPoint401Response{}, nil
	}
	return api.ChangeAccessPoint400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) generateNetworkDomain(ctx context.Context, requestObject api.GenerateNetworkDomainRequestObject) (api.GenerateNetworkDomainResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	domain, err := s.handler.GenerateNetworkDomain(auth, requestObject)
	if err == nil {
		return api.GenerateNetworkDomain200TextResponse(domain), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.GenerateNetworkDomain500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GenerateNetworkDomain401Response{}, nil
	}
	return api.GenerateNetworkDomain500JSONResponse{}, nil
}
func (s *UserService) setNetworkDomain(ctx context.Context, requestObject api.SetNetworkDomainRequestObject) (api.SetNetworkDomainResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.handler.SetNetworkDomain(auth, requestObject)
	if err == nil {
		return api.SetNetworkDomain200TextResponse("OK"), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.SetNetworkDomain500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.GenerateNetworkDomain401Response{}, nil
	}
	return api.SetNetworkDomain400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) listFriend(ctx context.Context, requestObject api.ListFriendRequestObject) (api.ListFriendResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	list, err := s.friendHandler.List(auth, requestObject)
	if err == nil {
		return api.ListFriend200JSONResponse(*list), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListFriend500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListFriend401Response{}, nil
	}
	return api.ListFriend400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) updateFriendRequests(ctx context.Context, requestObject api.UpdateFriendRequestsRequestObject) (api.UpdateFriendRequestsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.friendHandler.UpdateRequests(auth, requestObject)
	if err == nil {
		return api.UpdateFriendRequests200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.UpdateFriendRequests500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.UpdateFriendRequests401Response{}, nil
	}
	return api.UpdateFriendRequests400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) deleteFriends(ctx context.Context, requestObject api.DeleteFriendsRequestObject) (api.DeleteFriendsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.friendHandler.Delete(auth, requestObject)
	if err == nil {
		return api.DeleteFriends200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteFriends500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteFriends401Response{}, nil
	}
	return api.DeleteFriends400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) listFriendRequest(ctx context.Context, requestObject api.ListFriendRequestsRequestObject) (api.ListFriendRequestsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	list, err := s.friendHandler.ListRequests(auth, requestObject)
	if err == nil {
		return api.ListFriendRequests200JSONResponse(list), nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.ListFriendRequests500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.ListFriendRequests401Response{}, nil
	}
	return api.ListFriendRequests400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) createFriendRequest(ctx context.Context, requestObject api.CreateFriendRequestRequestObject) (api.CreateFriendRequestResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.friendHandler.CreateRequest(auth, requestObject)
	if err == nil {
		return api.CreateFriendRequest200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.CreateFriendRequest500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.CreateFriendRequest401Response{}, nil
	}
	return api.CreateFriendRequest400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}

func (s *UserService) deleteFriendRequest(ctx context.Context, requestObject api.DeleteFriendRequestsRequestObject) (api.DeleteFriendRequestsResponseObject, error) {
	auth := ctx.Value(api.SecurityAuthContextKey)
	err := s.friendHandler.DeleteRequests(auth, requestObject)
	if err == nil {
		return api.DeleteFriendRequests200Response{}, nil
	}
	if errors.Is(err, common.ErrInternalErr) {
		return api.DeleteFriendRequests500JSONResponse{}, nil
	}
	if errors.Is(err, common.ErrModelUnauthorized) {
		return api.DeleteFriendRequests401Response{}, nil
	}
	return api.DeleteFriendRequests400JSONResponse{
		BadRequestJSONResponse: common.NewBadRequestJSONResponse(err),
	}, nil
}
