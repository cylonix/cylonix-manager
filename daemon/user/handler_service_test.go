// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	"context"
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"errors"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakeUserHandler struct {
	err error
	// Various return values populated per-test.
	userList        *models.UserList
	shortInfo       *models.UserShortInfo
	approvalTotal   int
	approvalList    []models.UserApprovalInfo
	noticeList      *models.NoticeList
	summaryStats    models.SummaryStatsList
	deviceSummary   []models.DeviceSummary
	deviceTraffic   []models.DeviceTrafficStats
	multiUserTotal  int
	multiUserUsers  *[]models.User
	profile         *models.UserProfile
	accessPointList models.AccessPointList
	accessPoint     *models.AccessPoint
	genDomain       string
	idToken         *models.UserIDToken
	roles           []models.Role
	inviteLink      string
	userInvite      *models.UserInvite
	userInvites     []models.UserInvite
	userInvitesTot  int
	changedPass     *string
	isUsernameFree  bool
}

func (f *fakeUserHandler) GetUserList(_ any, _ api.GetUserListRequestObject) (*models.UserList, error) {
	return f.userList, f.err
}
func (f *fakeUserHandler) SearchUser(_ any, _ api.SearchUserRequestObject) (*models.UserShortInfo, error) {
	return f.shortInfo, f.err
}
func (f *fakeUserHandler) UpdateUser(_ any, _ api.UpdateUserRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) PostUser(_ any, _ api.PostUserRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) DeleteUsers(_ any, _ api.DeleteUsersRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) RegisterUser(_ any, _ api.RegisterUserRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) UpdateApprovals(_ any, _ api.UpdateUserApprovalRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) DeleteApprovals(_ any, _ api.DeleteUserApprovalsRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) ApprovalRecords(_ any, _ api.GetUserApprovalsRequestObject) (int, []models.UserApprovalInfo, error) {
	return f.approvalTotal, f.approvalList, f.err
}
func (f *fakeUserHandler) SendUsername(_ api.SendUsernameRequestObject) error { return f.err }
func (f *fakeUserHandler) ResetPassword(_ api.ResetPasswordRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) ChangePassword(_ any, _ api.ChangePasswordRequestObject) (*string, error) {
	return f.changedPass, f.err
}
func (f *fakeUserHandler) ListNotice(_ any, _ api.ListNoticeRequestObject) (*models.NoticeList, error) {
	return f.noticeList, f.err
}
func (f *fakeUserHandler) UpdateNotices(_ any, _ api.UpdateNoticesRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) DeleteNotices(_ any, _ api.DeleteNoticesRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) UserSummary(_ any, _ api.GetUserSummaryRequestObject) (models.SummaryStatsList, error) {
	return f.summaryStats, f.err
}
func (f *fakeUserHandler) UserDeviceSummary(_ any, _ api.GetUserDeviceSummaryRequestObject) ([]models.DeviceSummary, error) {
	return f.deviceSummary, f.err
}
func (f *fakeUserHandler) UserDeviceTraffic(_ any, _ api.GetDeviceTrafficRequestObject) ([]models.DeviceTrafficStats, error) {
	return f.deviceTraffic, f.err
}
func (f *fakeUserHandler) MultiUserNetworkSummary(_ any, _ api.GetUserMultiUserNetworkSummaryRequestObject) (int, *[]models.User, error) {
	return f.multiUserTotal, f.multiUserUsers, f.err
}
func (f *fakeUserHandler) ProfileImg(_ any, _ api.GetProfileImgRequestObject) (*models.UserProfile, error) {
	return f.profile, f.err
}
func (f *fakeUserHandler) UpdateProfileImg(_ any, _ api.UpdateProfileImgRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) DeleteProfileImg(_ any, _ api.DeleteProfileImgRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) ListAccessPoint(_ any, _ api.ListAccessPointRequestObject) (models.AccessPointList, error) {
	return f.accessPointList, f.err
}
func (f *fakeUserHandler) ChangeAccessPoint(_ any, _ api.ChangeAccessPointRequestObject) (*models.AccessPoint, error) {
	return f.accessPoint, f.err
}
func (f *fakeUserHandler) GenerateNetworkDomain(_ any, _ api.GenerateNetworkDomainRequestObject) (string, error) {
	return f.genDomain, f.err
}
func (f *fakeUserHandler) SetNetworkDomain(_ any, _ api.SetNetworkDomainRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) IsUsernameAvailable(_ api.CheckUsernameRequestObject) (bool, error) {
	return f.isUsernameFree, f.err
}
func (f *fakeUserHandler) UserIDToken(_ api.GetIDTokenRequestObject) (*models.UserIDToken, error) {
	return f.idToken, f.err
}
func (f *fakeUserHandler) GetUserRoles(_ any, _ api.GetUserRolesRequestObject) ([]models.Role, error) {
	return f.roles, f.err
}
func (f *fakeUserHandler) InviteUser(_ any, _ api.InviteUserRequestObject) (string, error) {
	return f.inviteLink, f.err
}
func (f *fakeUserHandler) DeleteUserInvite(_ any, _ api.DeleteUserInviteRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) GetUserInvite(_ any, _ api.GetUserInviteRequestObject) (*models.UserInvite, error) {
	return f.userInvite, f.err
}
func (f *fakeUserHandler) UpdateUserInvite(_ any, _ api.UpdateUserInviteRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) SendUserInvite(_ any, _ api.SendUserInviteRequestObject) error {
	return f.err
}
func (f *fakeUserHandler) ListUserInvite(_ any, _ api.GetUserInviteListRequestObject) (int, []models.UserInvite, error) {
	return f.userInvitesTot, f.userInvites, f.err
}

type fakeFriendHandler struct {
	err      error
	friends  *models.UserFriends
	requests models.FriendRequestList
}

func (f *fakeFriendHandler) List(_ any, _ api.ListFriendRequestObject) (*models.UserFriends, error) {
	return f.friends, f.err
}
func (f *fakeFriendHandler) Delete(_ any, _ api.DeleteFriendsRequestObject) error {
	return f.err
}
func (f *fakeFriendHandler) CreateRequest(_ any, _ api.CreateFriendRequestRequestObject) error {
	return f.err
}
func (f *fakeFriendHandler) ListRequests(_ any, _ api.ListFriendRequestsRequestObject) (models.FriendRequestList, error) {
	return f.requests, f.err
}
func (f *fakeFriendHandler) UpdateRequests(_ any, _ api.UpdateFriendRequestsRequestObject) error {
	return f.err
}
func (f *fakeFriendHandler) DeleteRequests(_ any, _ api.DeleteFriendRequestsRequestObject) error {
	return f.err
}

func newUserSvc(uh *fakeUserHandler, fh *fakeFriendHandler) *UserService {
	return &UserService{
		handler:       uh,
		friendHandler: fh,
		logger:        logrus.NewEntry(logrus.New()),
	}
}

func TestUserService_MetaAndRegister(t *testing.T) {
	s := newUserSvc(&fakeUserHandler{}, &fakeFriendHandler{})
	assert.Equal(t, "user api handler", s.Name())
	assert.NotNil(t, s.Logger())
	assert.NoError(t, s.Start())
	s.Stop()
	d := &api.StrictServer{}
	assert.NoError(t, s.Register(d))
	assert.NotNil(t, d.GetUserListHandler)
	assert.NotNil(t, d.ListFriendHandler)
}

func runBranchCheck(t *testing.T, f *fakeUserHandler, fh *fakeFriendHandler, fn func(*UserService) (any, error), success, internal, unauthorized, bad any) {
	s := newUserSvc(f, fh)
	resp, _ := fn(s)
	assert.IsType(t, success, resp)
	if internal != nil {
		f.err = common.ErrInternalErr
		resp, _ = fn(s)
		assert.IsType(t, internal, resp)
	}
	if unauthorized != nil {
		f.err = common.ErrModelUnauthorized
		resp, _ = fn(s)
		assert.IsType(t, unauthorized, resp)
	}
	if bad != nil {
		f.err = errors.New("x")
		resp, _ = fn(s)
		assert.IsType(t, bad, resp)
	}
}

func TestGetUserList_Branches(t *testing.T) {
	fh := &fakeFriendHandler{}
	userList := &models.UserList{}
	runBranchCheck(t, &fakeUserHandler{userList: userList}, fh, func(s *UserService) (any, error) {
		return s.getUser(context.Background(), api.GetUserListRequestObject{})
	},
		api.GetUserList200JSONResponse{}, api.GetUserList500JSONResponse{},
		api.GetUserList401Response{}, api.GetUserList400JSONResponse{},
	)
}

func TestUpdateUser_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.updateUser(context.Background(), api.UpdateUserRequestObject{})
	},
		api.UpdateUser200Response{}, api.UpdateUser500JSONResponse{},
		api.UpdateUser401Response{}, api.UpdateUser400JSONResponse{},
	)
}

func TestPostUser_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.postUser(context.Background(), api.PostUserRequestObject{})
	},
		api.PostUser200Response{}, api.PostUser500JSONResponse{},
		api.PostUser401Response{}, api.PostUser400JSONResponse{},
	)
}

func TestSearchUser_Branches(t *testing.T) {
	info := &models.UserShortInfo{}
	runBranchCheck(t, &fakeUserHandler{shortInfo: info}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.searchUser(context.Background(), api.SearchUserRequestObject{})
	},
		api.SearchUser200JSONResponse{}, api.SearchUser500JSONResponse{},
		api.SearchUser401Response{}, api.SearchUser400JSONResponse{},
	)
}

func TestDeleteUsers_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.deleteUsers(context.Background(), api.DeleteUsersRequestObject{})
	},
		api.DeleteUsers200Response{}, api.DeleteUsers500JSONResponse{},
		api.DeleteUsers401Response{}, api.DeleteUsers400JSONResponse{},
	)
}

func TestRegisterUser_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.registerUser(context.Background(), api.RegisterUserRequestObject{})
	},
		api.RegisterUser200TextResponse(""), api.RegisterUser500JSONResponse{},
		api.RegisterUser401Response{}, api.RegisterUser400JSONResponse{},
	)
}

func TestApprovalRecords_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{approvalTotal: 1}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.approvalRecords(context.Background(), api.GetUserApprovalsRequestObject{})
	},
		api.GetUserApprovals200JSONResponse{}, api.GetUserApprovals500JSONResponse{},
		api.GetUserApprovals401Response{}, api.GetUserApprovals400JSONResponse{},
	)
}

func TestUpdateApprovals_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.updateApprovals(context.Background(), api.UpdateUserApprovalRequestObject{})
	},
		api.UpdateUserApproval200TextResponse(""), api.UpdateUserApproval500JSONResponse{},
		api.UpdateUserApproval401Response{}, api.UpdateUserApproval400JSONResponse{},
	)
}

func TestDeleteApprovals_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.deleteApprovals(context.Background(), api.DeleteUserApprovalsRequestObject{})
	},
		api.DeleteUserApprovals200TextResponse(""), api.DeleteUserApprovals500JSONResponse{},
		api.DeleteUserApprovals401Response{}, api.DeleteUserApprovals400JSONResponse{},
	)
}

func TestSendUsername_Branches(t *testing.T) {
	s := newUserSvc(&fakeUserHandler{}, &fakeFriendHandler{})
	resp, _ := s.sendUsername(context.Background(), api.SendUsernameRequestObject{})
	assert.IsType(t, api.SendUsername200TextResponse(""), resp)

	s = newUserSvc(&fakeUserHandler{err: common.ErrInternalErr}, &fakeFriendHandler{})
	resp, _ = s.sendUsername(context.Background(), api.SendUsernameRequestObject{})
	assert.IsType(t, api.SendUsername500JSONResponse{}, resp)

	s = newUserSvc(&fakeUserHandler{err: errors.New("x")}, &fakeFriendHandler{})
	resp, _ = s.sendUsername(context.Background(), api.SendUsernameRequestObject{})
	assert.IsType(t, api.SendUsername400JSONResponse{}, resp)
}

func TestResetPassword_Branches(t *testing.T) {
	s := newUserSvc(&fakeUserHandler{}, &fakeFriendHandler{})
	resp, _ := s.resetPassword(context.Background(), api.ResetPasswordRequestObject{})
	assert.IsType(t, api.ResetPassword200TextResponse(""), resp)

	s = newUserSvc(&fakeUserHandler{err: common.ErrInternalErr}, &fakeFriendHandler{})
	resp, _ = s.resetPassword(context.Background(), api.ResetPasswordRequestObject{})
	assert.IsType(t, api.ResetPassword500JSONResponse{}, resp)

	s = newUserSvc(&fakeUserHandler{err: errors.New("x")}, &fakeFriendHandler{})
	resp, _ = s.resetPassword(context.Background(), api.ResetPasswordRequestObject{})
	assert.IsType(t, api.ResetPassword400JSONResponse{}, resp)
}

func TestChangePassword_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.changePassword(context.Background(), api.ChangePasswordRequestObject{})
	},
		api.ChangePassword200TextResponse(""), api.ChangePassword500JSONResponse{},
		api.ChangePassword401Response{}, api.ChangePassword400JSONResponse{},
	)
}

func TestCheckUsername_Branches(t *testing.T) {
	s := newUserSvc(&fakeUserHandler{isUsernameFree: true}, &fakeFriendHandler{})
	resp, _ := s.checkUsername(context.Background(), api.CheckUsernameRequestObject{})
	assert.IsType(t, api.CheckUsername200JSONResponse(false), resp)

	s = newUserSvc(&fakeUserHandler{err: errors.New("x")}, &fakeFriendHandler{})
	resp, _ = s.checkUsername(context.Background(), api.CheckUsernameRequestObject{})
	assert.IsType(t, api.CheckUsername500JSONResponse{}, resp)
}

func TestListNotice_Branches(t *testing.T) {
	notices := &models.NoticeList{}
	runBranchCheck(t, &fakeUserHandler{noticeList: notices}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.listNotice(context.Background(), api.ListNoticeRequestObject{})
	},
		api.ListNotice200JSONResponse{}, api.ListNotice500JSONResponse{},
		api.ListNotice401Response{}, api.ListNotice400JSONResponse{},
	)
}

func TestUpdateNotices_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.updateNotices(context.Background(), api.UpdateNoticesRequestObject{})
	},
		api.UpdateNotices200TextResponse(""), api.UpdateNotices500JSONResponse{},
		api.UpdateNotices401Response{}, api.UpdateNotices400JSONResponse{},
	)
}

func TestDeleteNotices_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.deleteNotices(context.Background(), api.DeleteNoticesRequestObject{})
	},
		api.DeleteNotices200TextResponse(""), api.DeleteNotices500JSONResponse{},
		api.DeleteNotices401Response{}, api.DeleteNotices400JSONResponse{},
	)
}

func TestUserSummary_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.userSummary(context.Background(), api.GetUserSummaryRequestObject{})
	},
		api.GetUserSummary200JSONResponse{}, api.GetUserSummary500JSONResponse{},
		api.GetUserSummary401Response{}, api.GetUserSummary400JSONResponse{},
	)
}

func TestMultiUserNetworkSummary_Branches(t *testing.T) {
	users := &[]models.User{}
	runBranchCheck(t, &fakeUserHandler{multiUserUsers: users}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.multiUserNetworkSummary(context.Background(), api.GetUserMultiUserNetworkSummaryRequestObject{})
	},
		api.GetUserMultiUserNetworkSummary200JSONResponse{},
		api.GetUserMultiUserNetworkSummary500JSONResponse{},
		api.GetUserMultiUserNetworkSummary401Response{},
		api.GetUserMultiUserNetworkSummary400JSONResponse{},
	)
}

func TestUserDeviceSummary_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.userDeviceSummary(context.Background(), api.GetUserDeviceSummaryRequestObject{})
	},
		api.GetUserDeviceSummary200JSONResponse{}, api.GetUserDeviceSummary500JSONResponse{},
		api.GetUserDeviceSummary401Response{}, api.GetUserDeviceSummary400JSONResponse{},
	)
}

func TestUserDeviceTraffic_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.userDeviceTraffic(context.Background(), api.GetDeviceTrafficRequestObject{})
	},
		api.GetDeviceTraffic200JSONResponse{}, api.GetDeviceTraffic500JSONResponse{},
		api.GetDeviceTraffic401Response{}, api.GetDeviceTraffic400JSONResponse{},
	)
}

func TestUserIDToken_Branches(t *testing.T) {
	tok := &models.UserIDToken{}
	runBranchCheck(t, &fakeUserHandler{idToken: tok}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.userIDToken(context.Background(), api.GetIDTokenRequestObject{})
	},
		api.GetIDToken200JSONResponse{}, api.GetIDToken500JSONResponse{},
		api.GetIDToken401Response{}, api.GetIDToken400JSONResponse{},
	)
}

func TestGetUserRoles_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.getUserRoles(context.Background(), api.GetUserRolesRequestObject{})
	},
		api.GetUserRoles200JSONResponse{}, api.GetUserRoles500JSONResponse{},
		api.GetUserRoles401Response{}, api.GetUserRoles400JSONResponse{},
	)
}

func TestProfileImg_Branches(t *testing.T) {
	prof := &models.UserProfile{}
	runBranchCheck(t, &fakeUserHandler{profile: prof}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.userProfileImg(context.Background(), api.GetProfileImgRequestObject{})
	},
		api.GetProfileImg200JSONResponse{}, api.GetProfileImg500JSONResponse{},
		api.GetProfileImg401Response{}, api.GetProfileImg400JSONResponse{},
	)
}

func TestUpdateProfileImg_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.updateUserProfileImg(context.Background(), api.UpdateProfileImgRequestObject{})
	},
		api.UpdateProfileImg200TextResponse(""), api.UpdateProfileImg500JSONResponse{},
		api.UpdateProfileImg401Response{}, api.UpdateProfileImg400JSONResponse{},
	)
}

func TestDeleteProfileImg_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.deleteUserProfileImg(context.Background(), api.DeleteProfileImgRequestObject{})
	},
		api.DeleteProfileImg200TextResponse(""), api.DeleteProfileImg500JSONResponse{},
		api.DeleteProfileImg401Response{}, api.DeleteProfileImg400JSONResponse{},
	)
}

func TestListAccessPoint_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.listAccessPoint(context.Background(), api.ListAccessPointRequestObject{})
	},
		api.ListAccessPoint200JSONResponse{}, api.ListAccessPoint500JSONResponse{},
		api.ListAccessPoint401Response{}, api.ListAccessPoint400JSONResponse{},
	)
}

func TestChangeAccessPoint_Branches(t *testing.T) {
	ap := &models.AccessPoint{}
	runBranchCheck(t, &fakeUserHandler{accessPoint: ap}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.changeAccessPoint(context.Background(), api.ChangeAccessPointRequestObject{})
	},
		api.ChangeAccessPoint200JSONResponse{}, api.ChangeAccessPoint500JSONResponse{},
		api.ChangeAccessPoint401Response{}, api.ChangeAccessPoint400JSONResponse{},
	)
}

func TestGenerateNetworkDomain_Branches(t *testing.T) {
	s := newUserSvc(&fakeUserHandler{genDomain: "d"}, &fakeFriendHandler{})
	resp, _ := s.generateNetworkDomain(context.Background(), api.GenerateNetworkDomainRequestObject{})
	assert.IsType(t, api.GenerateNetworkDomain200TextResponse(""), resp)

	s = newUserSvc(&fakeUserHandler{err: common.ErrInternalErr}, &fakeFriendHandler{})
	resp, _ = s.generateNetworkDomain(context.Background(), api.GenerateNetworkDomainRequestObject{})
	assert.IsType(t, api.GenerateNetworkDomain500JSONResponse{}, resp)

	s = newUserSvc(&fakeUserHandler{err: common.ErrModelUnauthorized}, &fakeFriendHandler{})
	resp, _ = s.generateNetworkDomain(context.Background(), api.GenerateNetworkDomainRequestObject{})
	assert.IsType(t, api.GenerateNetworkDomain401Response{}, resp)
}

func TestSetNetworkDomain_Branches(t *testing.T) {
	s := newUserSvc(&fakeUserHandler{}, &fakeFriendHandler{})
	resp, _ := s.setNetworkDomain(context.Background(), api.SetNetworkDomainRequestObject{})
	assert.IsType(t, api.SetNetworkDomain200TextResponse(""), resp)

	s = newUserSvc(&fakeUserHandler{err: common.ErrInternalErr}, &fakeFriendHandler{})
	resp, _ = s.setNetworkDomain(context.Background(), api.SetNetworkDomainRequestObject{})
	assert.IsType(t, api.SetNetworkDomain500JSONResponse{}, resp)

	s = newUserSvc(&fakeUserHandler{err: errors.New("x")}, &fakeFriendHandler{})
	resp, _ = s.setNetworkDomain(context.Background(), api.SetNetworkDomainRequestObject{})
	assert.IsType(t, api.SetNetworkDomain400JSONResponse{}, resp)
}

func TestListFriend_Branches(t *testing.T) {
	fh := &fakeFriendHandler{friends: &models.UserFriends{}}
	s := newUserSvc(&fakeUserHandler{}, fh)
	resp, _ := s.listFriend(context.Background(), api.ListFriendRequestObject{})
	assert.IsType(t, api.ListFriend200JSONResponse{}, resp)

	fh.err = common.ErrInternalErr
	resp, _ = s.listFriend(context.Background(), api.ListFriendRequestObject{})
	assert.IsType(t, api.ListFriend500JSONResponse{}, resp)

	fh.err = common.ErrModelUnauthorized
	resp, _ = s.listFriend(context.Background(), api.ListFriendRequestObject{})
	assert.IsType(t, api.ListFriend401Response{}, resp)

	fh.err = errors.New("x")
	resp, _ = s.listFriend(context.Background(), api.ListFriendRequestObject{})
	assert.IsType(t, api.ListFriend400JSONResponse{}, resp)
}

func TestUpdateFriendRequests_Branches(t *testing.T) {
	fh := &fakeFriendHandler{}
	s := newUserSvc(&fakeUserHandler{}, fh)
	resp, _ := s.updateFriendRequests(context.Background(), api.UpdateFriendRequestsRequestObject{})
	assert.IsType(t, api.UpdateFriendRequests200Response{}, resp)

	fh.err = common.ErrInternalErr
	resp, _ = s.updateFriendRequests(context.Background(), api.UpdateFriendRequestsRequestObject{})
	assert.IsType(t, api.UpdateFriendRequests500JSONResponse{}, resp)

	fh.err = common.ErrModelUnauthorized
	resp, _ = s.updateFriendRequests(context.Background(), api.UpdateFriendRequestsRequestObject{})
	assert.IsType(t, api.UpdateFriendRequests401Response{}, resp)

	fh.err = errors.New("x")
	resp, _ = s.updateFriendRequests(context.Background(), api.UpdateFriendRequestsRequestObject{})
	assert.IsType(t, api.UpdateFriendRequests400JSONResponse{}, resp)
}

func TestDeleteFriends_Branches(t *testing.T) {
	fh := &fakeFriendHandler{}
	s := newUserSvc(&fakeUserHandler{}, fh)
	resp, _ := s.deleteFriends(context.Background(), api.DeleteFriendsRequestObject{})
	assert.IsType(t, api.DeleteFriends200Response{}, resp)

	fh.err = common.ErrInternalErr
	resp, _ = s.deleteFriends(context.Background(), api.DeleteFriendsRequestObject{})
	assert.IsType(t, api.DeleteFriends500JSONResponse{}, resp)

	fh.err = common.ErrModelUnauthorized
	resp, _ = s.deleteFriends(context.Background(), api.DeleteFriendsRequestObject{})
	assert.IsType(t, api.DeleteFriends401Response{}, resp)

	fh.err = errors.New("x")
	resp, _ = s.deleteFriends(context.Background(), api.DeleteFriendsRequestObject{})
	assert.IsType(t, api.DeleteFriends400JSONResponse{}, resp)
}

func TestListFriendRequest_Branches(t *testing.T) {
	fh := &fakeFriendHandler{}
	s := newUserSvc(&fakeUserHandler{}, fh)
	resp, _ := s.listFriendRequest(context.Background(), api.ListFriendRequestsRequestObject{})
	assert.IsType(t, api.ListFriendRequests200JSONResponse{}, resp)

	fh.err = common.ErrInternalErr
	resp, _ = s.listFriendRequest(context.Background(), api.ListFriendRequestsRequestObject{})
	assert.IsType(t, api.ListFriendRequests500JSONResponse{}, resp)

	fh.err = common.ErrModelUnauthorized
	resp, _ = s.listFriendRequest(context.Background(), api.ListFriendRequestsRequestObject{})
	assert.IsType(t, api.ListFriendRequests401Response{}, resp)

	fh.err = errors.New("x")
	resp, _ = s.listFriendRequest(context.Background(), api.ListFriendRequestsRequestObject{})
	assert.IsType(t, api.ListFriendRequests400JSONResponse{}, resp)
}

func TestCreateFriendRequest_Branches(t *testing.T) {
	fh := &fakeFriendHandler{}
	s := newUserSvc(&fakeUserHandler{}, fh)
	resp, _ := s.createFriendRequest(context.Background(), api.CreateFriendRequestRequestObject{})
	assert.IsType(t, api.CreateFriendRequest200Response{}, resp)

	fh.err = common.ErrInternalErr
	resp, _ = s.createFriendRequest(context.Background(), api.CreateFriendRequestRequestObject{})
	assert.IsType(t, api.CreateFriendRequest500JSONResponse{}, resp)

	fh.err = common.ErrModelUnauthorized
	resp, _ = s.createFriendRequest(context.Background(), api.CreateFriendRequestRequestObject{})
	assert.IsType(t, api.CreateFriendRequest401Response{}, resp)

	fh.err = errors.New("x")
	resp, _ = s.createFriendRequest(context.Background(), api.CreateFriendRequestRequestObject{})
	assert.IsType(t, api.CreateFriendRequest400JSONResponse{}, resp)
}

func TestDeleteFriendRequest_Branches(t *testing.T) {
	fh := &fakeFriendHandler{}
	s := newUserSvc(&fakeUserHandler{}, fh)
	resp, _ := s.deleteFriendRequest(context.Background(), api.DeleteFriendRequestsRequestObject{})
	assert.IsType(t, api.DeleteFriendRequests200Response{}, resp)

	fh.err = common.ErrInternalErr
	resp, _ = s.deleteFriendRequest(context.Background(), api.DeleteFriendRequestsRequestObject{})
	assert.IsType(t, api.DeleteFriendRequests500JSONResponse{}, resp)

	fh.err = common.ErrModelUnauthorized
	resp, _ = s.deleteFriendRequest(context.Background(), api.DeleteFriendRequestsRequestObject{})
	assert.IsType(t, api.DeleteFriendRequests401Response{}, resp)

	fh.err = errors.New("x")
	resp, _ = s.deleteFriendRequest(context.Background(), api.DeleteFriendRequestsRequestObject{})
	assert.IsType(t, api.DeleteFriendRequests400JSONResponse{}, resp)
}

func TestInviteUser_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{inviteLink: "l"}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.inviteUser(context.Background(), api.InviteUserRequestObject{})
	},
		api.InviteUser200TextResponse(""), api.InviteUser500JSONResponse{},
		api.InviteUser401Response{}, api.InviteUser400JSONResponse{},
	)
}

func TestDeleteUserInvite_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.deleteUserInvite(context.Background(), api.DeleteUserInviteRequestObject{})
	},
		api.DeleteUserInvite200TextResponse(""), api.DeleteUserInvite500JSONResponse{},
		api.DeleteUserInvite401Response{}, api.DeleteUserInvite400JSONResponse{},
	)
}

func TestListUserInvite_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{userInvitesTot: 1}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.listUserInvite(context.Background(), api.GetUserInviteListRequestObject{})
	},
		api.GetUserInviteList200JSONResponse{}, api.GetUserInviteList500JSONResponse{},
		api.GetUserInviteList401Response{}, api.GetUserInviteList400JSONResponse{},
	)
}

func TestGetUserInvite_Branches(t *testing.T) {
	inv := &models.UserInvite{}
	runBranchCheck(t, &fakeUserHandler{userInvite: inv}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.getUserInvite(context.Background(), api.GetUserInviteRequestObject{})
	},
		api.GetUserInvite200JSONResponse{}, api.GetUserInvite500JSONResponse{},
		api.GetUserInvite401Response{}, api.GetUserInvite400JSONResponse{},
	)
}

func TestUpdateUserInvite_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.updateUserInvite(context.Background(), api.UpdateUserInviteRequestObject{})
	},
		api.UpdateUserInvite200TextResponse(""), api.UpdateUserInvite500JSONResponse{},
		api.UpdateUserInvite401Response{}, api.UpdateUserInvite400JSONResponse{},
	)
}

func TestSendUserInvite_Branches(t *testing.T) {
	runBranchCheck(t, &fakeUserHandler{}, &fakeFriendHandler{}, func(s *UserService) (any, error) {
		return s.sendUserInvite(context.Background(), api.SendUserInviteRequestObject{})
	},
		api.SendUserInvite200TextResponse(""), api.SendUserInvite500JSONResponse{},
		api.SendUserInvite401Response{}, api.SendUserInvite400JSONResponse{},
	)
}
