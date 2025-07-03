package user

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"errors"

	"github.com/sirupsen/logrus"
)

type friendHandlerImpl struct {
	logger *logrus.Entry
}

func newFriendHandlerImpl(logger *logrus.Entry) *friendHandlerImpl {
	return &friendHandlerImpl{
		logger: logger,
	}
}

func (h *friendHandlerImpl) List(auth interface{}, requestObject api.ListFriendRequestObject) (*models.UserFriends, error) {
	_, namespace, userID, logger := common.ParseToken(auth, "list-friend", "List friend", h.logger)
	list, err := db.GetUserFriendIDs(namespace, userID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get the user's friend IDs from db.")
		if err == db.ErrUserFriendNotExists {
			return nil, nil
		}
		return nil, common.ErrInternalErr
	}
	var friends []models.UserShortInfo
	for _, f := range list {
		log := logger.WithField("friend-id", f.String())
		friend, err := friendInfo(namespace, f)
		if err != nil {
			log.WithError(err).Errorln("Failed to friend info from db.")
			continue
		}
		friends = append(friends, *friend)
	}
	requests, err := h.getRequests(namespace, userID, nil, logger)
	if err != nil {
		return nil, err
	}
	return &models.UserFriends{
		FriendList:        &friends,
		FriendRequestList: &requests,
	}, nil
}

// Delete removes friends mutually.
func (h *friendHandlerImpl) Delete(auth interface{}, requestObject api.DeleteFriendsRequestObject) error {
	_, namespace, userID, logger := common.ParseToken(auth, "delete-friends", "Delete friends", h.logger)
	idList := types.UUIDListToIDList(requestObject.Body)
	if err := db.DeleteFriends(namespace, userID, idList); err != nil {
		logger.WithError(err).Errorln("Failed to remove friends from db.")
		return common.ErrInternalErr
	}
	return nil
}

// CreateRequest adds a friend request.
func (h *friendHandlerImpl) CreateRequest(auth interface{}, requestObject api.CreateFriendRequestRequestObject) error {
	_, namespace, requesterID, logger := common.ParseToken(auth, "create-friend-request", "Create friend requests", h.logger)
	r := requestObject.Body
	if r == nil || r.ToUserID == nil {
		logger.Warnln("Bad request params.")
		err := errors.New("missing request or to-user id")
		return common.NewBadParamsErr(err)
	}
	u, err := db.GetUserBaseInfoFast(namespace, requesterID)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get user from db.")
		return common.ErrInternalErr
	}
	requesterName := u.DisplayName
	toUserID := types.UUIDToID(*r.ToUserID)
	if db.FriendRequestExists(namespace, toUserID, requesterID) {
		return common.ErrModelFriendRequestExists
	}
	if err = db.InsertFriendRequest(namespace, requesterID, toUserID, requesterName, optional.String(r.ToUsername), optional.String(r.Note)); err != nil {
		logger.WithError(err).WithFields(logrus.Fields{
			"requester-id":   requesterID,
			"requester-name": requesterName,
		}).Errorln("Failed to insert friend request to db.")
		return common.ErrInternalErr
	}
	return nil
}

// ListRequest lists the friend request.
func (h *friendHandlerImpl) ListRequests(auth interface{}, requestObject api.ListFriendRequestsRequestObject) (models.FriendRequestList, error) {
	_, namespace, userID, logger := common.ParseToken(auth, "list-friend-request", "List friend requests", h.logger)
	return h.getRequests(namespace, userID, requestObject.Params.Contain, logger)
}

// Update requests' note or approval state.
// Only to-user or admin can change state
// Either from-user-id or to-user-id must be set for non-admin so that we can
// confirm if user is authorized to update the request.
func (h *friendHandlerImpl) UpdateRequests(auth interface{}, requestObject api.UpdateFriendRequestsRequestObject) error {
	token, namespace, userID, logger := common.ParseToken(auth, "update-friend-requests", "Update friend requests", h.logger)
	r := requestObject.Body
	if r == nil ||
		(r.Update.Note == nil && r.Update.State == nil) ||
		(!token.IsAdminUser && (r.Update.FromUserID == nil && r.Update.ToUserID == nil)) {
		err := errors.New("missing request input or update or from and to use id")
		logger.WithError(err).Debugln("Bad parameters.")
		return common.NewBadParamsErr(err)
	}
	var (
		up         = &r.Update
		notAdmin   = !token.IsAdminUser
		toUserID   *types.UserID
		fromUserID *types.UserID
	)
	if up.FromUserID != nil {
		fromUserID = types.UUIDPToID(up.FromUserID)
	}
	if up.ToUserID != nil {
		toUserID = types.UUIDPToID(up.ToUserID)
	}
	if notAdmin {
		// Need to set from or to user ID for non-admin users.
		if (up.FromUserID != nil && userID.UUID() != *up.FromUserID) || 
			(up.ToUserID != nil && userID.UUID() != *up.ToUserID) {
			return common.ErrModelUnauthorized
		}
		// Only to user ID can change state.
		if up.State != nil {
			toUserID = &userID
		} else {
			// Note only change. Must set the from or to user id.
			if (up.FromUserID == nil && up.ToUserID == nil) {
				err := errors.New("missing from and to user id")
				return common.NewBadParamsErr(err)
			}
		}
	}

	update := types.FriendRequest{
		Note:  optional.String(r.Update.Note),
		State: types.ApprovalState(*r.Update.State),
	}

	idList := types.UUIDListToIDList(&r.IDList)
	if err := db.UpdateFriendRequests(namespace, fromUserID, toUserID, idList, update); err != nil {
		logger.WithError(err).Errorln("Failed to update friend request.")
		return common.ErrInternalErr
	}
	return nil
}

// DeleteRequests removes a list of friend requests.
func (h *friendHandlerImpl) DeleteRequests(auth interface{}, requestObject api.DeleteFriendRequestsRequestObject) error {
	_, namespace, userID, logger := common.ParseToken(auth, "delete-friend-request", "Delete friend requests", h.logger)
	idList := types.UUIDListToIDList(requestObject.Body)
	if err := db.DeleteFriendRequests(namespace, userID, idList); err != nil {
		logger.WithError(err).Errorln("Failed to delete request from db.")
		return common.ErrInternalErr
	}
	return nil
}

func (h *friendHandlerImpl) getRequests(namespace string, userID types.UserID, contain *string, logger *logrus.Entry) (list []models.FriendRequest, err error) {
	requests, err := db.GetFriendRequests(namespace, userID, nil, contain)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get the friend request from db.")
		if err == db.ErrUserFriendRequestNotExists {
			return nil, nil
		}
		return nil, common.ErrInternalErr
	}
	for _, r := range requests {
		list = append(list, *r.ToModel())
	}
	return
}

func friendInfo(namespace string, friendID types.UserID) (*models.UserShortInfo, error) {
	userBaseInfo, err := db.GetUserBaseInfoFast(namespace, friendID)
	if err != nil {
		return nil, err
	}
	return &models.UserShortInfo{
		UserID:        friendID.UUID(),
		DisplayName:   userBaseInfo.DisplayName,
		Email:         optional.CopyStringP(userBaseInfo.Email),
		Phone:         optional.CopyStringP(userBaseInfo.Mobile),
		ProfilePicURL: optional.StringP(userBaseInfo.ProfilePicURL),
	}, nil
}
