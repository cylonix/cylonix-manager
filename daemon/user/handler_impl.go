// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package user

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/fwconfig"
	"cylonix/sase/pkg/metrics"
	"cylonix/sase/pkg/optional"
	"cylonix/sase/pkg/sendmail"
	"cylonix/sase/pkg/vpn"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/cylonix/utils"
	kc "github.com/cylonix/utils/keycloak"
	ulog "github.com/cylonix/utils/log"

	"github.com/sirupsen/logrus"
)

type handlerImpl struct {
	fwService fwconfig.ConfigService
	logger    *logrus.Entry
}

func newHandlerImpl(fwService fwconfig.ConfigService, logger *logrus.Entry) *handlerImpl {
	return &handlerImpl{
		fwService: fwService,
		logger:    logger,
	}
}

func (h *handlerImpl) parseToken(
	auth interface{}, caller, description string,
) (*utils.UserTokenData, string, types.UserID, *logrus.Entry) {
	return common.ParseToken(auth, caller, description, h.logger)
}

// GetUserList gets the list of sase users base on various filters, sort and paging
// options. To get the user of a specific ID, just pass in the single user id
// as the id-list.
//
// GetUserList returns common.ErrModelUserNotExists if there is no match.
func (h *handlerImpl) GetUserList(auth interface{}, requestObject api.GetUserListRequestObject) (*models.UserList, error) {
	token, namespace, userID, logger := h.parseToken(auth, "get-user", "Get user request")

	idList := types.UUIDListToIDList(requestObject.Body)
	params := requestObject.Params
	// Only admin user can get other user's information.
	if token == nil || !token.IsAdminUser {
		if len(idList) != 1 || idList[0] != userID {
			return nil, common.ErrModelUnauthorized
		}
	}

	// Don't include devices et al if WithDetails is not set.
	withDetails := false
	if params.WithDetails != nil {
		withDetails = *params.WithDetails
	}

	var total int64
	var err error
	var userList []*types.User

	if len(idList) == 1 {
		// Single user ID fetch does not support all other options.
		targetUserID := idList[0]
		if userID != targetUserID {
			logger = logger.WithField("target-user-id", targetUserID.String())
		}
		user, e := db.GetUserFast(namespace, targetUserID, withDetails)
		total = 1
		userList = []*types.User{user}
		err = e
	} else {
		var namespaceP *string
		if !token.IsSysAdmin {
			namespaceP = &namespace
		}
		userList, total, err = db.GetUserList(namespaceP,
			params.FilterBy, params.FilterValue, nil,
			params.SortBy, params.SortDesc, nil, idList, params.Page,
			params.PageSize,
		)
	}
	if err != nil {
		if errors.Is(err, db.ErrUserNotExists) {
			return nil, common.ErrModelUserNotExists
		}
		logger.WithError(err).Infoln("Failed to get user from db.")
		return nil, common.ErrInternalErr
	}
	users := []models.User{}
	for _, u := range userList {
		users = append(users, *u.ToModel())
	}
	return &models.UserList{
		Total: int(total),
		Users: users,
	}, nil
}

func isAdminOnlyUpdate(u *models.UserUpdateInfo) bool {
	return (u.AddLabels != nil && len(*u.AddLabels) > 0) ||
		(u.DelLabels != nil && len(*u.DelLabels) > 0) ||
		u.AddRole != nil || u.DelRole != nil ||
		u.MeshVpnMode != nil ||
		u.AdvertiseDefaultRoute != nil ||
		u.WgEnabled != nil ||
		u.AutoAcceptRoutes != nil ||
		u.AutoApproveDevice != nil
}

func isCriticalUpdate(u *models.UserUpdateInfo) bool {
	return u.AddEmail != nil || u.DelEmail != nil ||
		u.AddPhone != nil || u.DelPhone != nil ||
		optional.Bool(u.SetUsername) || optional.Bool(u.SetPassword)
}

func (h *handlerImpl) addEmailOrPhone(
	login *types.UserLogin, isPhone bool,
	approverID types.UserID, approverName string,
	update *models.UserUpdateInfo, ub *types.UserBaseInfo, logger *logrus.Entry,
) error {
	if err := h.addUserLoginIfNotExists(login, approverID, approverName); err != nil {
		logger.WithError(err).Warnln("Add email/phone failed.")
		if errors.Is(err, db.ErrUserLoginUsedByOtherUser) {
			if isPhone {
				return common.ErrModelPhoneRegistered
			}
			return common.ErrModelEmailRegistered
		}
		return common.ErrInternalErr
	}
	if !isPhone && ub.Email != nil {
		// Remove add-email to skip user base info email update.
		*update.AddEmail = ""
	}
	if isPhone && ub.Mobile != nil {
		// Remove add-phone to skip user base info phone update.
		*update.AddPhone = ""
	}
	return nil
}
func (h *handlerImpl) delEmailOrPhone(
	namespace string, userID types.UserID, loginName string, isPhone bool,
	update *models.UserUpdateInfo, ub *types.UserBaseInfo, logger *logrus.Entry,
) error {
	if err := db.DeleteUserLoginCheckUserID(namespace, userID, loginName); err != nil {
		logger.WithError(err).Warnln("Delete email/phone failed.")
	}
	if !isPhone && loginName == optional.String(ub.Email) ||
		loginName == optional.String(ub.Mobile) {
		// Find a back up email to set in base info.
		newEmailOrPhone, err := db.GetUserEmailOrPhone(namespace, userID, isPhone)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get user email/phone login.")
			return common.ErrInternalErr
		}
		if newEmailOrPhone != nil {
			if isPhone {
				*update.AddPhone = *newEmailOrPhone
			} else {
				*update.AddEmail = *newEmailOrPhone
			}
		}
	}
	return nil
}

func (h *handlerImpl) addUserLoginIfNotExists(login *types.UserLogin, approverID types.UserID, approverName string) error {
	namespace, loginName := login.Namespace, login.LoginName
	if err := db.CreateUserLogin(login); err != nil {
		if !errors.Is(err, db.ErrUserLoginExists) {
			return err
		}
		existing, err := db.GetUserLoginByLoginName(namespace, loginName)
		if err != nil {
			return err
		}
		if existing.UserID != login.UserID {
			return db.ErrUserLoginUsedByOtherUser
		}
		return nil
	}
	r, err := db.GetUserApprovalByLoginName(namespace, login.LoginName)
	if err != nil {
		// Skip updating approval if there is none exists.
		if errors.Is(err, db.ErrUserApprovalNotExists) {
			return nil
		}
		return err
	}
	if err := db.SetUserApprovalState(namespace, r.ID, approverID, approverName, "", models.ApprovalStateApproved); err != nil {
		if !errors.Is(err, db.ErrUserApprovalNotExists) {
			return err
		}
	}
	return nil
}

// UpdateUser updates a single existing user.
// Only admin user can update other user.
// Non-admin user needs to have do otp verification for certain changes.
// For login related changes including username, password, email, phone et al,
// we will create such logins even if it was meant to be logins just so that it
// won't be used as another user's login.
func (h *handlerImpl) UpdateUser(auth interface{}, requestObject api.UpdateUserRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "update-user", "Update user request")
	approverID, approverName := types.NilID, ""
	if token.IsAdminUser {
		approverID = userID
		approverName = token.Username
	}
	ofNamespace := requestObject.Params.Namespace
	if ofNamespace == "" {
		ofNamespace = namespace
	} else if namespace != ofNamespace {
		if !token.IsSysAdmin {
			logger.
				WithField("of-namespace", ofNamespace).
				Warnln("Non-sysadmin user trying to update user in other namespace.")
			return common.ErrModelUnauthorized
		}
		namespace = ofNamespace
	}
	if namespace == "" {
		logger.Errorln("Missing namespace.")
		return common.NewBadParamsErr(errors.New("missing namespace"))
	}

	if userID.String() != requestObject.UserID {
		logger = logger.WithField("target-user-id", requestObject.UserID)
		if !token.IsAdminUser {
			logger.Warnln("Non-admin can't change update other user.")
			return common.ErrModelUnauthorized
		}
		id, err := types.ParseID(requestObject.UserID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to parse user ID.")
			return common.NewBadParamsErr(err)
		}
		userID = id
	}

	update := requestObject.Body
	if !token.IsAdminUser {
		if isAdminOnlyUpdate(update) {
			if !utils.IsDefaultNamespace(namespace) {
				logger.Warnln("Some setting require admin access.")
				return common.ErrModelUnauthorized
			}
			domain, err := getNetworkDomainOfAdmin(userID)
			if err != nil {
				logger.WithError(err).Errorln("Failed to get network domain.")
				return common.ErrInternalErr
			}
			if domain == nil || *domain != "" {
				logger.Warnln("Non-admin user trying to update user admin scoped changes.")
				return common.ErrModelUnauthorized
			}
		}
		if isCriticalUpdate(update) {
			if valid, err := common.CheckOneTimeCode(update.OneTimeCodeCheck); err != nil || !valid {
				if err != nil {
					logger.WithError(err).Errorln("Failed to verify the OTP code.")
					return common.ErrInternalErr
				}
				logger.Warnln("OTP code invalid.")
				return common.ErrModelUnauthorized
			}
		}
	}

	su, err := db.GetUserFast(namespace, userID, false)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get user from db.")
		return common.ErrInternalErr
	}
	ub := &su.UserBaseInfo

	// TODO: move all the updates to be done in db for rollbacks.
	if update.SetUsername != nil && *update.SetUsername && update.Username != nil && *update.Username != "" {
		logger = logger.WithField(ulog.Username, update.Username)
		if update.Password == nil || *update.Password == "" || update.SetPassword == nil || !*update.SetPassword {
			err = common.NewBadParamsErr(err)
			logger.WithError(err).Errorln("Update username must also reset password.")
			return err
		}
		login := &types.UserLogin{
			Namespace:  namespace,
			UserID:     userID,
			LoginType:  types.LoginTypeUsername,
			LoginName:  *update.Username,
			Credential: *update.Password,
		}
		current, err := db.GetUserLoginByUserIDAndLoginType(namespace, userID, types.LoginTypeUsername)
		if err != nil {
			if !errors.Is(err, db.ErrUserLoginNotExists) {
				logger.WithError(err).Errorln("Failed to get current user login.")
				return common.ErrInternalErr
			}
			// Admin user username login must have exists already.
			if optional.Bool(su.IsAdminUser) {
				logger.WithError(err).Errorln("Admin username login does not exist.")
				return common.ErrInternalErr
			}
			// Login not yet exists for non-admin user. Add login.
			if err := h.addUserLoginIfNotExists(login, approverID, approverName); err != nil {
				logger.WithError(err).Warnln("Create new username login failed.")
				if errors.Is(err, db.ErrUserLoginUsedByOtherUser) {
					return common.ErrModelUsernameRegistered
				}
				return common.ErrInternalErr
			}
			// Add login success. Fall through to process other updates.
		} else {
			err = h.setUsernamePassword(
				namespace, *update.Username, optional.String(update.Password),
				current.LoginName, models.LoginTypeUsername,
				logger,
			)
			if err != nil {
				return err
			}
		}
	} else if update.SetPassword != nil && *update.SetPassword {
		loginName := ""
		loginType := models.LoginTypeUsername
		if update.SetPasswordForEmail != nil && *update.SetPasswordForEmail != "" {
			loginName = *update.SetPasswordForEmail
			loginType = models.LoginTypeEmail
		}
		err = h.setUsernamePassword(
			namespace, "", optional.String(update.Password),
			loginName, loginType, logger,
		)
		if err != nil {
			return err
		}
	}
	if optional.String(update.AddEmail) != "" {
		logger = logger.WithField("add-email", update.AddEmail)
		login := types.NewEmailLogin(namespace, *update.AddEmail, "", "")
		login.UserID = userID
		if err := h.addEmailOrPhone(login, false, approverID, approverName, update, ub, logger); err != nil {
			return err
		}
	}
	if optional.String(update.AddPhone) != "" {
		logger = logger.WithField("add-phone", update.AddPhone)
		login := types.NewPhoneLogin(namespace, *update.AddPhone, "", "")
		login.UserID = userID
		err := h.addEmailOrPhone(login, true, approverID, approverName, update, ub, logger)
		if err != nil {
			return err
		}
	}
	if optional.String(update.DelEmail) != "" {
		logger = logger.WithField("del-email", update.DelEmail)
		err := h.delEmailOrPhone(namespace, userID, optional.String(update.DelEmail), false, update, ub, logger)
		if err != nil {
			return err
		}
	}
	if optional.String(update.DelPhone) != "" {
		logger = logger.WithField("del-phone", update.DelPhone)
		err := h.delEmailOrPhone(namespace, userID, optional.String(update.DelPhone), true, update, ub, logger)
		if err != nil {
			return err
		}
	}
	if update.AddRole != nil {
		if err := db.AddUserRole(namespace, userID, string(*update.AddRole)); err != nil {
			logger.
				WithField("role", *update.AddRole).
				WithError(err).
				Errorln("Failed to add user role.")
			return common.ErrInternalErr
		}
	}
	if update.DelRole != nil {
		if err := db.DelUserRole(namespace, userID, string(*update.DelRole)); err != nil {
			logger.
				WithField("role", *update.DelRole).
				WithError(err).
				Errorln("Failed to del user role.")
			return common.ErrInternalErr
		}
	}
	if err := db.UpdateUser(namespace, userID, update); err != nil {
		logger.WithError(err).Errorln("Failed")
		return common.ErrInternalErr
	}
	return nil
}

// PostUser adds a new user directly without going through the approval process.
// It can only be requested by an admin user. For non-admin user or community
// user, please refer to the RegisterUser function.
func (h *handlerImpl) PostUser(auth interface{}, requestObject api.PostUserRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "post-user", "Post user request")
	if !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}

	// Sysadmin can add an admin user for other namespace.
	params := requestObject.Params
	namespaceParam := optional.String(params.Namespace)
	if namespaceParam != "" && namespaceParam != namespace {
		if !token.IsSysAdmin {
			return common.ErrModelUnauthorized
		}
		namespace = namespaceParam
	}

	// Default namespace to "default" if adding by sysadmin
	// To add a sysadmin by another sysadmin, namespaceParam must be set.
	if namespaceParam == "" && token.IsSysAdmin {
		namespace = utils.DefaultNamespace
	}

	_, err := db.GetTenantConfigByNamespace(namespace)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get tenant information.")
		return common.ErrInternalErr
	}

	// Must have one login method specified.
	user := requestObject.Body
	if user == nil || len(user.Logins) <= 0 {
		logger.WithError(db.ErrUserLoginNotExists).Errorln("Bad params.")
		return common.NewBadParamsErr(err)
	}
	var loginSlice types.UserLoginSlice
	loginSlice = loginSlice.FromModel(namespace, user.Logins)

	loginNames := []string{}
	for _, l := range user.Logins {
		loginNames = append(loginNames, l.Login)
	}
	r := &models.UserApprovalInfo{
		Namespace: namespace,
		Login:     user.Logins[0],
		Email:     &user.Email,
		Phone:     &user.Phone,
		Roles:     &user.Roles,
		IsAdmin:   user.IsAdmin,
	}
	approval, err := newUserApproval(r, loginNames, userID, token.Username, logger, true /* ok if registered */)
	if err != nil {
		logger.WithError(err).Errorln("Failed to create user approval record.")
		return err
	}
	if approval.Namespace != namespace && !token.IsSysAdmin {
		logger.
			WithField("namespace", namespace).
			Warnln("Non-sysadmin user trying to add user in other namespace.")
		return common.ErrModelUnauthorized
	}
	if approval.State != types.ApprovalStateApproved {
		err = db.SetUserApprovalState(namespace, approval.ID, userID, token.Username, "", models.ApprovalStateApproved)
		if err != nil {
			logger.WithError(err).Errorln("Failed to set user approval record approved.")
			return common.ErrInternalErr
		}
	}

	// Set network domain if not specified
	networkDomain := optional.String(user.NetworkDomain)
	if networkDomain == "" {
		if token.IsSysAdmin {
			networkDomain, err = generateNetworkDomain(logger, false /* does not want words based */)
			if err != nil {
				logger.WithError(err).Errorln("Failed to generate network domain.")
				return common.ErrInternalErr
			}
		} else {
			fromUser := types.User{}
			if err := db.GetUser(userID, fromUser); err != nil {
				logger.WithError(err).Errorln("Failed to get user.")
				return common.ErrInternalErr
			}
			networkDomain = optional.String(fromUser.NetworkDomain)
		}
	}

	newUser, err := db.AddUser(
		namespace, user.Email, user.Phone, user.DisplayName, loginSlice,
		user.Roles, nil, nil, &networkDomain, nil,
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to create new user in db.")
		if errors.Is(err, db.ErrMaxUserLimitReached) ||
			errors.Is(err, db.ErrBadParams) ||
			errors.Is(err, db.ErrTenantConfigNotFound) {
			return common.NewBadParamsErr(err)
		}
		return common.ErrInternalErr
	}
	login, newErr := db.GetUserLogin(namespace, newUser.UserLogins[0].ID)
	if newErr != nil {
		logger.WithError(newErr).Errorln("Failed to get the newly created login.")
		return common.ErrInternalErr
	}
	s, _ := json.Marshal(login)
	logger.WithField("login", string(s)).Debugln("Login created.")

	return nil
}

func (h *handlerImpl) SearchUser(auth interface{}, requestObject api.SearchUserRequestObject) (*models.UserShortInfo, error) {
	token, namespace, _, logger := h.parseToken(auth, "search-user", "Search user request")
	if token == nil || token.Token == "" {
		logger.Debugln("invalid token")
		return nil, common.ErrModelUnauthorized
	}
	params := requestObject.Params
	u, err := db.SearchUser(namespace, params.Username, params.Email, params.PhoneNum)
	if err != nil {
		if errors.Is(err, db.ErrUserNotExists) {
			return &models.UserShortInfo{}, nil
		}
		logger.WithError(err).Errorln("Failed to search.")
		if errors.Is(err, db.ErrBadParams) {
			return nil, common.NewBadParamsErr(err)
		}
		return nil, common.ErrInternalErr
	}
	return &models.UserShortInfo{
		UserID:        u.ID.UUID(),
		DisplayName:   u.UserBaseInfo.DisplayName,
		Email:         params.Email,
		Phone:         params.PhoneNum,
		ProfilePicURL: optional.StringP(u.UserBaseInfo.ProfilePicURL),
	}, nil
}

func (h *handlerImpl) DeleteUsers(auth interface{}, requestObject api.DeleteUsersRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "delete-user", "Delete user request")
	ofNamespace := requestObject.Params.Namespace
	if ofNamespace != "" {
		if ofNamespace != namespace && !token.IsSysAdmin {
			logger.Warnln("Non-sysadmin user trying to delete user in other namespace.")
			return common.ErrModelUnauthorized
		}
		logger = logger.WithField(ulog.Namespace, ofNamespace)
	} else {
		ofNamespace = namespace
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	tx, err := db.BeginTransaction()
	if err != nil {
		logger.WithError(err).Errorln("Failed to begin transaction.")
		return common.ErrInternalErr
	}
	defer tx.Rollback()

	requstor, err := db.GetUserFast(ofNamespace, userID, false)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get user.")
		return common.ErrInternalErr
	}
	isNetworkOwner := requstor.IsNetworkOwner()
	ofNetwork := optional.String(requstor.NetworkDomain)
	if isNetworkOwner {
		userIDsOfNetwork, err := db.GetUserIDList(tx, ofNamespace, &ofNetwork)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get network owner ID.")
			return common.ErrInternalErr
		}
		if len(idList) == 1 && idList[0] == userID {
			logger.Infoln("Network owner deleting self, will delete all users in the network domain.")
			idList = userIDsOfNetwork
		}
	}
	var cbList []func() error

	for _, uID := range idList {
		log := logger.WithField("target-user-id", uID.String())
		user, err := db.GetUserFast(ofNamespace, uID, false)
		if err != nil {
			if errors.Is(err, db.ErrUserNotExists) {
				log.Warnln("User does not exist.")
				continue // Skip non-existing user.
			}
			log.WithError(err).Errorln("Get user failed")
			return common.ErrInternalErr
		}
		// Network owner can delete users in the same network domain.
		// Namespace admin can delete non-admin users in the same namespace.
		if userID != uID {
			network := optional.String(user.NetworkDomain)
			if network == "" || network != ofNetwork || !isNetworkOwner {
				if !token.IsAdminUser {
					return common.ErrModelUnauthorized
				}
				if optional.Bool(user.IsAdminUser) {
					log.Warnln("Admin user cannot be deleted.")
					err = fmt.Errorf(
						"admin user %s cannot be deleted (demote to non-admin user first)",
						user.UserBaseInfo.DisplayName,
					)
					return common.NewBadParamsErr(err)
				}
			}
		}
		if optional.Bool(user.IsSysAdmin) {
			log.Warnln("Sysadmin user cannot be deleted.")
			err = fmt.Errorf(
				"sysadmin user %s cannot be deleted.", user.UserBaseInfo.DisplayName,
			)
			return common.NewBadParamsErr(err)
		}
		deviceIDList, err := db.GetUserDeviceIDList(ofNamespace, uID)
		if err != nil {
			if !errors.Is(err, db.ErrDeviceNotExists) {
				log.WithError(err).Warnln("Get user devices failed")
				return common.ErrInternalErr
			}
		}
		for _, dID := range deviceIDList {
			cb, err := common.DeleteDeviceInAllForPG(tx, ofNamespace, uID, dID, h.fwService)
			if err != nil {
				log.WithError(err).Warnln("Delete device in all failed")
				return common.ErrInternalErr
			}
			cbList = append(cbList, cb)
		}
		logins, err := db.GetUserLoginByUserID(ofNamespace, uID)
		if err != nil {
			log.WithError(err).Warnln("Get user logins failed")
			return common.ErrInternalErr
		}
		log.WithField("login-count", len(logins)).Debugln("Deleting user approvals.")
		for _, login := range logins {
			if err := db.DeleteUserApprovalByLoginName(tx, ofNamespace, login.LoginName); err != nil {
				log.WithField("login-name", login.LoginName).
					WithError(err).Errorln("Delete user approval failed")
				return common.ErrInternalErr
			}
			log.WithField("login-name", login.LoginName).Debugln("User approval deleted.")
		}
		if err := db.DeleteUser(tx, ofNamespace, uID); err != nil {
			if !errors.Is(err, db.ErrUserNotExists) {
				log.WithError(err).Errorln("Delete user in all db failed")
				return common.ErrInternalErr
			}
		}
		cbList = append(cbList, func() error {
			return vpn.DeleteHsUser(ofNamespace, optional.String(user.NetworkDomain), uID)
		})
		log.Infoln("Deletion scheduled.")
	}
	if err := tx.Commit().Error; err != nil {
		logger.WithError(err).Errorln("Failed to commit transaction.")
		return common.ErrInternalErr
	}
	hasCallbackError := false
	for _, cb := range cbList {
		if err := cb(); err != nil {
			logger.WithError(err).Errorln("Failed to execute callback.")
			hasCallbackError = true
			// Ignore callback errors
		}
	}
	logger.WithField("has-callback-error", hasCallbackError).Infoln("User deleted.")
	return nil
}

// RegisterUser adds a user approval approval record.
func (h *handlerImpl) RegisterUser(auth interface{}, requestObject api.RegisterUserRequestObject) error {
	r := requestObject.Body
	if r == nil {
		err := errors.New("missing registration input")
		return common.NewBadParamsErr(err)
	}
	namespace := r.Namespace
	logger := h.logger.WithFields(logrus.Fields{
		ulog.Handle:    "register-user",
		ulog.Namespace: namespace,
	})
	token, ok := auth.(*utils.UserTokenData)
	if auth == nil || !ok || !token.IsAdminUser {
		if valid, err := common.CheckSmsCode(optional.String(r.Phone), r.Code); err != nil || !valid {
			if err != nil {
				logger.WithError(err).Errorln("Failed to check sms code.")
				return common.ErrInternalErr
			}
			return common.ErrModelInvalidSmsCode
		}
	}
	common.LogWithLongDashes("Register user", logger)
	_, err := newUserApproval(r, []string{r.Login.Login}, types.NilID, "", logger, false /* not ok if registered */)
	return err
}

func (h *handlerImpl) ApprovalRecords(auth interface{}, requestObject api.GetUserApprovalsRequestObject) (int, []models.UserApprovalInfo, error) {
	token, namespace, _, logger := h.parseToken(auth, "list-user-approval-records", "List user approval records")
	params := requestObject.Params

	// Only admin user or pending approval user can read approval records.
	if token != nil && !token.IsAdminUser {
		return 0, nil, common.ErrModelUnauthorized
	}

	ofNamespace := optional.String(params.Namespace)
	if ofNamespace != "" {
		if namespace != "" && namespace != ofNamespace {
			if !token.IsSysAdmin {
				logger.WithField("of-namespace", ofNamespace).
					Warnln("Non-sysadmin user trying to get approval records in other namespace.")
				return 0, nil, common.ErrModelUnauthorized
			}
		}
		logger = logger.WithField(ulog.Namespace, ofNamespace)
	} else {
		if !token.IsSysAdmin {
			ofNamespace = namespace
		}
	}
	idList := types.UUIDListToIDList(requestObject.Body)

	// Pending approval user needs to authenticate with email/phone and can only
	// fetch its own status. Oauth fetch can be done through the login API.
	if auth == nil || token == nil {
		if params.Code == nil || *params.Code == "" ||
			(params.Email == nil || *params.Email == "") &&
				(params.PhoneNum == nil || *params.PhoneNum == "") {
			err := errors.New("missing code validation input")
			return 0, nil, common.NewBadParamsErr(err)
		}
		if len(idList) > 0 {
			return 0, nil, common.ErrModelUnauthorized
		}
		valid, err := common.CheckOneTimeCodeWithEmailOrPhoneP(params.Email, params.PhoneNum, params.Code)
		if err != nil || !valid {
			if err != nil {
				logger.WithError(err).Errorln("Failed to check code.")
				return 0, nil, common.ErrInternalErr
			}
			return 0, nil, common.ErrModelInvalidSmsCode
		}

		var loginName string
		if params.Email != nil {
			loginName = *params.Email
		} else {
			loginName = *params.PhoneNum
		}
		approval, err := db.GetUserApprovalByLoginName(namespace, loginName)
		if err != nil {
			logger.WithField("login-name", loginName).WithError(err).Errorln("Failed.")
			return 0, nil, common.ErrInternalErr
		}
		return 1, []models.UserApprovalInfo{*approval.ToModel()}, nil
	}
	total, list, err := db.ListUserApproval(
		ofNamespace,
		params.IsAdmin, params.ApprovalState,
		params.Contain, params.FilterBy, params.FilterValue,
		params.SortBy, params.SortDesc,
		idList, params.Page, params.PageSize,
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get user approval info.")
		return 0, nil, common.ErrInternalErr
	}
	return total, types.UserApprovalSlice(list).ToModel(), nil
}

// DeleteApprovals deletes the user approval records base on the list of ID.
// Non-existing ID is not an error. It will simply be skipped.
func (h *handlerImpl) DeleteApprovals(auth interface{}, requestObject api.DeleteUserApprovalsRequestObject) error {
	token, namespace, _, logger := h.parseToken(auth, "delete-approval-records", "Delete approval records")

	// Only admin user can delete approval records.
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	if err := db.DeleteUserApprovals(namespace, idList); err != nil {
		logger.WithError(err).Errorln("Failed")
		return common.ErrInternalErr
	}
	return nil
}
func (h *handlerImpl) UpdateApprovals(auth interface{}, requestObject api.UpdateUserApprovalRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "update-approval-records", "Update approval records")

	// Only admin user can update approval records.
	if token == nil || !token.IsAdminUser {
		return common.ErrModelUnauthorized
	}
	params := requestObject.Body
	if params == nil {
		err := errors.New("missing approval params")
		logger.WithError(err).Errorln("Failed.")
		return common.NewBadParamsErr(err)
	}

	idList := types.UUIDListToIDList(&params.IDList)
	state, note := params.SetState, params.Note
	for _, id := range idList {
		log := logger.WithField("login-id", id.String())
		if id == types.NilID {
			log.Warnln("Included empty approval id.")
			continue
		}
		err := db.SetUserApprovalState(namespace, id, userID, token.Username, note, state)
		if err != nil {
			log.WithError(err).Errorln("Failed to update approval state.")
			if errors.Is(err, db.ErrUserApprovalNotExists) {
				return common.NewBadParamsErr(err)
			}
			return common.ErrInternalErr
		}
		if state == models.ApprovalStateApproved {
			if err = createNewUserFromRegistration(namespace, id, logger); err != nil {
				log.WithError(err).Errorln("Failed to add newly approved user.")
				if errors.Is(err, db.ErrMaxUserLimitReached) ||
					errors.Is(err, db.ErrBadParams) ||
					errors.Is(err, db.ErrTenantConfigNotFound) {
					return common.NewBadParamsErr(err)
				}
				return common.ErrInternalErr
			}
		}
	}
	return nil
}

// IsUsernameAvailable checks if a username aka login name already exists.
// Note a display name can be the same among different users. A username
// only needs to be unique as a login username.
// Note, this is an API without auth token, don't log anything above debug.
func (h *handlerImpl) IsUsernameAvailable(requestObject api.CheckUsernameRequestObject) (bool, error) {
	namespace := utils.DefaultNamespace
	params := requestObject.Params
	if params.Namespace != nil && *params.Namespace != "" {
		namespace = *params.Namespace
	}
	return db.UserLoginExists(namespace, []string{params.Username})
}

// Change password changes the password of a user of the same namespace by
// the user itself or an admin user. The password can be auto-generated
// if the new password is not specified. Change the pasword of a user
// in a different namespae is not allowed.
func (h *handlerImpl) ChangePassword(auth interface{}, requestObject api.ChangePasswordRequestObject) (*string, error) {
	token, namespace, userID, logger := h.parseToken(auth, "change-password", "Change password")
	if namespace == utils.SysAdminNamespace {
		if !token.IsSysAdmin {
			logger.Debugln("non-sysadmin changing admin user password directly in admin namespace.")
			return nil, common.ErrModelUnauthorized
		}
	}
	if userID.String() != requestObject.UserID && requestObject.UserID != "" {
		if !token.IsAdminUser {
			logger.WithError(common.ErrModelUnauthorized).Warnln("Unauthorized.")
			return nil, common.ErrModelUnauthorized
		}
		logger = logger.WithField("target-user-id", requestObject.UserID)
		id, err := types.ParseID(requestObject.UserID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to parse user ID.")
			return nil, common.NewBadParamsErr(err)
		}
		userID = id
	} else {
		logger.Warnln("resetting own password.")
	}
	var (
		err      error
		c        = requestObject.Body
		params   = requestObject.Params
		password = optional.String(c.NewPassword)
	)
	if password == "" {
		if password, err = generatePassword(); err != nil {
			logger.WithError(err).Errorln("Failed to generate new password.")
			return nil, common.ErrInternalErr
		}
		logger.Debugln("new password auto-generated.")
	}
	loginType := models.LoginTypeUsername
	if c.LoginType != nil {
		loginType = *c.LoginType
	}

	// Code verification is required for non-admin users.
	if !token.IsAdminUser {
		_, err := common.CheckUserOneTimeCode(namespace, userID, params.Code, params.Email, params.PhoneNum)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get user from db.")
			return nil, common.ErrInternalErr
		}
	}
	ofNamespace := namespace
	if token.IsSysAdmin {
		ofNamespace = ""
	}

	current, err := db.GetUserLoginByUserIDAndLoginType(ofNamespace, userID, types.LoginTypeUsername)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get current login from db.")
		return nil, common.ErrInternalErr
	}

	if err = h.setUsernamePassword(
		current.Namespace, "", password, current.LoginName, loginType,
		logger,
	); err != nil {
		return nil, err
	}
	return &password, nil
}

func (h *handlerImpl) setUsernamePassword(
	namespace, username, password, loginName string,
	mLoginType models.LoginType, logger *logrus.Entry,
) error {
	loginType := types.LoginType(mLoginType)
	if loginType == types.LoginTypeEmail {
		if loginName == "" {
			return common.ErrModelBadUserInfo
		}
	}

	if password != "" && !validatePassword(password) {
		logger.Warnln("Invalid new password.")
		return common.ErrModelPasswordPolicyNotMet
	}

	login, err := db.GetUserLoginByLoginName(namespace, loginName)
	if err != nil {
		if errors.Is(err, db.ErrUserLoginNotExists) {
			logger.WithError(err).Warnln("Failed to get user login.")
			return common.ErrModelBadUserInfo
		}
		logger.WithError(err).Errorln("Failed to get user login.")
		return common.ErrInternalErr
	}
	if login.LoginName == username {
		err = common.ErrModelSameUsername
		logger.WithError(err).Errorln("Failed to set username.")
		return err
	}

	// Update the password in user login.
	// DB will check and save the bcrypt hashed raw password.
	if err := db.UpdateLoginUsernamePassword(login, username, password); err != nil {
		logger.WithError(err).Errorln("Update username password in database failed.")
		if errors.Is(err, db.ErrInvalidLoginType) {
			return common.NewBadParamsErr(err)
		}
		if errors.Is(err, db.ErrSamePassword) {
			return common.ErrModelSamePassword
		}
		if errors.Is(err, db.ErrInvalidPasswordHistory) {
			return common.ErrModelInvalidPasswordHistory
		}
		return common.ErrInternalErr
	}

	return nil
}

// Open access for this API. Don't log above info.
func (h *handlerImpl) SendUsername(requestObject api.SendUsernameRequestObject) error {
	params := requestObject.Params
	email, namespace := params.Email, params.Namespace
	if email == nil || *email == "" || namespace == nil || *namespace == "" {
		return db.ErrBadParams
	}
	logger := h.logger.WithField(ulog.Handle, "send-username").WithField(ulog.Namespace, *namespace)
	username, err := db.GetUsernameByEmail(*namespace, *email)
	if err != nil {
		if errors.Is(err, db.ErrUserNotExists) || errors.Is(err, db.ErrUserLoginNotExists) {
			return nil
		}
		logger.WithError(err).Errorln("Failed to get user base on email.")
		return common.ErrInternalErr
	}

	s := "Here is your username. If you have not requested this please " +
		"contact your administrator or reply to this email directly."
	msg := fmt.Sprintf("<p>%v</p><h3 style=\"text-align:center;\">%v</h3>", s, username)
	if err := sendmail.SendEmail([]string{*email}, "Your username", msg); err != nil {
		logger.WithError(err).Errorln("Failed to send email.")
		return common.ErrInternalErr
	}
	return nil
}

// Open access for this API. Don't log above info.
func (h *handlerImpl) ResetPassword(requestObject api.ResetPasswordRequestObject) error {
	f := requestObject.Body
	if f == nil {
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	namespace, loginName, otp := f.Namespace, f.LoginName, f.OneTimeCodeCheck
	code, emailOrPhone := otp.Code, otp.EmailOrPhone

	namespace = strings.TrimSpace(namespace)
	loginName = strings.TrimSpace(loginName)
	if namespace == "" {
		namespace = utils.DefaultNamespace
	}

	logger := h.logger.WithFields(logrus.Fields{
		ulog.Handle:    "reset-password",
		ulog.Namespace: namespace,
		ulog.Username:  loginName,
		ulog.Code:      code,
		"email/phone":  emailOrPhone,
	})
	if valid, err := common.CheckOneTimeCode(&otp); err != nil || !valid {
		if err != nil {
			logger.WithError(err).Errorln("Failed to check one time code.")
			return common.ErrInternalErr
		}
		return common.ErrModelOneTimeCodeInvalid
	}

	user, err := db.GetUserByLoginName(namespace, loginName)
	if err != nil {
		if errors.Is(err, db.ErrUserNotExists) || errors.Is(err, db.ErrUserLoginNotExists) {
			logger.Errorln("User or login does not exist.")
			return common.NewBadParamsErr(err) // Don't be specific.
		}
		logger.WithError(err).Errorln("Failed to get user from DB.")
		return common.ErrInternalErr
	}
	isAdmin := optional.Bool(user.IsAdminUser)
	email := optional.String(user.UserBaseInfo.Email)
	phone := optional.String(user.UserBaseInfo.Mobile)
	if (email != otp.EmailOrPhone && !otp.IsPhone) ||
		(phone != otp.EmailOrPhone && otp.IsPhone) {
		logger.
			WithField("user-email", email).
			WithField("user-phone", phone).
			WithField("otp-is-phone", otp.IsPhone).
			Warnln("Email or phone does not match record.")
		return common.NewBadParamsErr(errors.New("email or phone does not match"))
	}

	if isAdmin {
		logger.Warnln("Admin forgetting own password.")
	}
	return h.setUsernamePassword(namespace, "", f.NewPassword, loginName, models.LoginTypeUsername, logger)
}

func (h *handlerImpl) ListNotice(auth interface{}, requestObject api.ListNoticeRequestObject) (*models.NoticeList, error) {
	token, namespace, userID, logger := h.parseToken(auth, "list-notice", "List notice")
	category := requestObject.Category
	params := requestObject.Params
	idList := types.UUIDListToIDList(requestObject.Body)
	logger = logger.WithField("category", category)
	var (
		ofUserID        *types.UserID
		ofNamespace     *string
		ofNetworkDomain *string
	)
	if !token.IsAdminUser {
		domain, err := getNetworkDomainOfAdmin(userID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get network domain.")
			return nil, common.ErrInternalErr
		}
		ofNetworkDomain = domain
		if ofNetworkDomain == nil || *ofNetworkDomain == "" {
			ofUserID = &userID
		}
	} else if !token.IsSysAdmin {
		ofNamespace = &namespace
	}

	// Must have page and page size set so that we don't load the whole list.
	var (
		pageSize = 10
		page     = 1
	)
	if params.PageSize != nil && *params.PageSize > 0 {
		pageSize = *params.PageSize
	}
	if params.Page != nil && *params.Page > 0 {
		page = *params.Page
	}

	var list *models.NoticeList
	var err error
	switch string(category) {
	case string(models.NoticeCategoryAlarm):
		if params.SortBy != nil {
			logger.WithField("sort-by", *params.SortBy).Debugln("Sorting by")
			return nil, common.NewBadParamsErr(errors.New("sorting by is not supported for alarms"))
		}
		list, err = db.GetAlarmList(ofNamespace, ofNetworkDomain, ofUserID,
			params.Level, params.State,
			params.StartTime, params.EndTime,
			&page, &pageSize,
			idList)
	case string(models.NoticeCategoryAlert):
		list, err = db.GetAlertList(params.Type,
			ofNamespace, ofNetworkDomain, ofUserID, params.State,
			params.SortBy, params.SortDesc, idList,
			&page, &pageSize)
	default:
		logger.Warnln("invalid category")
		return nil, common.NewBadParamsErr(err)
	}

	if err != nil {
		logger.WithError(err).Warnln("Get notice list failed")
		return nil, common.ErrInternalErr
	}
	logger.WithField("total", list.Total).Debugln("Get notice list")
	return list, nil
}

func (h *handlerImpl) DeleteNotices(auth interface{}, requestObject api.DeleteNoticesRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "delete-notices", "Delete notices")
	category := requestObject.Category
	idList := types.UUIDListToIDList(requestObject.Body)
	logger = logger.WithField("category", category)
	var (
		ofNamespace     *string
		ofNetworkDomain *string
		ofUserID        *types.UserID
	)
	if !token.IsSysAdmin {
		ofNamespace = &namespace
	}
	if !token.IsAdminUser {
		domain, err := getNetworkDomainOfAdmin(userID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get network domain.")
			return common.ErrInternalErr
		}
		if domain != nil && *domain != "" {
			ofNetworkDomain = domain
		} else {
			ofUserID = &userID
		}
	}
	var err error
	switch category {
	case models.NoticeCategoryAlarm:
		err = db.DeleteAlarms(ofNamespace, ofNetworkDomain, ofUserID, requestObject.Params.DaysOld, idList)
	case models.NoticeCategoryAlert:
		err = db.DeleteAlerts(namespace, ofUserID, idList)
	default:
		logger.Warnln("invalid category")
		return common.NewBadParamsErr(err)
	}

	if err != nil {
		logger.WithError(err).Warnln("Delete notices failed")
		return common.ErrInternalErr
	}
	return nil
}
func (h *handlerImpl) UpdateNotices(auth interface{}, requestObject api.UpdateNoticesRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "update-notices", "Update notices")
	category := requestObject.Category
	logger = logger.WithField("category", category)
	var ofUserID *types.UserID
	if !token.IsAdminUser {
		ofUserID = &userID
	}
	var err error
	update := requestObject.Body
	state := types.NoticeState(update.State)
	idList := types.UUIDListToIDList(&update.IDList)
	switch category {
	case models.NoticeCategoryAlarm:
		err = db.UpdateAlarmState(namespace, ofUserID, idList, userID, token.Username, "", state)
	case models.NoticeCategoryAlert:
		_, err = db.UpdateAlertState(namespace, ofUserID, idList, userID, token.Username, "", state)
	default:
		logger.Warnln("invalid category")
		return common.NewBadParamsErr(err)
	}

	if err != nil {
		logger.WithError(err).Warnln("Update notices failed")
		return common.ErrInternalErr
	}
	return nil
}

func (h *handlerImpl) UserDeviceTraffic(auth interface{}, requestObject api.GetDeviceTrafficRequestObject) (list []models.DeviceTrafficStats, err error) {
	token, namespace, userID, logger := h.parseToken(auth, "user-device-traffic", "Get user device traffic")
	if requestObject.UserID != "" && requestObject.UserID != userID.String() {
		logger = logger.WithField("target-user-id", requestObject.UserID)
		if !token.IsAdminUser {
			logger.Warnln("Trying to access other user's device traffic stats.")
			return nil, common.ErrModelUnauthorized
		}
		id, err := types.ParseID(requestObject.UserID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to parse user ID.")
			return nil, common.NewBadParamsErr(err)
		}
		userID = id
	}

	deviceList, err := db.GetUserDeviceListFast(namespace, userID)
	if err != nil {
		if errors.Is(err, db.ErrDeviceNotExists) {
			return nil, nil
		}
		logger.WithError(err).Errorln("get user device list failed")
		return nil, err
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	for _, d := range deviceList {
		deviceID := d.ID
		if len(idList) > 0 {
			if !slices.Contains(idList, deviceID) {
				continue
			}
		}
		items, err := db.GetDeviceAllWgTrafficStats(namespace, deviceID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get device traffic stats from db.")
			return nil, err
		}
		var stats []models.WgTrafficStats
		for _, v := range items {
			stats = append(stats, *v.ToModel())
		}
		list = append(list, models.DeviceTrafficStats{
			DeviceID:   deviceID.UUID(),
			DeviceName: optional.StringP(d.NameAlias),
			IP:         optional.CopyStringP(d.IP()),
			WgStats:    &stats,
		})
	}
	return list, nil
}

func isAuthorizedForUser(userID, ofUserID types.UserID) (bool, error) {
	var (
		user   types.User
		ofUser types.User
	)
	if userID == ofUserID {
		return true, nil
	}
	if err := db.GetUser(userID, &user); err != nil {
		return false, fmt.Errorf("failed to get user %s: %w", userID, err)
	}
	if err := db.GetUser(ofUserID, &ofUser); err != nil {
		return false, fmt.Errorf("failed to get of-user %s: %w", ofUserID, err)
	}
	if optional.Bool(user.IsSysAdmin) {
		return true, nil
	}
	if optional.Bool(user.IsAdminUser) {
		return user.Namespace == ofUser.Namespace, nil
	}
	if user.IsNetworkAdmin() {
		return user.NetworkDomain == ofUser.NetworkDomain, nil
	}
	return false, nil
}

func getNetworkDomainOfAdmin(userID types.UserID) (*string, error) {
	var (
		user types.User
	)
	if err := db.GetUser(userID, &user); err != nil {
		return nil, err
	}
	if optional.Bool(user.IsAdminUser) || user.IsNetworkAdmin() {
		return user.NetworkDomain, nil
	}
	return nil, nil
}

func (h *handlerImpl) UserSummary(auth interface{}, requestObject api.GetUserSummaryRequestObject) (list models.SummaryStatsList, err error) {
	token, namespace, userID, logger := h.parseToken(auth, "user-summary", "Get user summary")
	params := requestObject.Params
	var (
		ofNamespace     *string
		ofUserID        *types.UserID
		ofNetworkDomain *string
	)
	if params.Namespace != nil && *params.Namespace != "" {
		if !token.IsSysAdmin {
			if namespace != *params.Namespace {
				logger.Warnln("Non-sysadmin user trying to access other namespace.")
				return nil, common.ErrModelUnauthorized
			}
		}
		ofNamespace = params.Namespace
		logger = logger.WithField(ulog.Namespace, *ofNamespace)
	} else {
		if !token.IsSysAdmin {
			ofNamespace = &namespace
		}
	}
	if params.UserID != nil && *params.UserID != "" {
		logger = logger.WithField("target-user-id", *params.UserID)
		id, err := types.ParseID(*params.UserID)
		if err != nil {
			logger.WithError(err).Debugln("Failed to parse user ID.")
			return nil, common.NewBadParamsErr(err)
		}
		ok, err := isAuthorizedForUser(userID, id)
		if err != nil {
			logger.WithError(err).Errorln("Failed to check user authorization.")
			return nil, common.ErrInternalErr
		}
		if !ok {
			logger.Warnln("Trying to access other user's summary.")
			return nil, common.ErrModelUnauthorized
		}
		ofUserID = &id
	} else {
		if !token.IsAdminUser {
			ofNetworkDomain, err = getNetworkDomainOfAdmin(userID)
			if err != nil {
				logger.WithError(err).Errorln("Failed to get network domain of admin.")
				return nil, common.ErrInternalErr
			}
			if ofNetworkDomain == nil || *ofNetworkDomain == "" {
				ofUserID = &userID
			}
		}
	}

	if params.Days == nil {
		deviceCount, err := db.DeviceCount(ofNamespace, ofUserID, ofNetworkDomain, false)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get device count.")
			return nil, common.ErrInternalErr
		}
		onlineDeviceCount, err := db.DeviceCount(ofNamespace, ofUserID, ofNetworkDomain, true)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get online device count.")
			return nil, common.ErrInternalErr
		}
		userCount := int64(1)
		if ofUserID == nil {
			userCount, err = db.UserCount(ofNamespace, ofNetworkDomain, false)
			if err != nil {
				logger.WithError(err).Errorln("Failed to get user count.")
				return nil, common.ErrInternalErr
			}
		}
		onlineUserCount, err := db.UserCount(ofNamespace, ofNetworkDomain, true)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get online user count.")
			return nil, common.ErrInternalErr
		}
		logger.WithFields(logrus.Fields{
			"device-count":        deviceCount,
			"online-device-count": onlineDeviceCount,
			"user-count":          userCount,
			"online-user-count":   onlineUserCount,
		}).Debugln("Success")
		return []models.SummaryStats{
			{
				DeviceCount:       optional.P(int(deviceCount)),
				UserCount:         optional.P(int(userCount)),
				OnlineDeviceCount: optional.P(int(onlineDeviceCount)),
				OnlineUserCount:   optional.P(int(onlineUserCount)),
			},
		}, nil
	}
	days := int(*params.Days)
	logger = logger.WithField("days", days)
	if days < 1 {
		logger.Warnln("Invalid days parameter.")
		return nil, common.NewBadParamsErr(err)
	}
	if list, err = metrics.UserSummaryStats(namespace, ofUserID.String(), days); err != nil {
		logger.WithError(err).Errorln("Failed to get user summary.")
		return nil, err
	}
	return
}

func (h *handlerImpl) UserDeviceSummary(auth interface{}, requestObject api.GetUserDeviceSummaryRequestObject) (list []models.DeviceSummary, err error) {
	token, namespace, userID, logger := h.parseToken(auth, "user-device-summary", "Get user device summary")
	params := requestObject.Params
	if params.UserID != nil && *params.UserID != "" && *params.UserID != userID.String() {
		logger = logger.WithField("target-user-id", *params.UserID)
		if !token.IsAdminUser {
			logger.Warnln("Trying to access other user's device summary.")
			return nil, common.ErrModelUnauthorized
		}
		id, err := types.ParseID(*params.UserID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to parse user ID.")
			return nil, common.NewBadParamsErr(err)
		}
		userID = id
	}
	deviceList, err := db.GetUserDeviceListFast(namespace, userID)
	if err != nil {
		if errors.Is(err, db.ErrDeviceNotExists) {
			return nil, nil
		}
		logger.WithError(err).Errorln("Failed to get user device list.")
		return nil, common.ErrInternalErr
	}

	days := 0
	if params.Days != nil {
		days = int(*params.Days)
		logger = logger.WithField("days", days)
		if days < 1 {
			logger.Warnln("Invalid days parameter.")
			return nil, common.NewBadParamsErr(err)
		}
	}

	for _, device := range deviceList {
		deviceID := device.ID
		log := logger.WithField(ulog.DeviceID, deviceID)
		var items []models.DeviceSummaryItem
		if days > 0 {
			items, err = metrics.DeviceSummaryStats(namespace, userID.String(), deviceID.String(), days)
		} else {
			var s *models.TrafficStats
			if s, err = db.DeviceAggregateTrafficStats(namespace, deviceID); err == nil {
				items = []models.DeviceSummaryItem{
					{
						TrafficStats: s,
					},
				}
			}
		}
		if err != nil {
			log.WithError(err).Errorln("Failed to get device stats")
			return nil, common.ErrInternalErr
		}
		s := models.DeviceSummary{
			DeviceID:   deviceID.UUIDP(),
			DeviceName: optional.StringP(device.NameAlias),
			IP:         optional.CopyStringP(device.IP()),
			Items:      &items,
		}
		list = append(list, s)
	}
	return
}

// UserIDToken API is open to public.
// DO NOT log above debug except for internal errors.
func (h *handlerImpl) UserIDToken(params api.GetIDTokenRequestObject) (*models.UserIDToken, error) {
	token := &utils.OauthCodeToken{
		Token: params.Code,
	}
	t, err := token.Get()
	if err != nil {
		if errors.Is(err, utils.ErrTokenNotExists) || errors.Is(err, utils.ErrTokenExpired) {
			return nil, common.ErrModelUnauthorized
		}
		h.logger.WithError(err).Errorln("Failed to get oauth code token.")
		return nil, common.ErrInternalErr
	}
	ub, err := db.GetUserBaseInfoFast(t.Namespace, types.UUIDToID(t.UserID))
	if err != nil {
		h.logger.WithError(err).Errorln("Failed to get user from db.")
		return nil, common.ErrInternalErr
	}
	return &models.UserIDToken{
		DisplayName:   &ub.DisplayName,
		ProfilePicURL: &ub.ProfilePicURL,
		TenantName:    &ub.CompanyName,
	}, nil
}

// GetUserRoles gets the roles of available for the user.
func (h *handlerImpl) GetUserRoles(auth interface{}, params api.GetUserRolesRequestObject) ([]models.Role, error) {
	token, namespace, _, logger := h.parseToken(auth, "get-user-roles", "Get user roles")

	// Only admin is authorized to get user roles.
	if token == nil || !token.IsAdminUser {
		return nil, common.ErrModelUnauthorized
	}

	// Get non-admin roles from namespace labels of "roles" category.
	if utils.SysAdminNamespace != namespace {
		labels, err := db.GetLabelOfCategory(namespace, "roles")
		if err != nil {
			logger.WithError(err).Errorln("Failed to get namespace roles.")
			return nil, common.ErrInternalErr
		}
		var list []models.Role
		for _, v := range labels {
			list = append(list, models.Role{
				ID:          v.ID.String(),
				Description: v.Description,
				Name:        v.Name,
			})
		}
		return list, nil
	}

	// Get admin namespace from keycloak.
	getRolesParams := gocloak.GetRoleParams{}
	if params.Params.Contain != nil && *params.Params.Contain != "" {
		search := *params.Params.Contain
		getRolesParams.Search = &search
	}

	clientRoles, err := kc.GetClientRoles(namespace, getRolesParams)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get client roles from keycloak.")
		return nil, common.ErrInternalErr
	}
	var roles []models.Role
	for _, r := range clientRoles {
		roles = append(roles, models.Role{
			ID:          optional.String(r.ID),
			Name:        optional.String(r.Name),
			Description: optional.String(r.Description),
		})
	}
	logger.WithField("total", len(clientRoles)).Debugln("Get user roles success.")
	return roles, nil
}

// OK to get other user's profile img.

func profileImgParamsUserID(namespace string, userIDStr, username *string, logger *logrus.Entry) (*types.UserID, error) {
	if userIDStr != nil {
		logger = logger.WithField("target-user-id", *userIDStr)
		id, err := types.ParseID(*userIDStr)
		if err != nil {
			logger.WithError(err).Errorln("Failed to parse user ID.")
			return nil, common.NewBadParamsErr(err)
		}
		return &id, nil
	} else if username != nil && *username != "" {
		l, err := db.GetUserLoginByLoginName(namespace, *username)
		if err != nil {
			if errors.Is(err, db.ErrUserLoginNotExists) {
				return nil, common.ErrModelUserNotExists
			}
			logger.WithError(err).Errorln("Failed to get user login.")
			return nil, common.ErrInternalErr
		}
		userID := l.UserID
		return &userID, nil
	}
	return nil, nil
}

func (h *handlerImpl) ProfileImg(auth interface{}, requestObject api.GetProfileImgRequestObject) (*models.UserProfile, error) {
	_, namespace, userID, logger := h.parseToken(auth, "get-profile-img", "Get profile image")
	params := requestObject.Params
	targetUserID, err := profileImgParamsUserID(namespace, params.UserID, params.Username, logger)
	if err != nil {
		return nil, err
	}
	if targetUserID != nil {
		userID = *targetUserID
	}
	if userID.IsNil() {
		return nil, common.NewBadParamsErr(err)
	}

	ret, err := db.GetUserProfile(namespace, userID.String())
	if err != nil {
		if errors.Is(err, db.ErrUserProfilePicNotExists) {
			return &models.UserProfile{}, nil
		}
		logger.WithError(err).Errorln("Failed to get user profile image.")
		return nil, common.ErrInternalErr
	}
	return ret, nil
}

func (h *handlerImpl) UpdateProfileImg(auth interface{}, requestObject api.UpdateProfileImgRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "update-profile-img", "Update profile image")
	params := requestObject.Params
	targetUserID, err := profileImgParamsUserID(namespace, params.UserID, params.Username, logger)
	if err != nil {
		return err
	}
	if targetUserID != nil {
		if *targetUserID != userID {
			if token == nil || !token.IsAdminUser {
				logger.Warnln("Non-admin user trying to update other user's image.")
				return common.ErrModelUnauthorized
			}
			userID = *targetUserID
		}
	}
	if userID.IsNil() {
		return common.NewBadParamsErr(err)
	}

	body := requestObject.Body
	if body == nil || body.Base64Image == "" {
		logger.Warnln("Empty image. Please try delete API instead.")
		return common.NewBadParamsErr(err)
	}
	if err := db.UpdateUserProfile(namespace, userID.String(), body); err != nil {
		logger.WithError(err).Errorln("Failed to update user profile image in db.")
		return common.ErrInternalErr
	}
	return nil
}

func (h *handlerImpl) DeleteProfileImg(auth interface{}, requestObject api.DeleteProfileImgRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "delete-profile-img", "Delete profile image")
	params := requestObject.Params
	targetUserID, err := profileImgParamsUserID(namespace, params.UserID, params.Username, logger)
	if err != nil {
		return err
	}
	if targetUserID != nil {
		if *targetUserID != userID {
			if token == nil || !token.IsAdminUser {
				logger.Warnln("Non-admin user trying to delete other user's image.")
				return common.ErrModelUnauthorized
			}
			userID = *targetUserID
		}
	}
	if userID.IsNil() {
		return common.NewBadParamsErr(err)
	}

	if err := db.DeleteUserProfile(namespace, userID.String()); err != nil {
		logger.WithError(err).Errorln("Failed to delete user profile image from db.")
		return common.ErrInternalErr
	}
	return nil
}

func (h *handlerImpl) ListAccessPoint(auth interface{}, requestObject api.ListAccessPointRequestObject) (models.AccessPointList, error) {
	token, namespace, userID, logger := h.parseToken(auth, "list-access-point", "List access point")
	if token == nil {
		err := common.ErrModelUnauthorized
		logger.WithError(err).Debugln("nil token")
		return nil, err
	}
	if requestObject.UserID != "" && userID.String() != requestObject.UserID {
		logger = logger.WithField("target-user-id", requestObject.UserID)
		if !token.IsAdminUser {
			logger.Warnln("Non-admin user trying to list other user's access point.")
			return nil, common.ErrModelUnauthorized
		}
		id, err := types.ParseID(requestObject.UserID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to parse user ID.")
			return nil, common.NewBadParamsErr(err)
		}
		userID = id
	}
	if common.IsGatewaySupported(namespace, userID, types.NilID) {
		list, err := common.AccessPoints(namespace)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get namespace ap list")
			return nil, common.ErrInternalErr
		}
		return list, nil
	}
	return nil, nil
}

func (h *handlerImpl) ChangeAccessPoint(auth interface{}, requestObject api.ChangeAccessPointRequestObject) (*models.AccessPoint, error) {
	token, namespace, userID, logger := h.parseToken(auth, "change-access-point", "Change access point")
	forUserID := requestObject.UserID
	if forUserID != "" && forUserID != "self" && userID.String() != forUserID {
		logger = logger.WithField("target-user-id", forUserID)
		if !token.IsAdminUser {
			logger.Debugln("non-admin user changing other user's ap.")
			return nil, common.ErrModelUnauthorized
		}
		var err error
		userID, err = types.ParseID(forUserID)
		if err != nil {
			return nil, common.NewBadParamsErr(err)
		}
	}
	if !common.IsGatewaySupported(namespace, userID, types.NilID) {
		err := errors.New("access point is not supported")
		return nil, common.NewBadParamsErr(err)
	}
	params := requestObject.Params
	apName := ""
	if params.AccessPointName != nil {
		apName = *params.AccessPointName
	}
	machineKey := params.MachineKey
	logger = logger.WithField(ulog.MKey, machineKey)
	wgInfo, err := db.WgInfoByMachineKey(namespace, userID, machineKey)
	if err != nil {
		if errors.Is(err, db.ErrDeviceWgInfoNotExists) {
			logger.Debugln("wg info does not exist")
			return nil, common.NewBadParamsErr(err)
		}
		logger.WithError(err).Errorln("Failed to get wg info")
		return nil, common.ErrInternalErr
	}

	var ret *models.AccessPoint
	if apName == "" {
		ret = &models.AccessPoint{}
	} else {
		apList, err := common.AccessPoints(namespace)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get access points.")
			return nil, common.ErrInternalErr
		}
		for _, ap := range apList {
			if ap.Name == apName {
				ret = &ap
				break
			}
		}
	}

	if ret == nil {
		err := fmt.Errorf("access point %v does not exist", apName)
		logger.WithError(err).Errorln("Failed to find access point.")
		return nil, common.NewBadParamsErr(err)
	}

	exitNodeID, err := common.ChangeExitNode(wgInfo, apName, token, logger)
	if err != nil {
		logger.WithError(err).Errorln("Failed to move device to new wg.")
		return nil, common.ErrInternalErr
	}
	ret.ID = exitNodeID.UUIDP()
	return ret, nil
}

func (h *handlerImpl) GenerateNetworkDomain(auth interface{}, requestObject api.GenerateNetworkDomainRequestObject) (string, error) {
	token, _, userID, logger := h.parseToken(auth, "generate-network-domain", "Genrate network domain")
	if token == nil {
		return "", common.ErrModelUnauthorized
	}
	if !token.IsAdminUser {
		user := &types.User{}
		if err := db.GetUser(userID, &user); err != nil {
			logger.WithError(err).Errorln("Failed to get user from db.")
			return "", err
		}
		if !user.IsNetworkAdmin() {
			logger.Warnln("Non-admin user trying to generate network domain.")
			return "", common.ErrModelUnauthorized
		}
	}
	wantWordsBased := requestObject.Params.WantWordsBased
	return generateNetworkDomain(logger, wantWordsBased)
}

func generateNetworkDomain(logger *logrus.Entry, wantWordsBased bool) (string, error) {
	for i := 0; i < 5; i++ {
		domain := ""
		if wantWordsBased {
			domain = common.GenerateNetworkDomainWithTwoWords()
		} else {
			domain = common.GenerateNetworkDomain()
		}
		inUse, err := db.IsNetworkDomainInUse(domain)
		if err != nil {
			return "", fmt.Errorf("failed to check if network domain is in use: %w", err)
		}
		if inUse {
			logger.
				WithField("domain", domain).
				Debugln("network domain in use, retrying...")
			continue
		}
		return domain, nil
	}
	return "", fmt.Errorf("failed to create network domain after 5 attempts")
}

func (h *handlerImpl) SetNetworkDomain(auth interface{}, requestObject api.SetNetworkDomainRequestObject) (err error) {
	token, namespace, userID, logger := h.parseToken(auth, "set-network-domain", "Set network domain")
	if token == nil {
		return common.ErrModelUnauthorized
	}
	if token.IsAdminUser {
		userID, err = types.ParseID(requestObject.UserID)
		if err != nil {
			logger.WithError(err).Errorln("Failed to parse user ID.")
			return common.NewBadParamsErr(err)
		}
		if userID.IsNil() {
			logger.Warnln("User ID is nil.")
			return common.NewBadParamsErr(err)
		}
	}
	user := &types.User{}
	if err = db.GetUser(userID, &user); err != nil {
		logger.WithError(err).Errorln("Failed to get user from db.")
		return err
	}
	if !token.IsSysAdmin {
		if user.Namespace != namespace {
			logger.Warnln("Non-sysadmin user trying to set network domain of other tenant.")
			return common.ErrModelUnauthorized
		}
	}
	if !token.IsAdminUser {
		if !user.IsNetworkAdmin() {
			logger.Warnln("Non-admin user trying to set network domain.")
			return common.ErrModelUnauthorized
		}
	}
	var (
		ofUserID      *types.UserID
		networkDomain = requestObject.NetworkDomain
		prevDomain    = optional.String(user.NetworkDomain)
	)
	if networkDomain == "" {
		logger.Warnln("Network domain is empty.")
		return common.NewBadParamsErr(errors.New("network domain is empty"))
	}
	if isUse, err := db.IsNetworkDomainInUse(networkDomain); err != nil {
		logger.WithError(err).Errorln("Failed to check if network domain is in use.")
		return common.ErrInternalErr
	} else if isUse {
		logger.WithField("domain", networkDomain).Warnln("Network domain is already in use.")
		return common.NewBadParamsErr(errors.New("network domain is already in use"))
	}

	if prevDomain == networkDomain {
		logger.Warnln("Network domain is the same.")
		return nil
	}

	if prevDomain == "" {
		ofUserID = &userID
	}

	if err = db.UpdateUserNetworkDomain(
		user.Namespace, prevDomain, networkDomain, ofUserID,
		func() error {
			err := vpn.UpdateUserNetworkDomain(user.Namespace, userID, networkDomain)
			if err != nil {
				logger.WithError(err).Errorln("Failed to update VPN user network domain.")
				return err
			}
			return nil
		},
	); err != nil {
		logger.WithError(err).Errorln("Failed to update user network domain.")
		return common.ErrInternalErr
	}

	return nil
}

func (h *handlerImpl) InviteUser(auth interface{}, request api.InviteUserRequestObject) (string, error) {
	token, namespace, userID, logger := h.parseToken(auth, "invite-user", "Invite user")
	if token == nil {
		logger.Warnln("nil token")
		return "", common.ErrModelUnauthorized
	}
	var user types.User
	err := db.GetUser(userID, &user)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get user from db.")
		return "", common.ErrInternalErr
	}
	if !(user.IsNetworkAdmin()) {
		logger.Warnln("Non-admin user trying to invite user.")
		return "", common.ErrModelUnauthorized
	}
	if namespace == "" {
		namespace = utils.DefaultNamespace
	}
	networkDomain := user.NetworkDomain
	if networkDomain == nil || *networkDomain == "" {
		networkDomain = &user.TenantConfig.NetworkDomain
	}
	logger = logger.WithField(ulog.Namespace, namespace)
	params := request.Body
	code := utils.NewStateToken(12)
	err = db.CreateUserInvite(&models.UserInvite{
		Namespace:     namespace,
		Emails:        params.Emails,
		NetworkDomain: *networkDomain,
		Code:          code,
		InvitedBy:     *user.UserBaseInfo.ShortInfo(),
		Role:          string(params.Role),
	})
	if err != nil {
		logger.WithError(err).Errorln("Failed to create user invite.")
		return "", common.ErrInternalErr
	}
	if params.SendEmail {
		var emails []string
		for _, email := range params.Emails {
			if email != "" {
				emails = append(emails, string(email))
			}
		}
		subject := inviteEmailSubject(user.UserBaseInfo.DisplayName, params.InternalUser)
		body := inviteEmailBody(
			user.UserBaseInfo.DisplayName,
			code,
			params.InternalUser,
		)
		if err := sendmail.SendEmail(emails, subject, body); err != nil {
			logger.WithError(err).Errorln("Failed to send user invite email.")
			return "", common.ErrInternalErr
		}
	}
	return inviteLink(code), nil
}

func (h *handlerImpl) DeleteUserInvite(auth interface{}, request api.DeleteUserInviteRequestObject) error {
	token, namespace, userID, logger := h.parseToken(auth, "delete-user-invite", "Delete user invite")
	if token == nil {
		logger.Warnln("nil token")
		return common.ErrModelUnauthorized
	}
	var (
		ofNamespace   *string
		networkDomain *string
	)
	if !token.IsSysAdmin {
		ofNamespace = &namespace
		if !token.IsAdminUser {
			var user types.User
			err := db.GetUser(userID, &user)
			if err != nil {
				logger.WithError(err).Errorln("Failed to get user from db.")
				return common.ErrInternalErr
			}
			if !(user.IsNetworkAdmin()) {
				logger.Warnln("Non-admin user trying to delete user invite.")
				return common.ErrModelUnauthorized
			}
			networkDomain = user.NetworkDomain
			if networkDomain == nil || *networkDomain == "" {
				networkDomain = &user.TenantConfig.NetworkDomain
			}
		}
	}
	logger = logger.WithFields(logrus.Fields{
		ulog.Namespace:   optional.String(ofNamespace),
		"network-domain": optional.String(networkDomain),
	})
	if request.Body == nil || len(*request.Body) == 0 {
		logger.Warnln("Empty user invite ID list.")
		return common.NewBadParamsErr(errors.New("empty user invite ID list"))
	}
	idList := types.UUIDListToIDList(request.Body)
	err := db.DeleteUserInvites(ofNamespace, networkDomain, idList)
	if err != nil {
		logger.WithError(err).Errorln("Failed to delete user invite.")
		return common.ErrInternalErr
	}
	return nil
}

func (h *handlerImpl) ListUserInvite(auth interface{}, request api.GetUserInviteListRequestObject) (int, []models.UserInvite, error) {
	token, namespace, userID, logger := h.parseToken(auth, "list-user-invite", "List user invite")
	if token == nil {
		logger.Warnln("nil token")
		return 0, nil, common.ErrModelUnauthorized
	}
	ofNamespace := request.Params.Namespace
	var networkDomain *string
	if !token.IsSysAdmin {
		if ofNamespace == nil || *ofNamespace == "" {
			ofNamespace = &namespace
		} else if *ofNamespace != namespace {
			logger.
				WithField(ulog.Namespace, *ofNamespace).
				Warnln("Non-sysadmin user trying to list user invite of other namespace.")
			return 0, nil, common.ErrModelUnauthorized
		}
		if !token.IsAdminUser {
			var user types.User
			err := db.GetUser(userID, &user)
			if err != nil {
				logger.WithError(err).Errorln("Failed to get user from db.")
				return 0, nil, common.ErrInternalErr
			}
			if !(user.IsNetworkAdmin()) {
				logger.Warnln("Non-admin user trying to list user invite.")
				return 0, nil, common.ErrModelUnauthorized
			}
			networkDomain = user.NetworkDomain
			if networkDomain == nil || *networkDomain == "" {
				networkDomain = &user.TenantConfig.NetworkDomain
			}
		}
	}
	logger = logger.WithFields(logrus.Fields{
		ulog.Namespace:   optional.String(ofNamespace),
		"network-domain": optional.String(networkDomain),
	})

	params := request.Params
	total, list, err := db.ListUserInvites(
		ofNamespace, networkDomain, params.FilterBy, params.FilterValue,
		params.SortBy, params.SortDesc, nil,
		params.Page, params.PageSize,
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to list user invite.")
		return 0, nil, common.ErrInternalErr
	}
	mList, _ := types.SliceMap(list, func(v types.UserInvite) (models.UserInvite, error) {
		return *v.ToModel(), nil
	})
	return total, mList, nil
}
