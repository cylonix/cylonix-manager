// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tenant

import (
	api "cylonix/sase/api/v2"
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/metrics"
	"cylonix/sase/pkg/optional"
	"cylonix/sase/pkg/sendmail"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/cylonix/utils"
	ulog "github.com/cylonix/utils/log"
	pw "github.com/cylonix/utils/password"
	"github.com/sirupsen/logrus"
)

type handlerImpl struct {
	logger *logrus.Entry
}

func newHandlerImpl(logger *logrus.Entry) *handlerImpl {
	return &handlerImpl{
		logger: logger,
	}
}

func checkTenantDBError(err error) error {
	switch {
	case errors.Is(err, db.ErrBadParams):
		return common.NewBadParamsErr(err)
	case errors.Is(err, db.ErrTenantExists):
		return common.ErrModelCompanyExists
	case errors.Is(err, db.ErrTenantApprovalExists):
		return common.ErrModelCompanyRegistrationExists
	case errors.Is(err, db.ErrTenantNotExists):
		return common.ErrModelCompanyConfigurationNotExists
	case errors.Is(err, db.ErrTenantApprovalNotExists):
		return common.ErrModelCompanyRegistrationNotExists
	case errors.Is(err, db.ErrTenantNameNotAvailable):
		return common.ErrModelCompanyNameNotAvailable
	case errors.Is(err, db.ErrTenantNamespaceNotAvailable):
		return common.ErrModelCompanyNamespaceNotAvailable
	case errors.Is(err, db.ErrTenantEMailExists):
		return common.ErrModelEmailRegistered
	case errors.Is(err, db.ErrTenantPhoneExists):
		return common.ErrModelPhoneRegistered
	default:
		return common.ErrInternalErr
	}
}

// ListConfig gets the list of tenant config base on various filters, sorting
// and paging options. To get the config of a specific tenant ID, just pass in
// the single tenant id as the id-list or set the namespace parameter. Tenant
// admin can only get the config of its own namespace.
func (h *handlerImpl) ListConfig(auth interface{}, requestObject api.ListTenantConfigRequestObject) (int, []models.TenantConfig, error) {
	token, namespace, _, logger := common.ParseToken(auth, "list-tenant-config", "List tenant config", h.logger)
	params := requestObject.Params
	idList := types.UUIDListToIDList(requestObject.Body)
	var targetNamespace *string
	if !token.IsSysAdmin {
		targetNamespace = &namespace
	}
	if params.Namespace != nil && *params.Namespace != "" {
		if !token.IsSysAdmin && !strings.EqualFold(*params.Namespace, namespace) {
			return 0, nil, common.ErrModelUnauthorized
		}
		targetNamespace = params.Namespace
	}

	if targetNamespace != nil {
		tenant, err := db.GetTenantConfigByNamespace(*targetNamespace)
		if err != nil {
			logger.WithError(err).Infoln("Failed to get tenant config from db.")
			if errors.Is(err, db.ErrTenantNotExists) {
				return 0, nil, nil
			}
			return 0, nil, common.ErrInternalErr
		}
		return 1, []models.TenantConfig{*tenant.ToModel()}, nil
	}

	list, total, err := db.ListTenantConfig(params.Contain,
		params.FilterBy, params.FilterValue,
		params.SortBy, params.SortDesc, idList, params.Page, params.PageSize,
	)
	if err != nil {
		if errors.Is(err, db.ErrTenantNotExists) {
			return 0, nil, nil
		}
		logger.WithError(err).Infoln("Failed to get tenant config from db.")
		return 0, nil, common.ErrInternalErr
	}
	var rList []models.TenantConfig
	for _, l := range list {
		rList = append(rList, *l.ToModel())
	}
	return total, rList, nil
}

func (h *handlerImpl) UpdateConfig(auth interface{}, requestObject api.UpdateTenantConfigRequestObject) error {
	token, namespace, userID, logger := common.ParseToken(auth, "update-tenant-config", "Update tenant config", h.logger)

	// Only sys admin user can update tenant config of other tenants.
	update := requestObject.Body
	if update == nil || update.ID == uuid.Nil {
		err := errors.New("missing update or config id")
		return common.NewBadParamsErr(err)
	}
	id := types.UUIDToID(update.ID)
	config, err := db.GetTenantConfig(id)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get tenant config.")
		if errors.Is(err, db.ErrTenantNotExists) {
			return common.ErrModelCompanyConfigurationNotExists
		}
		return common.ErrInternalErr
	}

	if namespace != config.Namespace {
		if !token.IsSysAdmin {
			return common.ErrModelUnauthorized
		}
		namespace = config.Namespace
		logger = logger.WithField("target-namespace", namespace)
	}
	if update.Namespace != "" && update.Namespace != config.Namespace {
		logger.WithError(db.ErrUpdateNotSupported).Errorln("Tenant ID or namespace change is not supported.")
		return common.ErrModelOperationNotSupported
	}

	updateConfig := types.TenantConfig{
		Name:             update.Name,
		Email:            optional.NilIfEmptyStringP(strings.ToLower(strings.TrimSpace(update.Email))),
		Phone:            optional.NilIfEmptyStringP(strings.ToLower(strings.TrimSpace(update.Phone))),
		Address:          update.Address,
		WelcomeEmailSent: update.WelcomeEmailSent,
		TenantSetting: types.TenantSetting{
			AutoApproveDevice: update.AutoApproveDevice,
			AutoAcceptRoutes:  update.AutoAcceptRoutes,
			MaxUser:           uint(optional.V(update.MaxUserCount, 0)),
			MaxDevice:         uint(optional.V(update.MaxDeviceCount, 0)),
			MaxDevicePerUser:  uint(optional.V(update.MaxDevicePerUser, 0)),
		},
	}
	note := optional.String(requestObject.Params.Note)
	if err := db.UpdateTenantConfig(id, updateConfig, userID, token.Username, note); err != nil {
		logger.WithError(err).Errorln("Failed to update tenant config.")
		return checkTenantDBError(err)
	}
	return nil
}

// AddConfig adds a new tenant config directly without going through the
// approval process. Tenant registration must exist prior.
func (h *handlerImpl) AddConfig(auth interface{}, requestObject api.AddTenantConfigRequestObject) (password string, err error) {
	token, _, userID, logger := common.ParseToken(auth, "add-tenant-config", "Add tenant config", h.logger)
	if !token.IsSysAdmin {
		err = common.ErrModelUnauthorized
		return
	}

	c := requestObject.Body
	logger = logger.WithFields(logrus.Fields{
		ulog.Company:   c.Name,
		ulog.Namespace: c.Namespace,
		ulog.Email:     c.Email,
		ulog.Phone:     c.Phone,
	})
	if c.Namespace == "" || c.Name == "" {
		err = common.NewBadParamsErr(errors.New("missing namespace or name"))
		logger.WithError(err).Errorln("Invalid namespace or name.")
		return
	}

	// Check if tenant config already exists.
	_, err = db.GetTenantConfigByNamespace(c.Namespace)
	if err == nil {
		err = common.ErrModelCompanyExists
		logger.WithError(err).Errorln("Failed.")
		return
	}
	if !errors.Is(err, db.ErrTenantNotExists) {
		logger.WithError(err).Errorln("Failed to get tenant config.")
		err = common.ErrInternalErr
		return
	}

	// Check if user tier exists.
	var userTier *types.UserTier
	if c.UserTierID != nil {
		userTier, err = db.GetUserTier(types.UUIDToID(*c.UserTierID))
	} else {
		userTier, err = db.GetUserTierByName(utils.DefaultUserTier)
	}
	if err != nil {
		if errors.Is(err, db.ErrUserTierNotExists) {
			err = common.NewBadParamsErr(errors.New("user tier not exists"))
			logger.WithError(err).Errorln("Failed.")
			return
		}
		logger.WithError(err).Errorln("Failed to get user tier.")
		err = common.ErrInternalErr
		return
	}
	userTierID := &userTier.ID

	// Check if network domain is set.
	networkDomain := optional.V(c.NetworkDomain, "")
	if networkDomain == "" {
		err = common.NewBadParamsErr(errors.New("missing network domain"))
		logger.WithError(err).Errorln("Failed.")
		return
	}

	// Set tenant registration state to approved.
	var r *types.TenantApproval
	if r, err = db.GetTenantApprovalByName(c.Name); err != nil {
		if !errors.Is(err, db.ErrTenantApprovalNotExists) {
			logger.WithError(err).Errorln("Failed to get tenant registration.")
			err = common.ErrInternalErr
			return
		}
		// Create a new registration record.
		mr := &models.TenantApproval{
			CompanyName: c.Name,
			Namespace:   c.Namespace,
			Email:       c.Email,
			Phone:       c.Phone,
		}
		note := "created automatically when adding tenant config"
		if r, err = db.NewTenantApproval(mr, userID, token.Username, note); err != nil {
			logger.WithError(err).Errorln("Failed to add tenant registration.")
			err = checkTenantDBError(err)
			return
		}
	}
	note := "approved automatically when adding tenant config"
	if err = db.SetTenantApprovalState(r.ID, models.ApprovalStateApproved, userID, token.Username, note); err != nil {
		logger.WithError(err).Errorln("Failed to set tenant registration state to approved.")
		err = checkTenantDBError(err)
		return
	}
	password, err = h.handleNewlyApprovedTenant(
		r, userTierID, networkDomain, userID, token.Username, logger,
	)
	return
}

// DeleteConfigs deletes the tenants config and set their registration state to
// the holding state. If full deletion is desired, please refer to the delete
// API for registration, users and devices.
func (h *handlerImpl) DeleteConfigs(auth interface{}, requestObject api.DeleteTenantConfigsRequestObject) error {
	token, _, userID, logger := common.ParseToken(auth, "delete-tenant-configs", "Delete tenant configs", h.logger)

	// Only sys admin user can delete tenant.
	if !token.IsSysAdmin {
		return common.ErrModelUnauthorized
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	for _, id := range idList {
		log := logger.WithField("target-tenant", id.String())
		t, err := db.GetTenantConfig(id)
		if err != nil {
			if !errors.Is(err, db.ErrTenantNotExists) {
				log.WithError(err).Errorln("Failed to get tenant config.")
				return common.ErrInternalErr
			}
			continue
		}
		userCount, err := db.UserCount(&t.Namespace, nil)
		if err != nil {
			log.WithError(err).Errorln("Failed to get tenant's user count.")
			return common.ErrInternalErr
		}
		if userCount > 0 {
			err = common.ErrModelUserExists
			log.WithError(err).Errorln("Cannot delete tenant with existing users.")
			return err
		}
		r, err := db.GetTenantApprovalByName(t.Name)
		if err != nil {
			log.WithError(err).Errorln("Failed to get tenant approval.")
			return common.ErrInternalErr
		}
		if err := db.SetTenantApprovalState(r.ID, models.ApprovalStateHold, userID, token.Username, "deleting tenant config"); err != nil {
			if !errors.Is(err, db.ErrTenantApprovalNotExists) {
				log.WithError(err).Errorln("Failed to set tenant approval state to hold.")
				return common.ErrInternalErr
			}
		}
		if err := db.DeleteTenantConfig(id); err != nil {
			log.WithError(err).Errorln("Delete user in all db failed")
			return common.ErrInternalErr
		}
	}
	return nil
}

// RegisterTenant adds a tenant registration for sys admin approval.
func (h *handlerImpl) RegisterTenant(auth interface{}, requestObject api.RegisterTenantRequestObject) error {
	r := requestObject.Body
	if r == nil {
		err := errors.New("missing input")
		return common.NewBadParamsErr(err)
	}
	namespace := r.Namespace
	logger := h.logger.WithFields(logrus.Fields{
		ulog.Handle:    "register-tenant",
		ulog.Company:   r.CompanyName,
		ulog.ID:        r.ID,
		ulog.Namespace: namespace,
		ulog.Email:     r.Email,
		ulog.Phone:     r.Phone,
	})
	approvalUserID, approvalUsername := types.NilID, r.ContactName
	token, ok := auth.(*utils.UserTokenData)
	if auth == nil || !ok || !token.IsSysAdmin {
		logger = logger.WithFields(logrus.Fields{
			ulog.Code: r.Code,
		})
		valid, err := common.CheckOneTimeCodeWithEmailOrPhone(r.Email, r.Phone, r.Code, r.IsSmsCode)
		if err != nil || !valid {
			if err != nil {
				logger.WithError(err).Errorln("Failed to check code.")
				return common.ErrInternalErr
			}
			logger.Debugln("Invalid code")
			if r.IsSmsCode {
				return common.ErrModelInvalidSmsCode
			}
			return common.ErrModelOneTimeCodeInvalid
		}
	}
	if token != nil && token.Token != "" {
		approvalUserID = types.UUIDToID(token.UserID)
		approvalUsername = token.Username
	}
	common.LogWithLongDashes("Register tenant", logger)
	if _, err := db.NewTenantApproval(r, approvalUserID, approvalUsername, "submitted by "+r.ContactName); err != nil {
		logger.WithError(err).Errorln("Failed to add registration to database.")
		return checkTenantDBError(err)
	}
	return nil
}

func (h *handlerImpl) handleNewlyApprovedTenant(
	r *types.TenantApproval,
	tier *types.ID,
	networkDomain string,
	approverID types.UserID, approverName string,
	logger *logrus.Entry,
) (password string, err error) {
	// Roll back if rest of the operation failed.
	defer func() {
		if err == nil {
			return
		}
		newErr := db.SetTenantApprovalState(
			r.ID, models.ApprovalStatePending,
			approverID, approverName, "roll back to pending due to error",
		)
		if newErr != nil {
			logger.WithError(newErr).Errorln("Failed to roll back to pending.")
		}
	}()

	password = utils.NewPassword()
	hashedPassword, newErr := pw.NewHash(password)
	if newErr != nil {
		logger.WithError(newErr).Errorln("Failed to hash the new password.")
		err = common.ErrInternalErr
		return
	}

	// If there is a race condition on getting the same namespace, the
	// NewTenant call below will fail with an existing entry check.
	config := &types.TenantConfig{
		Name:       r.CompanyName,
		Namespace:  r.Namespace,
		Email:      optional.NilIfEmptyStringP(strings.ToLower(strings.TrimSpace(optional.String(r.Email)))),
		Phone:      optional.NilIfEmptyStringP(strings.ToLower(strings.TrimSpace(optional.String(r.Phone)))),
		UserTierID: tier,
	}

	logger.WithField("tenant", *config).Debugln("adding tenant config.")
	err = db.NewTenant(config, approverID, approverName, "created automatically with tenant approval.")
	if err != nil {
		logger.WithError(err).Errorln("Failed to add the newly approved tenant.")
		err = checkTenantDBError(err)
		return
	}
	tenantID := config.ID
	defer func() {
		if err == nil {
			return
		}
		if newErr := db.DeleteTenantConfig(tenantID); newErr != nil {
			logger.WithError(newErr).Errorln("Failed to roll back tenant config.")
		}
	}()
	// Skip adding admin user if no email is set.
	if config.Email == nil {
		return
	}
	// Add admin user for the tenant.
	username := *config.Email
	displayName := r.ContactName
	if displayName == "" {
		displayName = username
	}
	login := types.UserLogin{
		Namespace:   r.Namespace,
		LoginName:   username,
		LoginType:   types.LoginTypeUsername,
		Credential:  string(hashedPassword),
		Verified:    true,
		DisplayName: r.ContactName,
	}

	err = common.CreateUser(
		&login, r.Namespace, username, optional.String(config.Phone),
		[]string{}, nil, nil, /* tier inherits from tenant */
		nil /* network domain inherits from tenant */, true, logger,
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to create the new admin user.")
		return "", common.ErrInternalErr
	}

	// Send email to the contact person.
	// Note we can re-try this if there is an error hence not rolling back
	// the user entries and approval state.
	if err := sendWelcomeEmail(r.Namespace, username, login.Credential); err != nil {
		logger.WithError(err).Errorln("Failed to send the new tenant welcome email.")
		// Fall through to signal the approval success. Email can be re-sent later.
	} else {
		logger.Debugln("Welcome email sent!")
		update := types.TenantConfig{
			WelcomeEmailSent: optional.BoolP(true),
		}
		if err := db.UpdateTenantConfig(tenantID, update, approverID, approverName, "update welcome email sent"); err != nil {
			logger.WithError(err).Errorln("Failed to update welcome email sent setting.")
		}
	}
	return
}

func (h *handlerImpl) ApprovalRecords(auth interface{}, requestObject api.GetTenantApprovalRecordsRequestObject) (int, []models.TenantApproval, error) {
	// Only sys admin user or pending approval tenant admin can read approval records.
	token, ok := auth.(*utils.UserTokenData)
	if auth != nil && ok && token != nil && !token.IsSysAdmin {
		return 0, nil, common.ErrModelUnauthorized
	}
	logger := h.logger.WithField(ulog.Handle, "get-tenant-approval-record")

	// Pending approval tenant needs to authenticate with email/phone and
	// can only fetch its own status.
	idList := types.UUIDListToIDList(requestObject.Body)
	params := requestObject.Params
	if auth == nil || token == nil {
		if params.Code == nil && *params.Code == "" ||
			((params.Email == nil || *params.Email == "") &&
				(params.PhoneNum == nil || *params.PhoneNum == "")) ||
			(params.CompanyName == nil || *params.CompanyName == "") {
			err := errors.New("missing code validation input")
			return 0, nil, common.NewBadParamsErr(err)
		}
		if len(idList) > 0 {
			return 0, nil, common.ErrModelUnauthorized
		}
		valid, err := common.CheckOneTimeCodeWithEmailOrPhoneP(params.Email, params.PhoneNum, params.Code)
		if err != nil {
			logger.WithError(err).Errorln("Failed to check code.")
			return 0, nil, common.ErrInternalErr
		}
		if !valid {
			if params.PhoneNum != nil {
				return 0, nil, common.ErrModelInvalidSmsCode
			}
			return 0, nil, common.ErrModelOneTimeCodeInvalid
		}
	}
	if params.CompanyName != nil && *params.CompanyName != "" {
		r, err := db.GetTenantApprovalByName(*params.CompanyName)
		if err != nil {
			logger.WithField("company-name", *params.CompanyName).
				WithError(err).
				Errorln("Failed to get tenant config based on company name.")
			if errors.Is(err, db.ErrTenantNotExists) {
				return 0, nil, common.ErrModelCompanyRegistrationNotExists
			}
			return 0, nil, common.ErrInternalErr
		}
		return 1, []models.TenantApproval{*r.ToModel()}, nil
	}
	list, total, err := db.ListTenantApproval(params.ApprovalState,
		params.Contain, params.FilterBy, params.FilterValue,
		params.SortBy, params.SortDesc, idList, params.Page, params.PageSize,
	)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get tenant registration info.")
		return 0, nil, common.ErrInternalErr
	}
	var ret []models.TenantApproval
	for _, l := range list {
		ret = append(ret, *l.ToModel())
	}
	return total, ret, nil
}

// DeleteApprovals deletes the user approval records base on the list of ID.
// Non-existing ID is not an error. It will simply be skipped.
func (h *handlerImpl) DeleteApprovals(auth interface{}, requestObject api.DeleteTenantApprovalRecordsRequestObject) error {
	token, _, _, logger := common.ParseToken(auth, "delete-tenant-approval-records", "Delete tenant approval records", h.logger)

	// Only sys admin can delete approval records.
	if token == nil || !token.IsSysAdmin {
		return common.ErrModelUnauthorized
	}
	idList := types.UUIDListToIDList(requestObject.Body)
	for _, id := range idList {
		if err := db.DeleteTenantApproval(types.TenantApprovalID(id)); err != nil {
			logger.WithField("id", id).WithError(err).Errorln("Failed")
			return common.ErrInternalErr
		}
	}
	return nil
}
func sendWelcomeEmail(namespace, email, password string) error {
	welcome := "Welcome to cylonix. Your company sign up has been approved."
	id := fmt.Sprintf("Your enterprise ID is %v.", namespace)
	login := fmt.Sprintf("Login username is your email %v and initial password is %v</p>.", email, password)
	msg := fmt.Sprintf("<p>%v %v %v</p>.", welcome, id, login)
	return sendmail.SendEmail(email, "Welcome to cylonix", msg)
}
func (h *handlerImpl) UpdateTenantRegistration(auth interface{}, requestObject api.UpdateTenantRegistrationRequestObject) (password string, err error) {
	token, _, userID, logger := common.ParseToken(auth, "update-tenant-registration", "Update tenant registration", h.logger)

	// Only sys admin can modify tenant approval records.
	if token == nil || !token.IsSysAdmin {
		return "", common.ErrModelUnauthorized
	}
	id := types.UUIDToID(requestObject.TenantRegistrationID)
	if id.IsNil() {
		err = errors.New("missing tenant registration id")
		logger.WithError(err).Errorln("Failed.")
		return "", common.NewBadParamsErr(err)
	}
	userTierID := types.UUIDToID(requestObject.Params.UserTierID)
	if userTierID.IsNil() {
		err = errors.New("missing user tier id")
		logger.WithError(err).Errorln("Failed.")
		return "", common.NewBadParamsErr(err)
	}
	if _, err = db.GetUserTier(userTierID); err != nil {
		if errors.Is(err, db.ErrUserTierNotExists) {
			err = errors.New("user tier not exists")
			logger.WithError(err).Errorln("Failed.")
			return "", common.NewBadParamsErr(err)
		} else {
			logger.WithError(err).Errorln("Failed to get user tier.")
			err = common.ErrInternalErr
		}
		return "", err
	}
	networkDomain := requestObject.Params.NetworkDomain
	if networkDomain == "" {
		err = errors.New("missing network domain")
		logger.WithError(err).Errorln("Failed.")
		return "", common.NewBadParamsErr(err)
	}

	var r *types.TenantApproval
	r, err = db.GetTenantApproval(id)
	if err != nil {
		logger.WithError(err).Errorln("Failed to get current tenant approval record.")
		return "", common.ErrInternalErr
	}
	u := requestObject.Body
	update := types.TenantApproval{
		Namespace: u.Namespace,
		Email:     optional.NilIfEmptyStringP(strings.ToLower(strings.TrimSpace(u.Email))),
		Phone:     optional.NilIfEmptyStringP(strings.ToLower(strings.TrimSpace(u.Phone))),
		Username:  u.Username,
		Password:  u.Password,
	}
	newApproval := false
	if u.ApprovalRecord != nil && u.ApprovalRecord.State != r.ApprovalState.ToModel() {
		update.ApprovalState = types.ApprovalState(u.ApprovalRecord.State)
		if u.ApprovalRecord.State == models.ApprovalStateApproved {
			newApproval = true
		}
	}

	err = db.UpdateTenantApproval(id, update, userID, token.Username, optional.String(requestObject.Params.Note))
	if err != nil {
		logger.WithError(err).Errorln("Failed to update tenant registration.")
		return "", checkTenantDBError(err)
	}

	// Handle newly approved tenant.
	if newApproval {
		password, err = h.handleNewlyApprovedTenant(
			r, &userTierID, networkDomain, userID, token.Username, logger,
		)
	}
	return
}

func (h *handlerImpl) UpdateApprovals(auth interface{}, requestObject api.UpdateTenantApprovalRecordsRequestObject) error {
	token, _, userID, logger := common.ParseToken(auth, "update-tenant-approval-records", "Update tenant approval records", h.logger)

	// Only sys admin can modify approval records.
	if token == nil || !token.IsSysAdmin {
		return common.ErrModelUnauthorized
	}
	params := requestObject.Body
	if params == nil {
		err := errors.New("empty approval params")
		logger.WithError(err).Errorln("Failed.")
		return common.NewBadParamsErr(err)
	}
	state, note := params.SetState, params.Note

	// Approve needs to be done with update tenant registration API since it
	// requires assigning a valid namespace.
	if state == models.ApprovalStateApproved {
		logger.WithError(errors.New("not allowed to approve with bulk change api")).Errorln("Failed.")
		return common.ErrModelOperationNotSupported
	}
	idList := types.UUIDListToIDList(&params.IDList)
	for _, id := range idList {
		log := logger.WithField("tenant-registration-id", id.String())
		err := db.SetTenantApprovalState(id, state, userID, token.Username, note)
		if err != nil {
			log.WithError(err).Errorln("Failed to update approval state")
			if errors.Is(err, db.ErrTenantApprovalNotExists) {
				return common.NewBadParamsErr(err)
			}
			return common.ErrInternalErr
		}
	}
	return nil
}

// IsNamespaceAvailable checks if a tenant handle aka namespace already exists.
// Note, this is an API without auth token, don't log anything above debug.
// It can be used to check the company name being available or not too.
func (h *handlerImpl) IsNamespaceAvailable(requestObject api.CheckNamespaceRequestObject) (bool, error) {
	params := requestObject.Params
	if params.Namespace == nil || *params.Namespace == "" {
		err := errors.New("missing namespace")
		return false, common.NewBadParamsErr(err)
	}
	available, err := db.TenantNameOrNamespaceAvailable(*params.Namespace)
	if err == nil && available && params.CompanyName != nil && *params.CompanyName != "" {
		available, err = db.TenantNameOrNamespaceAvailable(*params.CompanyName)
	}
	if err != nil {
		// Internal error.
		h.logger.WithFields(logrus.Fields{
			ulog.Handle:    "check-namespace",
			ulog.Namespace: *params.Namespace,
			"company-name": optional.String(params.CompanyName),
		}).WithError(err).Errorln("Failed.")
		return false, common.ErrInternalErr
	}
	return available, nil
}

// TenantSummary gets the latest summary or summary history of the tenant.
// Only sys admin can get other namespace's summary.
func (h *handlerImpl) TenantSummary(auth interface{}, requestObject api.GetTenantSummaryRequestObject) (list models.SummaryStatsList, err error) {
	token, namespace, _, logger := common.ParseToken(auth, "tenant-summary", "Get tenant summary", h.logger)
	if token == nil || (!token.IsAdminUser && !token.IsSysAdmin) {
		return nil, common.ErrModelUnauthorized
	}
	params := requestObject.Params
	if params.Namespace != nil && *params.Namespace != namespace {
		namespace = *params.Namespace
		logger = logger.WithField("target-namespace", namespace)
		if !token.IsSysAdmin {
			logger.Warnln("Non-sysadmin accessing other namespace.")
			return nil, common.ErrModelUnauthorized
		}
	}
	if params.Days == nil || *params.Days < 1 {
		s, err := db.LastNamespaceSummaryStat(namespace)
		if err != nil {
			logger.WithError(err).Errorln("Failed to get tenant latest summary.")
			return nil, common.ErrInternalErr
		}
		list = append(list, *s)
	} else {
		days := int(*params.Days)
		logger = logger.WithField("days", days)
		if list, err = metrics.NamespaceSummaryStats(namespace, days); err != nil {
			logger.WithError(err).Errorln("Get tenant summary failed.")
			return nil, common.ErrInternalErr
		}
	}
	return
}
