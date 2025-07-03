package login

import (
	"cylonix/sase/api/v2/models"
	"cylonix/sase/daemon/common"
	"cylonix/sase/daemon/db"
	"cylonix/sase/daemon/db/types"
	"cylonix/sase/pkg/optional"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cylonix/utils"
	"github.com/sirupsen/logrus"
)

const (
	maxNetworkDomainRetries = 5
)

func newUserApproval(login *types.UserLogin) *models.UserApprovalInfo {
	return &models.UserApprovalInfo{
		Login: *login.ToModel(),
		ApprovalRecord: &models.ApprovalRecord{
			State: models.ApprovalStatePending,
		},
	}
}

// getUser returns the user and the login for the user.
// If the user does not exist, it creates a new user and returns the user and
// the login for the default namespace. For other namespaces, the approval state
// is returned instead of the user. Sysadmin user must be provisioned by the
// deployment process or added by another sysadmin user.
func getUser(
	isSysAdmin bool, login *types.UserLogin, email, phone string,
	roles []string, attributes map[string][]string, networkDomain *string,
	logger *logrus.Entry,
) (loginUser *types.UserLogin, user *types.User, state *types.ApprovalState, err error) {
	namespace := login.Namespace
	loginUser, err = db.GetUserLoginByLoginNameFast(namespace, login.LoginName)
	if err == nil {
		user, err = db.GetUserFast(namespace, loginUser.UserID, true)
		if err != nil {
			err = fmt.Errorf("failed to get user by login: %w", err)
			return
		}
		return
	}
	if !errors.Is(err, db.ErrUserLoginNotExists) {
		err = fmt.Errorf("failed to get user login from db: %w", err)
		return
	} else {
		s, _ := json.Marshal(login)
		logger.WithField("login", string(s)).Debugln("user login does not exist!")
	}

	// No entry exists.
	if isSysAdmin {
		err = fmt.Errorf("sysadmin user must be provisioned or added by another sysadmin user")
		return
	}

	// Only allow auto sign up from default namespace users. Other namespaces
	// has to be approved first.
	if !utils.IsDefaultNamespace(namespace) {
		exists := false
		exists, err = db.UserApprovalExists(namespace, login.LoginName)
		if err != nil {
			err = fmt.Errorf("failed to check if user approval exists: %w", err)
			return
		}
		if !exists {
			userRegisterInfo := newUserApproval(login)
			if _, err = db.NewUserApproval(userRegisterInfo, types.NilID, "", ""); err != nil {
				return nil, nil, nil, fmt.Errorf("failed to add user approval: %w", err)
			}
			// Fall through to get the registration state.
		}
		state, err = db.GetUserApprovalState(namespace, login.LoginName)
		if err != nil {
			err = fmt.Errorf("failed to get user register info: %w", err)
			return
		}
		// Note the state cannot be approved here as the user would have been
		// created already for approved request.
		if *state == types.ApprovalStateApproved {
			err = fmt.Errorf("user already approved but not created")
		}
		return
	}

	// Automatically add new user for default namespace users.
	if email == "" {
		email = login.Email
	}
	if phone == "" {
		phone = login.Phone()
	}

	// If user is invited into a network domain, the network domain passed in
	// should be used. If not, a new network domain is created and the user is
	// added to the network domain as an admin.
	if optional.String(networkDomain) == "" {
		networkDomain, err = getNetworkDomainForNewUser(login, logger)
		if err != nil {
			err = fmt.Errorf("failed to get network domain for new user: %w", err)
			return
		}
		roles = append(roles, types.NetworkDomainAdminRole)
	}
	tier := optional.P(utils.DefaultUserTier)
	user, err = db.AddUser(
		namespace, email, phone, login.DisplayName, []types.UserLogin{*login},
		roles, attributes, tier, networkDomain, nil,
	)
	if err != nil {
		err = fmt.Errorf("failed to create new user with the new login: %w", err)
		return
	}
	login.UserID = user.ID
	return login, user, nil, nil
}

// getNetworkDomainForNewUser returns the network domain for a new user.
// For custom domain for the provider e.g. google workplace user, Tailscale
// lumps all users of the custom doamin into the same network domain without
// verifying if indeed they are the owners or exclusive users of the domain. We
// opt to not do that. Users who want to add other users of the same custom
// doamin to the same network domain should do so via invitations.
func getNetworkDomainForNewUser(login *types.UserLogin, log *logrus.Entry) (*string, error) {
	if login.Provider == "" {
		return nil, fmt.Errorf("only oauth login can be used to create new user automatically")
	}
	domain := getEmailDomain(login.LoginName)
	provider := getProviderFromDomain(domain)
	if provider != login.Provider {
		if existingUser, err := db.GetUserByEmailDomainOrNil(domain); existingUser != nil && err == nil {
			v := optional.String(existingUser.NetworkDomain)
			log.WithField("user", existingUser.UserBaseInfo.LoginName).
				WithField("domain", domain).
				WithField("network-domain", v).
				Warnln(`
					Domain already exists for another user. Check if domain
					is exclusive and invite other users to join the same network
					domain instead.
				`)
		}
	}
	// Create new network domain for the user.
	for i := 0; i < maxNetworkDomainRetries; i++ {
		domain := common.GenrateNetworkDomain()
		inUse, err := db.IsNetworkDomainInUse(domain)
		if err != nil {
			return nil, fmt.Errorf("failed to check if network domain is in use: %w", err)
		}
		if inUse {
			log.WithField("domain", domain).Debugln("network domain in use, retrying...")
			continue
		}
		return &domain, nil
	}
	return nil, fmt.Errorf("failed to create network domain for new user")
}
