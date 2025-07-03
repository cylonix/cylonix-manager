package daemon

import (
	_errors "errors"
	"log"
	"net/http"
	"os"

	"github.com/cylonix/utils"
	"github.com/cylonix/utils/apikey"
	"github.com/google/uuid"

	"github.com/go-openapi/errors"
)

var (
	debugAuth = true
)

type authenticator struct{}

func getToken(r *http.Request) string {
	return apikey.Parse(r)
}

func (a *authenticator) AdminAPIKeyAuth(r *http.Request) (interface{}, error) {
	return adminAuthenticate(getToken(r))
}
func (a *authenticator) InternalAPIKeyAuth(r *http.Request) (interface{}, error) {
	return internalAuthenticate(getToken(r))
}
func (a *authenticator) SysAPIKeyAuth(r *http.Request) (interface{}, error) {
	return sysAuthenticate(getToken(r))
}
func (a *authenticator) UserAPIKeyAuth(r *http.Request) (interface{}, error) {
	return userAuthenticate(getToken(r), false)
}
func (a *authenticator) UserAPIKeyFromApprovedDeviceAuth(r *http.Request) (interface{}, error) {
	return userAuthenticate(getToken(r), true)
}
func (a *authenticator) NoAuthAuth(r *http.Request) (interface{}, error) {
	return &utils.UserTokenData{}, nil
}

func internalAuthenticate(token string) (interface{}, error) {
	data, err := utils.CheckApiKey(token)
	if err == nil {
		return data, nil
	}
	if _errors.Is(err, utils.ErrInternalErr) {
		return nil, errors.New(500, "internal error for internal api key auth")
	}
	return nil, errors.New(401, "incorrect api key auth for internal")
}

func adminAuthenticate(token string) (interface{}, error) {
	s := utils.ShortStringN(token, 20)
	if debugAuth {
		log.Printf("%s admin auth", s)
	}
	v, err := sysAuthenticate(token)
	if err == nil {
		return v, nil
	}
	t := utils.AdminToken{
		Token: token,
	}
	data := &utils.UserTokenData{}
	err = t.Get(data)
	if err == nil {
		if debugAuth {
			log.Printf("%s found the admin token", s)
		}
		return data, nil
	}
	if debugAuth {
		log.Printf("%s admin token not found: %v", s, err)
	}

	if _errors.Is(err, utils.ErrInternalErr) {
		return nil, errors.New(500, "internal error for admin api key auth")
	}
	return nil, errors.New(401, "incorrect api key auth for admin")
}

func sysAuthenticate(token string) (interface{}, error) {
	t := utils.SysAdminToken{Token: token}
	data := &utils.UserTokenData{}
	err := t.Get(data)
	if err == nil {
		return data, nil
	}
	if _errors.Is(err, utils.ErrInternalErr) {
		return nil, errors.New(500, "internal error for sys admin api key auth")
	}
	if token != "" && token == os.Getenv("SASE_MGR_SYS_TOKEN") {
		return &utils.UserTokenData{
			IsAdminUser: true,
			IsSysAdmin:  true,
			Username:    os.Getenv("SASE_MGR_SYS_TOKEN_USER"),
			Namespace:   os.Getenv("SASE_MGR_SYS_TOKEN_NAMESPACE"),
			UserID:      uuid.New(),
		}, nil
	}
	return nil, errors.New(401, "incorrect api key auth for sys admin user")
}

func userAuthenticate(token string, mustFromApprovedDevice bool) (interface{}, error) {
	t := utils.UserToken{
		Token: token,
	}
	s := utils.ShortStringN(token, 20)
	if debugAuth {
		log.Printf("%s user auth", s)
	}
	data := &utils.UserTokenData{}
	err := t.Get(data)
	if err == nil {
		if debugAuth {
			log.Printf("%s user auth found", s)
		}
		if !mustFromApprovedDevice {
			return data, nil
		}
		if data.FromApprovedDevice {
			return data, nil
		}
		if debugAuth {
			log.Printf("%s user auth not from approved device", s)
		}
		return nil, errors.New(401, "not from approved device")
	}
	if debugAuth {
		log.Printf("%s user token not found: %v", s, err)
	}
	if _errors.Is(err, utils.ErrInternalErr) {
		return nil, errors.New(500, "internal error for user api key auth from approved device")
	}
	return nil, errors.New(401, "incorrect api key or device not yet approved")
}
