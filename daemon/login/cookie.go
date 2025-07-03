package login

import (
	pu "cylonix/sase/pkg/utils"
	"cylonix/sase/pkg/vpn"
	"encoding/json"
	"fmt"
)

type loginCookie struct {
	IsAdminUser   bool   `json:"is_admin_user"`
	IsSysAdmin    bool   `json:"is_sys_admin"`
	Email         string `json:"email"`
	CompanyId     string `json:"company_id"`
	CompanyName   string `json:"company_name"`
	DisplayName   string `json:"display_name"`
	ProfilePicURL string `json:"profile_pic_url"`
}

func cookie(id, c, path string, maxAgeSeconds int) string {
	secure := pu.CookieSecureString()
	return fmt.Sprintf("%v=%v; Path=%v; Max-Age=%v; %v HttpOnly", id, c, path, maxAgeSeconds, secure)
}

func (c loginCookie) toCookie() (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	return cookie(pu.LoginCookieName(), string(b), "/", 1800), nil
}

func apiKeyCookie(token string, maxAgeSeconds int) string {
	return cookie(pu.ApiKeyCookieName(), token, "/", maxAgeSeconds)
}

func apiKeyDeleteCookie() string {
	return cookie(pu.ApiKeyCookieName(), "", "/", 1)
}

func vpnAPIKeyCookie(key string, maxAgeSeconds int) string {
	return cookie(vpn.VpnAPIKeyCookieName, key, "/", maxAgeSeconds)
}