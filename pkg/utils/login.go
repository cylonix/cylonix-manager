// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package utils

import (
	"log"
	"os"
	"strings"

	"github.com/cylonix/utils/apikey"
	gviper "github.com/spf13/viper"
)

var (
	noTLS = false // Set to false in production!
	viper *gviper.Viper
)

func LoginInit(viperIn *gviper.Viper) {
	viper = viperIn
	if noTLS {
		return
	}
	env := strings.ToLower(viper.GetString("CYLONIX_MANAGER_NO_TLS"))
	if env == "" {
		log.Println("Trying to get no-TLS setting from env")
		env = strings.ToLower(os.Getenv("CYLONIX_MANAGER_NO_TLS"))
	}
	log.Printf("Login no TLS setting: %v\n", env)
	if env == "yes" || env == "1" || env == "true" {
		log.Println("Login no TLS is set to true")
		noTLS = true
		return
	}
	baseURL := strings.ToLower(viper.GetString("base_url"))
	if !strings.HasPrefix(baseURL, "https") {
		noTLS = true
		return
	}
}

func CookieSecureString() string {
	if noTLS {
		return ""
	}
	return "Secure;"
}

func ApiKeyCookieName() string {
	if noTLS {
		return apikey.ApiKeyCookieName
	}
	return apikey.SecureApiKeyCookieName
}

func LoginCookieName() string {
	if noTLS {
		return apikey.LoginCookieName
	}
	return apikey.SecureLoginCookieName
}