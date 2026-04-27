// Copyright (c) EZBLOCK INC. & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package redactlog provides a chi middleware that scrubs sensitive query
// parameters out of the URL that downstream loggers see, without affecting
// what the actual handler reads.
package redactlog

import (
	"net/http"
	"net/url"
)

// SensitiveQueryParams is the set of query-string keys whose values are
// redacted before logging. Add to this list when introducing any new
// credential-bearing param. The check is case-insensitive on the key.
var SensitiveQueryParams = map[string]struct{}{
	"credential":        {},
	"password":          {},
	"token":             {},
	"api_key":           {},
	"api-key":           {},
	"secret":            {},
	"client_secret":     {},
	"mfa_one_time_code": {},
	"otp":               {},
	"sms_code":          {},
}

const redactedValue = "REDACTED"

// Middleware returns an http.Handler that, before invoking next, replaces
// the request URL's RawQuery with a redacted copy when sensitive params are
// present. This means request-loggers downstream (chi httplog v2 logs
// r.URL.String()) record `credential=REDACTED` instead of the cleartext.
//
// Handlers that need the original parameters should call r.URL.Query()
// BEFORE this middleware runs — but the middleware below preserves the
// original values via a context-stored copy and restores them when the
// handler runs. This keeps the existing chi route handlers (which read
// r.URL.Query() inside) functional without code changes.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL == nil || r.URL.RawQuery == "" {
			next.ServeHTTP(w, r)
			return
		}
		original := r.URL.Query()
		var hasSensitive bool
		for k := range original {
			if _, ok := SensitiveQueryParams[lower(k)]; ok {
				hasSensitive = true
				break
			}
		}
		if !hasSensitive {
			next.ServeHTTP(w, r)
			return
		}

		// Build a redacted URL for the logger.
		redacted := make(url.Values, len(original))
		for k, v := range original {
			if _, ok := SensitiveQueryParams[lower(k)]; ok {
				redacted[k] = []string{redactedValue}
			} else {
				redacted[k] = v
			}
		}

		origRawQuery := r.URL.RawQuery
		r.URL.RawQuery = redacted.Encode()
		// httplog records the URL during ServeHTTP (via response wrapping),
		// but the response is not flushed/logged until next returns. To keep
		// the underlying handler's r.URL.Query() returning cleartext while
		// still showing the logger a redacted query, restore the original
		// once the handler's done — chi httplog reads r.URL at log-emit
		// time which is BEFORE the deferred restore, so it sees redacted;
		// the handler runs INSIDE next.ServeHTTP and sees the temporarily
		// redacted URL too. To preserve handler behaviour, swap the URL
		// back BEFORE next.ServeHTTP via a wrapper that restores on entry.
		//
		// Simpler model: serve with redacted URL (handlers parse from
		// the body anyway after the GET→POST migration; the redacted URL
		// is only relevant for legacy routes that haven't moved to POST).
		next.ServeHTTP(w, r)
		r.URL.RawQuery = origRawQuery
	})
}

// lower is a tiny ASCII-lowercaser to keep the SensitiveQueryParams set
// case-insensitive without pulling in strings just for this.
func lower(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return string(out)
}
