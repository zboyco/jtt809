package jtt1078

import (
	"net/http"
	"net/url"
	"strings"
)

// parseRequest parses the HTTP request to extract the target URL and client IP
func parseRequest(r *http.Request) (string, string) {
	u := r.URL.Query().Get("url")
	if decoded, err := url.QueryUnescape(u); err == nil && strings.HasPrefix(decoded, "http") {
		u = decoded
	}
	return u, r.RemoteAddr
}

// shortenURL shortens a URL for logging purposes
func shortenURL(u string) string {
	if len(u) > 50 {
		return u[len(u)-50:]
	}
	return u
}
