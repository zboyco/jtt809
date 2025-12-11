package jtt1078

import (
	"net/http"
	"net/url"
	"strings"
)

// ParseRequestFunc defines the signature for parsing incoming HTTP requests.
// It returns the target URL and client IP.
// Returns:
//   - jtt1078RtpURL: The target URL for the JT/T 1078-2016 RTP stream.
//   - clientAddr: The client IP address.
type ParseRequestFunc func(r *http.Request) (jtt1078RtpURL string, clientAddr string)

// defaultParseRequest parses the HTTP request to extract the target URL and client IP.
func defaultParseRequest(r *http.Request) (string, string) {
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
