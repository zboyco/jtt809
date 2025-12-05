package jtt809

import (
	"testing"
)

func TestLoginEncodeAndDecode(t *testing.T) {
	req := LoginRequest{
		UserID:       10001,
		Password:     "123456",
		DownLinkIP:   "127.0.0.1",
		DownLinkPort: 8080,
	}
	encoded, err := req.Encode()
	if err != nil {
		t.Fatalf("encode failed: %v", err)
	}

	decoded, err := ParseLoginRequest(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	if decoded.UserID != req.UserID {
		t.Errorf("expected user id %d, got %d", req.UserID, decoded.UserID)
	}
	if decoded.Password != req.Password {
		t.Errorf("expected password %s, got %s", req.Password, decoded.Password)
	}
	if decoded.DownLinkIP != req.DownLinkIP {
		t.Errorf("expected ip %s, got %s", req.DownLinkIP, decoded.DownLinkIP)
	}
	if decoded.DownLinkPort != req.DownLinkPort {
		t.Errorf("expected port %d, got %d", req.DownLinkPort, decoded.DownLinkPort)
	}
}

func TestLoginRequestValidate(t *testing.T) {
	req := LoginRequest{
		UserID:       10001,
		Password:     "123456789", // too long
		DownLinkIP:   "127.0.0.1",
		DownLinkPort: 8080,
	}
	if _, err := req.Encode(); err == nil {
		t.Fatalf("expected password length error")
	}
}
