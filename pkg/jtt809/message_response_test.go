package jtt809

import (
	"encoding/binary"
	"testing"
)

func TestGenerateLoginResponse(t *testing.T) {
	req := LoginRequest{
		UserID:       12345,
		Password:     "password",
		GnssCenterID: 0xAA55,
		DownLinkIP:   "127.0.0.1",
		DownLinkPort: 8080,
	}
	header := Header{GNSSCenterID: 7}
	data, err := EncodePackage(Package{Header: header, Body: req})
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	respPkg, err := GenerateResponse(frame, SimpleAuthValidator(req.UserID, req.Password, req.GnssCenterID, 0xAA55))
	if err != nil {
		t.Fatalf("generate response: %v", err)
	}
	respData, err := EncodePackage(*respPkg)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	respFrame, err := DecodeFrame(respData)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if respFrame.Header.BusinessType != MsgIDLoginResponse {
		t.Fatalf("unexpected response type: %x", respFrame.Header.BusinessType)
	}
	if len(respFrame.RawBody) < 5 {
		t.Fatalf("response body too short")
	}
	if respFrame.RawBody[0] != byte(LoginOK) {
		t.Fatalf("bad result: %x", respFrame.RawBody[0])
	}
	verify := binary.BigEndian.Uint32(respFrame.RawBody[1:5])
	if verify != 0xAA55 {
		t.Fatalf("unexpected verify code: %x", verify)
	}
}
