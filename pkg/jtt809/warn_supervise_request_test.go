package jtt809

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestWarnSuperviseRequestEncode(t *testing.T) {
	req := WarnSuperviseRequest{
		VehicleNo:       "粤A12345",
		VehicleColor:    PlateColorBlue,
		WarnSource:      WarnSrcVehicle,
		WarnType:        WarnTypeFatigueDriving,
		WarnTime:        time.Date(2018, 9, 27, 10, 24, 0, 0, time.UTC),
		SupervisionID:   "123FFAA1",
		EndTime:         time.Date(2018, 9, 27, 11, 24, 0, 0, time.UTC),
		Level:           SupervisionLevelNormal,
		Supervisor:      "smallchi",
		SupervisorTel:   "12345678901",
		SupervisorEmail: "123456@qq.com",
	}
	data, err := EncodePackage(Package{Header: Header{GNSSCenterID: 0x1357}, Body: req})
	if err != nil {
		t.Fatalf("encode warn supervise: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	sub, err := ParseSubBusiness(frame.RawBody)
	if err != nil {
		t.Fatalf("parse sub business: %v", err)
	}
	if sub.SubBusinessID != SubMsgWarnSuperviseReq {
		t.Fatalf("unexpected sub business id: %x", sub.SubBusinessID)
	}
	if sub.PayloadLength != 92 {
		t.Fatalf("unexpected payload length: %d", sub.PayloadLength)
	}
	parsed, err := ParseWarnSuperviseRequest(sub.Payload)
	if err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if parsed.WarnSource != req.WarnSource || parsed.WarnType != req.WarnType || parsed.Level != req.Level {
		t.Fatalf("parsed warn info mismatch: %+v", parsed)
	}
	if !parsed.WarnTime.Equal(req.WarnTime) || !parsed.EndTime.Equal(req.EndTime) {
		t.Fatalf("time mismatch: warn=%v end=%v", parsed.WarnTime, parsed.EndTime)
	}
	if parsed.SupervisionID != "123FFAA1" || parsed.Supervisor != req.Supervisor || parsed.SupervisorTel != req.SupervisorTel || parsed.SupervisorEmail != req.SupervisorEmail {
		t.Fatalf("string fields mismatch: %+v", parsed)
	}
}

func TestWarnSuperviseRequestParseHex(t *testing.T) {
	hexStr := "010002000000005BAC3F40123FFAA1000000005BAC4D5001736D616C6C636869000000000000000031323334353637383930310000000000000000003132333435364071712E636F6D00000000000000000000000000000000000000"
	payload, _ := hex.DecodeString(hexStr)
	req, err := ParseWarnSuperviseRequest(payload)
	if err != nil {
		t.Fatalf("parse warn supervise payload: %v", err)
	}
	if req.WarnSource != WarnSrcVehicle || req.WarnType != WarnTypeFatigueDriving || req.Level != SupervisionLevelNormal {
		t.Fatalf("field mismatch: %+v", req)
	}
	expectedWarn := time.Date(2018, 9, 27, 10, 24, 0, 0, time.UTC)
	expectedEnd := time.Date(2018, 9, 27, 11, 24, 0, 0, time.UTC)
	if !req.WarnTime.Equal(expectedWarn) || !req.EndTime.Equal(expectedEnd) {
		t.Fatalf("time mismatch: warn=%v end=%v", req.WarnTime, req.EndTime)
	}
	if req.SupervisionID != "123FFAA1" || req.Supervisor != "smallchi" || req.SupervisorTel != "12345678901" || req.SupervisorEmail != "123456@qq.com" {
		t.Fatalf("string fields mismatch: %+v", req)
	}
}
