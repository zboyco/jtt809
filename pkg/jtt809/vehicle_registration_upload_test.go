package jtt809

import (
	"strings"
	"testing"
)

func TestVehicleRegistrationUploadEncode(t *testing.T) {
	body := VehicleRegistrationUpload{
		VehicleNo:         "粤A12345",
		VehicleColor:      PlateColorBlue,
		PlatformID:        "1111111111",
		ProducerID:        "1111111111",
		TerminalModelType: "11111111",
		IMEI:              "123456789",
		TerminalID:        "11111aa", // 输入小写，编码时应转为大写
		TerminalSIM:       "222222222222",
	}

	data, err := EncodePackage(Package{Header: Header{GNSSCenterID: 0x01020304}, Body: body})
	if err != nil {
		t.Fatalf("encode registration upload: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	if frame.BodyID != MsgIDDynamicInfo {
		t.Fatalf("unexpected body id: %x", frame.BodyID)
	}

	sub, err := ParseSubBusiness(frame.RawBody)
	if err != nil {
		t.Fatalf("parse sub business: %v", err)
	}
	if sub.SubBusinessID != SubMsgUploadVehicleReg {
		t.Fatalf("unexpected sub business id: %x", sub.SubBusinessID)
	}
	if sub.PayloadLength != 110 {
		t.Fatalf("unexpected payload length: %d", sub.PayloadLength)
	}
	payload := sub.Payload
	if len(payload) != int(sub.PayloadLength) {
		t.Fatalf("payload length mismatch: %d vs %d", len(payload), sub.PayloadLength)
	}

	readStr := func(start, n int) string {
		return strings.TrimRight(string(payload[start:start+n]), "\x00")
	}
	if got := readStr(0, 11); got != body.PlatformID {
		t.Fatalf("platform id mismatch: %s", got)
	}
	if got := readStr(11, 11); got != body.ProducerID {
		t.Fatalf("producer id mismatch: %s", got)
	}
	if got := readStr(22, 30); got != body.TerminalModelType {
		t.Fatalf("model mismatch: %s", got)
	}
	if got := readStr(52, 15); got != body.IMEI {
		t.Fatalf("imei mismatch: %s", got)
	}
	if got := readStr(67, 30); got != strings.ToUpper(body.TerminalID) {
		t.Fatalf("terminal id mismatch: %s", got)
	}
	if got := readStr(97, 13); got != body.TerminalSIM {
		t.Fatalf("sim mismatch: %s", got)
	}
}
