package jtt809

import "testing"

func TestBatchLocationUploadEncode2019(t *testing.T) {
	pos := &VehiclePosition{
		Encrypt:     1,
		GnssData:    nil,
		PlatformID1: "11111111111",
		Alarm1:      1,
		PlatformID2: "22222222222",
		Alarm2:      2,
		PlatformID3: "33333333333",
		Alarm3:      3,
	}
	body := BatchLocationUpload{
		VehicleNo:    "粤B00001",
		VehicleColor: VehicleColorYellow,
		Locations: []BatchLocationRecord{
			{Position: pos},
			{Position: pos},
		},
	}
	data, err := EncodePackage(Package{Header: Header{GNSSCenterID: 0x0fedcba}, Body: body})
	if err != nil {
		t.Fatalf("encode batch upload: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	sub, err := ParseSubBusiness(frame.RawBody)
	if err != nil {
		t.Fatalf("parse sub business: %v", err)
	}
	if sub.SubBusinessID != SubMsgBatchLocation {
		t.Fatalf("unexpected sub business id: %x", sub.SubBusinessID)
	}
	if sub.PayloadLength != 101 {
		t.Fatalf("unexpected payload length: %d", sub.PayloadLength)
	}
	payload := sub.Payload
	if len(payload) != int(sub.PayloadLength) {
		t.Fatalf("payload length mismatch: %d vs %d", len(payload), sub.PayloadLength)
	}
	if payload[0] != 2 {
		t.Fatalf("unexpected gnss count: %d", payload[0])
	}

	recordLen := 50 // 2019 定位无 GNSS 数据时的长度
	for i := 0; i < 2; i++ {
		start := 1 + i*recordLen
		p, err := ParseVehiclePosition2019(payload[start : start+recordLen])
		if err != nil {
			t.Fatalf("parse position %d: %v", i, err)
		}
		if p.PlatformID1 != pos.PlatformID1 || p.Alarm2 != pos.Alarm2 || p.PlatformID3 != pos.PlatformID3 {
			t.Fatalf("position %d mismatch: %+v", i, p)
		}
	}
}
