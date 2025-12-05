package jtt809

import (
	"encoding/binary"
	"testing"
)

func TestVehicleLocationUploadEncode(t *testing.T) {
	gnss := []byte{0x01, 0x02, 0x03, 0x04}
	pos := &VehiclePosition{
		Encrypt:     1,
		GnssData:    gnss,
		PlatformID1: "11000000001",
		PlatformID2: "11000000002",
		PlatformID3: "11000000003",
		Alarm1:      1,
		Alarm2:      2,
		Alarm3:      3,
	}
	body := VehicleLocationUpload{
		VehicleNo:    "粤B00001",
		VehicleColor: 2,
		Position:     pos,
	}
	data, err := EncodePackage(Package{
		Header: Header{GNSSCenterID: 88},
		Body:   body,
	})
	if err != nil {
		t.Fatalf("encode vehicle upload: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}

	raw := frame.RawBody
	length := binary.BigEndian.Uint32(raw[24:28])
	const expectedLen = 54
	if length != expectedLen {
		t.Fatalf("unexpected length: %d", length)
	}
	parsed, err := ParseVehiclePosition(raw[28:])
	if err != nil {
		t.Fatalf("parse position: %v", err)
	}
	if parsed.Alarm3 != pos.Alarm3 || len(parsed.GnssData) != len(gnss) {
		t.Fatalf("position mismatch: %+v", parsed)
	}
}

func TestVehicleLocationUploadRequirePosition(t *testing.T) {
	body := VehicleLocationUpload{
		VehicleNo:    "粤B00001",
		VehicleColor: VehicleColorBlue,
	}
	if _, err := body.Encode(); err == nil {
		t.Fatalf("expected encode error when position is missing")
	}
}
