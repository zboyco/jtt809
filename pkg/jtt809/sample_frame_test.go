package jtt809

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDecodeSampleFrame(t *testing.T) {
	hexFrame := `5B 00 00 00 C9 00 00 06 82 17 00 01 34 15 F4 01 00 00 00 00 00 27 0F 00 00 00 00 5E 02 A5 07 B8 D4 C1 41 31 32 33 34 35 00 00 00 00 00 00 00 00 00 00 00 00 00 02 17 01 00 00 00 8B 01 02 03 04 05 06 07 08 09 10 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 E7 D3 5D`
	data, err := hexStringToBytes(hexFrame)
	if err != nil {
		t.Fatalf("parse hex string: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	if frame.Header.MsgLength != 201 {
		t.Fatalf("unexpected msg length: %d", frame.Header.MsgLength)
	}

	// 样例中的时间字段值为 0x5EA507B8（UTC 秒）。
	expectedTime := time.Unix(0x5EA507B8, 0).UTC()
	if !frame.Header.Timestamp.Equal(expectedTime) {
		t.Fatalf("timestamp mismatch: got %v expected %v (unix=%d)", frame.Header.Timestamp, expectedTime, frame.Header.Timestamp.Unix())
	}
	if frame.BodyID != 0x1700 {
		t.Fatalf("unexpected body id: %x", frame.BodyID)
	}
	if frame.Header.GNSSCenterID != 20190708 {
		t.Fatalf("unexpected GNSSCenterID: %d", frame.Header.GNSSCenterID)
	}
	if len(frame.RawBody) != 167 {
		t.Fatalf("unexpected raw body length: %d", len(frame.RawBody))
	}
	dyn, err := ParseMainDynamic(frame.RawBody)
	if err != nil {
		t.Fatalf("parse dynamic: %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(dyn.PlateRaw, "\x00"), []byte{0xD4, 0xC1, 'A', '1', '2', '3', '4', '5'}) {
		t.Fatalf("unexpected plate bytes: %x", dyn.PlateRaw)
	}
	t.Logf("plate=%s (hex=%x) color=0x%02x", dyn.Plate, dyn.PlateRaw, dyn.Color)

	if dyn.Color != 0x02 {
		t.Fatalf("unexpected vehicle color: %d", dyn.Color)
	}
	if dyn.SubBusinessID != 0x1701 {
		t.Fatalf("unexpected sub business type: %x", dyn.SubBusinessID)
	}
	if int(dyn.PayloadLength) != len(dyn.Payload) {
		t.Fatalf("payload length mismatch: length=%d actual=%d", dyn.PayloadLength, len(dyn.Payload))
	}
	payload := dyn.Payload
	// 前缀为平台 ID 等字段，样例以 1..11 递增开头。
	expectedPrefix := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11}
	if !bytes.Equal(payload[:len(expectedPrefix)], expectedPrefix) {
		t.Fatalf("payload prefix mismatch: %x", payload[:len(expectedPrefix)])
	}
	if bytes.Count(payload, []byte{0x00}) < 100 {
		t.Fatalf("payload zero padding not as expected")
	}
	t.Logf("crc=0x%04X end=0x%02X", binary.BigEndian.Uint16(data[len(data)-3:len(data)-1]), data[len(data)-1])
}

func hexStringToBytes(src string) ([]byte, error) {
	fields := strings.Fields(src)
	buf := make([]byte, len(fields))
	for i, f := range fields {
		v, err := strconv.ParseUint(f, 16, 8)
		if err != nil {
			return nil, err
		}
		buf[i] = byte(v)
	}
	return buf, nil
}
