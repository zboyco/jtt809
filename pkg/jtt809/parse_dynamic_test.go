package jtt809

import "testing"

func TestParsePlatformQueryAck(t *testing.T) {
	payload := make([]byte, 1+16+20+20+2+4+4+6)
	offset := 0
	payload[offset] = 1
	offset++
	copy(payload[offset:], []byte("responder\x00\x00\x00\x00\x00\x00"))
	offset += 16
	copy(payload[offset:], []byte("13800138000\x00\x00\x00\x00\x00\x00\x00\x00\x00"))
	offset += 20
	copy(payload[offset:], []byte("OBJID123456789012"))
	offset += 20
	payload[offset] = 0x13
	payload[offset+1] = 0x01
	offset += 2
	payload[offset+0] = 0
	payload[offset+1] = 0
	payload[offset+2] = 0
	payload[offset+3] = 5
	offset += 4
	payload[offset+0] = 0
	payload[offset+1] = 0
	payload[offset+2] = 0
	payload[offset+3] = 6
	offset += 4
	copy(payload[offset:], []byte("infos!"))

	pkt := &SubBusinessPacket{
		Plate:         "TEST",
		Color:         VehicleColorBlue,
		SubBusinessID: SubMsgPlatformQueryAck,
		Payload:       payload,
		PayloadLength: uint32(len(payload)),
	}
	info, err := ParsePlatformQueryAck(pkt)
	if err != nil {
		t.Fatalf("parse platform ack: %v", err)
	}
	if info.InfoContent != "infos!" {
		t.Fatalf("unexpected info content: %s", info.InfoContent)
	}
	if info.SourceDataType != 0x1301 || info.SourceMsgSN != 5 {
		t.Fatalf("unexpected source info: %x %d", info.SourceDataType, info.SourceMsgSN)
	}
}
