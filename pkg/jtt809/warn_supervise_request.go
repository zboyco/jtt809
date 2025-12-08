package jtt809

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// WarnSuperviseRequest 表示报警督办请求子业务（0x9401），下发给车属平台。
type WarnSuperviseRequest struct {
	VehicleNo    string
	VehicleColor PlateColor

	WarnSource      WarnSrc
	WarnType        WarnType
	WarnTime        time.Time
	SupervisionID   string
	EndTime         time.Time
	Level           SupervisionLevel
	Supervisor      string
	SupervisorTel   string
	SupervisorEmail string
}

func (WarnSuperviseRequest) MsgID() uint16 { return MsgIDAlarmInteract }

// Encode 构造 0x1400 主业务下的 0x9401 子业务报文。
func (w WarnSuperviseRequest) Encode() ([]byte, error) {
	if len(w.VehicleNo) == 0 {
		return nil, errors.New("vehicle number is required")
	}
	body, err := w.encodePayload()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(PadRightGBK(w.VehicleNo, 21))
	buf.WriteByte(byte(w.VehicleColor))
	_ = binary.Write(&buf, binary.BigEndian, SubMsgWarnSuperviseReq)
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(body)))
	buf.Write(body)
	return buf.Bytes(), nil
}

func (w WarnSuperviseRequest) encodePayload() ([]byte, error) {
	if w.WarnTime.IsZero() || w.EndTime.IsZero() {
		return nil, errors.New("warn time and end time are required")
	}
	if len(w.SupervisionID) == 0 {
		return nil, errors.New("supervision id is required")
	}
	var buf bytes.Buffer
	buf.WriteByte(byte(w.WarnSource))
	_ = binary.Write(&buf, binary.BigEndian, uint16(w.WarnType))
	putUTCSeconds(&buf, w.WarnTime)
	id, err := decodeHexString(w.SupervisionID, 4)
	if err != nil {
		return nil, fmt.Errorf("supervision id: %w", err)
	}
	buf.Write(id)
	putUTCSeconds(&buf, w.EndTime)
	buf.WriteByte(byte(w.Level))
	buf.Write(PadRightGBK(w.Supervisor, 16))
	buf.Write(PadRightGBK(w.SupervisorTel, 20))
	buf.Write(PadRightGBK(w.SupervisorEmail, 32))
	return buf.Bytes(), nil
}

// ParseWarnSuperviseRequest 解析 0x9401 子业务载荷。
func ParseWarnSuperviseRequest(payload []byte) (*WarnSuperviseRequest, error) {
	if len(payload) < 1+2+8+4+8+1+16+20+32 {
		return nil, errors.New("payload too short for warn supervise request")
	}
	offset := 0
	src := WarnSrc(payload[offset])
	offset++
	typ := WarnType(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	warnTime := parseUTCSeconds(payload[offset : offset+8])
	offset += 8
	supID := fmt.Sprintf("%02X%02X%02X%02X", payload[offset], payload[offset+1], payload[offset+2], payload[offset+3])
	offset += 4
	endTime := parseUTCSeconds(payload[offset : offset+8])
	offset += 8
	level := SupervisionLevel(payload[offset])
	offset++
	supervisor := padTrim(payload[offset : offset+16])
	offset += 16
	tel := padTrim(payload[offset : offset+20])
	offset += 20
	email := padTrim(payload[offset : offset+32])

	return &WarnSuperviseRequest{
		WarnSource:      src,
		WarnType:        typ,
		WarnTime:        warnTime,
		SupervisionID:   supID,
		EndTime:         endTime,
		Level:           level,
		Supervisor:      supervisor,
		SupervisorTel:   tel,
		SupervisorEmail: email,
	}, nil
}

func putUTCSeconds(buf *bytes.Buffer, t time.Time) {
	secs := uint64(t.UTC().Add(-8 * time.Hour).Unix())
	_ = binary.Write(buf, binary.BigEndian, secs)
}

func parseUTCSeconds(b []byte) time.Time {
	secs := int64(binary.BigEndian.Uint64(b))
	return time.Unix(secs, 0).Add(8 * time.Hour).UTC()
}

func decodeHexString(s string, expectedLen int) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("hex string must have even length")
	}
	raw := make([]byte, len(s)/2)
	for i := 0; i < len(raw); i++ {
		var v byte
		for j := 0; j < 2; j++ {
			c := s[2*i+j]
			var n byte
			switch {
			case c >= '0' && c <= '9':
				n = c - '0'
			case c >= 'A' && c <= 'F':
				n = c - 'A' + 10
			case c >= 'a' && c <= 'f':
				n = c - 'a' + 10
			default:
				return nil, fmt.Errorf("invalid hex char %q", c)
			}
			v = (v << 4) | n
		}
		raw[i] = v
	}
	if len(raw) != expectedLen {
		return nil, fmt.Errorf("hex length %d mismatch, expected %d bytes", len(raw), expectedLen)
	}
	return raw, nil
}

func padTrim(b []byte) string {
	s := string(b)
	last := len(s)
	for last > 0 && s[last-1] == 0 {
		last--
	}
	return s[:last]
}
