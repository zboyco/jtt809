package jtt809

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

// VehiclePosition 表示 2019 版车辆定位扩展，携带 GNSS 原始数据与多平台报警信息。
type VehiclePosition struct {
	Encrypt     byte
	GnssData    []byte
	PlatformID1 string // 11字节，不足补0
	Alarm1      uint32
	PlatformID2 string // 11字节
	Alarm2      uint32
	PlatformID3 string // 11字节
	Alarm3      uint32
}

func (v VehiclePosition) encode() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(v.Encrypt)
	pos := buf.Len()
	_ = binary.Write(&buf, binary.BigEndian, uint32(0)) // 占位长度
	buf.Write(v.GnssData)
	// 回写长度
	l := uint32(len(v.GnssData))
	binary.BigEndian.PutUint32(buf.Bytes()[pos:], l)
	buf.Write(PadRightGBK(v.PlatformID1, 11))
	_ = binary.Write(&buf, binary.BigEndian, v.Alarm1)
	buf.Write(PadRightGBK(v.PlatformID2, 11))
	_ = binary.Write(&buf, binary.BigEndian, v.Alarm2)
	buf.Write(PadRightGBK(v.PlatformID3, 11))
	_ = binary.Write(&buf, binary.BigEndian, v.Alarm3)
	return buf.Bytes(), nil
}

// VehicleLocationUpload 表示主链路车辆动态信息交换（0x1200）业务体，仅承载 2019 版定位数据。
type VehicleLocationUpload struct {
	VehicleNo    string
	VehicleColor byte
	Position2019 *VehiclePosition
}

func (VehicleLocationUpload) MsgID() uint16 { return MsgIDDynamicInfo }

func (v VehicleLocationUpload) Encode() ([]byte, error) {
	if len(v.VehicleNo) == 0 {
		return nil, errors.New("vehicle number is required")
	}
	if v.Position2019 == nil {
		return nil, errors.New("vehicle position 2019 is required")
	}
	positionBody, err := v.Position2019.encode()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(PadRightGBK(v.VehicleNo, 21))
	buf.WriteByte(v.VehicleColor)

	const subMsgID uint16 = 0x1202
	_ = binary.Write(&buf, binary.BigEndian, subMsgID)

	_ = binary.Write(&buf, binary.BigEndian, uint32(len(positionBody)))
	buf.Write(positionBody)
	return buf.Bytes(), nil
}

// ParseVehiclePosition2019 解析 2019 版定位载荷，保留原始 GNSS 数据，不做二次解码。
func ParseVehiclePosition2019(body []byte) (VehiclePosition, error) {
	if len(body) < 1+4+11+4+11+4+11+4 {
		return VehiclePosition{}, errors.New("position 2019 body too short")
	}
	pos := VehiclePosition{
		Encrypt: body[0],
	}
	dataLen := int(binary.BigEndian.Uint32(body[1:5]))
	if len(body) < 5+dataLen+11+4+11+4+11+4 {
		return VehiclePosition{}, errors.New("position 2019 body length mismatch")
	}
	pos.GnssData = append([]byte(nil), body[5:5+dataLen]...)
	offset := 5 + dataLen
	pos.PlatformID1 = strings.TrimRight(string(body[offset:offset+11]), "\x00")
	offset += 11
	pos.Alarm1 = binary.BigEndian.Uint32(body[offset : offset+4])
	offset += 4
	pos.PlatformID2 = strings.TrimRight(string(body[offset:offset+11]), "\x00")
	offset += 11
	pos.Alarm2 = binary.BigEndian.Uint32(body[offset : offset+4])
	offset += 4
	pos.PlatformID3 = strings.TrimRight(string(body[offset:offset+11]), "\x00")
	offset += 11
	pos.Alarm3 = binary.BigEndian.Uint32(body[offset : offset+4])
	return pos, nil
}
