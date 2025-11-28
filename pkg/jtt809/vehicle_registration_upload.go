package jtt809

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// VehicleRegistrationUpload 表示主链路上传车辆注册信息（0x1200 子业务 0x1201，2019 版）。
type VehicleRegistrationUpload struct {
	VehicleNo    string
	VehicleColor byte

	PlatformID        string // 11 字节
	ProducerID        string // 11 字节
	TerminalModelType string // 30 字节（2019版）
	IMEI              string // 15 字节（2019版）
	TerminalID        string // 30 字节（2019版），需转为大写
	TerminalSIM       string // 13 字节（2019版）
}

func (VehicleRegistrationUpload) MsgID() uint16 { return MsgIDDynamicInfo }

// Encode 构造 0x1201 子业务载荷（仅 2019 版），并封装到 0x1200 主链路报文中。
func (v VehicleRegistrationUpload) Encode() ([]byte, error) {
	if len(v.VehicleNo) == 0 {
		return nil, errors.New("vehicle number is required")
	}
	body, err := v.encodeRegistrationBody()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.Write(PadRightGBK(v.VehicleNo, 21)) // 使用 GBK 编码
	buf.WriteByte(v.VehicleColor)

	const subMsgID uint16 = SubMsgUploadVehicleReg
	_ = binary.Write(&buf, binary.BigEndian, subMsgID)
	_ = binary.Write(&buf, binary.BigEndian, uint32(len(body)))
	buf.Write(body)
	return buf.Bytes(), nil
}

func (v VehicleRegistrationUpload) encodeRegistrationBody() ([]byte, error) {
	if len(v.PlatformID) == 0 || len(v.ProducerID) == 0 || len(v.TerminalID) == 0 {
		return nil, fmt.Errorf("platform/producer/terminal id is required")
	}
	var buf bytes.Buffer
	buf.Write(PadRightGBK(v.PlatformID, 11))
	buf.Write(PadRightGBK(v.ProducerID, 11))
	buf.Write(PadRightGBK(v.TerminalModelType, 30))
	buf.Write(PadRightGBK(v.IMEI, 15)) // 2019版本：15字节
	buf.Write(PadRightGBK(strings.ToUpper(v.TerminalID), 30))
	buf.Write(PadRightGBK(v.TerminalSIM, 13))
	return buf.Bytes(), nil
}
