package jtt809

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ApplyForMonitorStartup 启动车辆定位信息交换请求 (0x9200/0x9205)
type ApplyForMonitorStartup struct {
	VehicleNo    string
	VehicleColor PlateColor
	ReasonCode   MonitorReasonCode
}

func (ApplyForMonitorStartup) MsgID() uint16 { return MsgIDDownExgMsg }

func (a ApplyForMonitorStartup) Encode() ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(PadRightGBK(a.VehicleNo, 21))
	buf.WriteByte(byte(a.VehicleColor))
	_ = binary.Write(&buf, binary.BigEndian, SubMsgApplyForMonitorStartup)
	_ = binary.Write(&buf, binary.BigEndian, uint32(1)) // 数据长度=1
	buf.WriteByte(byte(a.ReasonCode))
	return buf.Bytes(), nil
}

// ApplyForMonitorEnd 结束车辆定位信息交换请求 (0x9200/0x9206)
type ApplyForMonitorEnd struct {
	VehicleNo    string
	VehicleColor PlateColor
	ReasonCode   MonitorReasonCode
}

func (ApplyForMonitorEnd) MsgID() uint16 { return MsgIDDownExgMsg }

func (a ApplyForMonitorEnd) Encode() ([]byte, error) {
	var buf bytes.Buffer
	buf.Write(PadRightGBK(a.VehicleNo, 21))
	buf.WriteByte(byte(a.VehicleColor))
	_ = binary.Write(&buf, binary.BigEndian, SubMsgApplyForMonitorEnd)
	_ = binary.Write(&buf, binary.BigEndian, uint32(1)) // 数据长度=1
	buf.WriteByte(byte(a.ReasonCode))
	return buf.Bytes(), nil
}

// MonitorAck 车辆定位信息交换应答 (0x1205/0x1206)
type MonitorAck struct {
	SourceDataType uint16 // 对应启动车辆定位信息交换请求消息源子业务类型标识
	SourceMsgSN    uint32 // 对应启动车辆定位信息交换请求消息源报文序列号
	DataLength     uint32 // 后续数据长度，值为0x00
}

// ParseMonitorAck 解析车辆定位信息交换应答 (0x1205/0x1206)
// 注意：部分下级平台实现不完整，可能只发送 6 字节（缺少 DataLength 字段）
func ParseMonitorAck(payload []byte) (*MonitorAck, error) {
	if len(payload) < 6 {
		return nil, errors.New("payload too short, expected at least 6 bytes")
	}
	ack := &MonitorAck{
		SourceDataType: binary.BigEndian.Uint16(payload[0:2]),
		SourceMsgSN:    binary.BigEndian.Uint32(payload[2:6]),
	}
	// DataLength 字段是可选的，部分下级平台实现可能不发送
	if len(payload) >= 10 {
		ack.DataLength = binary.BigEndian.Uint32(payload[6:10])
	}
	return ack, nil
}
