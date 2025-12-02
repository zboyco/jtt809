package jtt809

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// DynamicInfo2019 表示 2019 版主链路车辆动态交互业务内容（0x1200），保留原始子业务载荷。
type DynamicInfo2019 struct {
	Plate         string
	PlateRaw      []byte
	Color         byte
	SubBusinessID uint16
	PayloadLength uint32
	Payload       []byte
}

// ParseMainDynamic2019 解析主链路车辆动态类报文（如 0x1200），返回子业务结构。
func ParseMainDynamic2019(body []byte) (*DynamicInfo2019, error) {
	pkt, err := ParseSubBusiness(body)
	if err != nil {
		return nil, err
	}
	return &DynamicInfo2019{
		Plate:         pkt.Plate,
		PlateRaw:      pkt.PlateRaw,
		Color:         pkt.Color,
		SubBusinessID: pkt.SubBusinessID,
		PayloadLength: pkt.PayloadLength,
		Payload:       pkt.Payload,
	}, nil
}

// SubBusinessPacket 主/从链路通用子业务解析结果，含车牌、颜色、子业务标识与载荷。
type SubBusinessPacket struct {
	Plate         string
	PlateRaw      []byte
	Color         byte
	SubBusinessID uint16
	PayloadLength uint32
	Payload       []byte
}

// ParseSubBusiness 解析通用子业务结构（车牌、颜色、子业务标识、长度与载荷），可复用在主/从链路。
func ParseSubBusiness(body []byte) (*SubBusinessPacket, error) {
	if len(body) < 28 {
		return nil, errors.New("sub business body too short")
	}
	plateRaw := make([]byte, 21)
	copy(plateRaw, body[:21])
	color := body[21]
	sub := binary.BigEndian.Uint16(body[22:24])
	length := binary.BigEndian.Uint32(body[24:28])
	if int(length) != len(body[28:]) {
		return nil, fmt.Errorf("sub payload length mismatch: declare=%d actual=%d", length, len(body[28:]))
	}
	payload := make([]byte, len(body[28:]))
	copy(payload, body[28:])
	plate, _ := DecodeGBK(plateRaw)
	return &SubBusinessPacket{
		Plate:         plate,
		PlateRaw:      plateRaw,
		Color:         color,
		SubBusinessID: sub,
		PayloadLength: length,
		Payload:       payload,
	}, nil
}
