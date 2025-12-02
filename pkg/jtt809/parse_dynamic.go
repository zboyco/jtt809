package jtt809

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// LocationDynamic 封装从子业务 0x1202 解析出的核心字段（2011 版定位格式）。
type LocationDynamic struct {
	Plate     string
	Color     byte
	Encrypt   byte
	Time      [6]byte // YYMMDDhhmmss BCD 格式（2011版）
	Lon       uint32
	Lat       uint32
	Speed     uint16
	RecordSpd uint16
	Mileage   uint32
	Direction uint16
	Altitude  uint16
	State     uint32
	Alarm     uint32
}

// ParseLocation2011 解析 0x1202 载荷为 2011 版定位数据。
func ParseLocation2011(pkt *SubBusinessPacket) (*LocationDynamic, error) {
	if pkt == nil {
		return nil, errors.New("nil packet")
	}
	if pkt.SubBusinessID != SubMsgRealLocation2011 {
		return nil, fmt.Errorf("unsupported sub business id: %x", pkt.SubBusinessID)
	}
	if len(pkt.Payload) < 36 {
		return nil, errors.New("payload too short for 2011 location")
	}
	p := pkt.Payload
	return &LocationDynamic{
		Plate:     pkt.Plate,
		Color:     pkt.Color,
		Encrypt:   p[0],
		Time:      [6]byte{p[1], p[2], p[3], p[4], p[5], p[6]},
		Lon:       binary.BigEndian.Uint32(p[8:12]),
		Lat:       binary.BigEndian.Uint32(p[12:16]),
		Speed:     binary.BigEndian.Uint16(p[16:18]),
		RecordSpd: binary.BigEndian.Uint16(p[18:20]),
		Mileage:   binary.BigEndian.Uint32(p[20:24]),
		Direction: binary.BigEndian.Uint16(p[24:26]),
		Altitude:  binary.BigEndian.Uint16(p[26:28]),
		State:     binary.BigEndian.Uint32(p[28:32]),
		Alarm:     binary.BigEndian.Uint32(p[32:36]),
	}, nil
}

// BatchLocationDynamic 表示批量补报（0x1203）的定位集合，携带车牌与多条定位。
type BatchLocationDynamic struct {
	Plate     string
	Color     byte
	Locations []LocationDynamic
}

// ParseBatchLocation 解析子业务 0x1203（批量定位补报），拆解为若干 LocationDynamic。
func ParseBatchLocation(pkt *SubBusinessPacket) (*BatchLocationDynamic, error) {
	if pkt == nil {
		return nil, errors.New("nil packet")
	}
	if pkt.SubBusinessID != SubMsgBatchLocation {
		return nil, fmt.Errorf("unsupported sub business id: %x", pkt.SubBusinessID)
	}
	if len(pkt.Payload) < 1 {
		return nil, errors.New("payload too short for batch location")
	}
	count := int(pkt.Payload[0])
	locs := make([]LocationDynamic, 0, count)
	reader := pkt.Payload[1:]
	for i := 0; i < count; i++ {
		if len(reader) < 36 {
			return nil, fmt.Errorf("insufficient payload for record %d", i)
		}
		subPkt := *pkt
		subPkt.SubBusinessID = SubMsgRealLocation2011
		subPkt.Payload = reader[:36]
		loc, err := ParseLocation2011(&subPkt)
		if err != nil {
			return nil, err
		}
		locs = append(locs, *loc)
		reader = reader[36:]
	}
	return &BatchLocationDynamic{
		Plate:     pkt.Plate,
		Color:     pkt.Color,
		Locations: locs,
	}, nil
}

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
