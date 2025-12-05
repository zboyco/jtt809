package jtt809

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
)

const (
	beginFlag byte = 0x5b
	endFlag   byte = 0x5d

	// MsgID* 定义 JT/T 809-2019 主链路与从链路常用业务 ID。
	MsgIDLoginRequest      uint16 = 0x1001
	MsgIDLoginResponse     uint16 = 0x1002
	MsgIDHeartbeatRequest  uint16 = 0x1005
	MsgIDHeartbeatResponse uint16 = 0x1006
	MsgIDDynamicInfo       uint16 = 0x1200
	MsgIDAlarmInteract     uint16 = 0x1400
	MsgIDPlatformInfo      uint16 = 0x1300
	MsgIDDisconnNotify     uint16 = 0x1007
	MsgIDCloseNotify       uint16 = 0x9008
	MsgIDDownlinkConnReq   uint16 = 0x9001
	MsgIDLogoutRequest     uint16 = 0x1003
	MsgIDLogoutResponse    uint16 = 0x1004

	// 从链路下行业务
	MsgIDDownExgMsg uint16 = 0x9200 // 从链路车辆动态信息交换业务

	// JT/T 1078-2016 视频业务
	MsgIDAuthorize         uint16 = 0x1700 // 视频相关鉴权
	MsgIDRealTimeVideo     uint16 = 0x1800 // 实时音视频
	MsgIDDownAuthorize     uint16 = 0x9700 // 下行视频鉴权
	MsgIDDownRealTimeVideo uint16 = 0x9800 // 下行实时音视频
)

// Version 表示 3 字节协议版本号，对应主版本/次版本/修订号。
type Version struct {
	Major byte
	Minor byte
	Patch byte
}

func (v Version) bytes() [3]byte {
	return [3]byte{v.Major, v.Minor, v.Patch}
}

// Header 对应 JT/T 809-2019 消息头字段，包含消息长度、流水号、业务 ID、平台标识、版本、加密及时间戳。
type Header struct {
	MsgLength    uint32
	MsgSN        uint32
	BusinessType uint16
	GNSSCenterID uint32
	Version      Version
	EncryptFlag  byte
	EncryptKey   uint32
	Timestamp    time.Time
}

// WithResponse 以当前头为模板生成应答头，设置目标业务 ID，若流水号未写入则自动生成。
func (h Header) WithResponse(msgID uint16) Header {
	h.BusinessType = msgID
	if h.MsgSN == 0 {
		h.MsgSN = atomic.AddUint32(&seq, 1)
	}
	return h
}

// Body 定义各业务体需实现的接口：返回业务 ID 与序列化后的业务体。
type Body interface {
	MsgID() uint16
	Encode() ([]byte, error)
}

// Package 表示一帧高层封装的 809 报文，由消息头与业务体组成。
type Package struct {
	Header Header
	Body   Body
}

var (
	defaultVersion = Version{Major: 1, Minor: 2, Patch: 15} // 默认协议版本号
	seq            uint32
)

// EncodePackage 根据消息头与业务体生成完整报文，自动补齐缺省字段、加 CRC 校验并进行转义。
func EncodePackage(pkg Package) ([]byte, error) {
	if pkg.Body == nil {
		return nil, errors.New("missing body")
	}
	body, err := pkg.Body.Encode()
	if err != nil {
		return nil, err
	}
	header := pkg.Header
	if header.BusinessType == 0 {
		header.BusinessType = pkg.Body.MsgID()
	}
	if header.Version == (Version{}) {
		header.Version = defaultVersion
	}

	if header.Timestamp.IsZero() {
		header.Timestamp = time.Now()
	}
	if header.MsgSN == 0 {
		header.MsgSN = atomic.AddUint32(&seq, 1)
	}

	var buf bytes.Buffer
	buf.WriteByte(beginFlag)

	// 占位写入长度
	lengthPos := buf.Len()
	_ = binary.Write(&buf, binary.BigEndian, uint32(0))

	_ = binary.Write(&buf, binary.BigEndian, header.MsgSN)
	_ = binary.Write(&buf, binary.BigEndian, header.BusinessType)
	_ = binary.Write(&buf, binary.BigEndian, header.GNSSCenterID)
	versionBytes := header.Version.bytes()
	buf.Write(versionBytes[:])
	buf.WriteByte(header.EncryptFlag)
	_ = binary.Write(&buf, binary.BigEndian, header.EncryptKey)

	// 按协议字段直接存储 UTC 秒
	secs := uint64(header.Timestamp.Unix())
	_ = binary.Write(&buf, binary.BigEndian, secs)

	buf.Write(body)

	msgLen := uint32(buf.Len() + 3) // CRC(2)+尾标识(1)
	binary.BigEndian.PutUint32(buf.Bytes()[lengthPos:], msgLen)

	crc := crc16CCITT(buf.Bytes()[1:])
	var crcBytes [2]byte
	binary.BigEndian.PutUint16(crcBytes[:], crc)
	buf.Write(crcBytes[:])
	buf.WriteByte(endFlag)

	return encodeEscape(buf.Bytes()), nil
}

// Frame 保存解码后的报文：包含消息头、业务 ID（即业务类型）与原始业务体字节。
type Frame struct {
	Header  Header
	BodyID  uint16
	RawBody []byte
}

// DecodeFrame 对收到的转义报文进行反转义与 CRC 校验，解析出消息头与原始业务体。
func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < 1+22+2+1 {
		return nil, errors.New("frame too short")
	}
	unescaped, err := decodeEscape(data)
	if err != nil {
		return nil, err
	}
	if unescaped[0] != beginFlag || unescaped[len(unescaped)-1] != endFlag {
		return nil, errors.New("invalid boundary flag")
	}
	length := binary.BigEndian.Uint32(unescaped[1:5])
	if int(length) != len(unescaped) {
		return nil, fmt.Errorf("length mismatch: header=%d actual=%d", length, len(unescaped))
	}
	bodyEnd := len(unescaped) - 3
	crcCalc := crc16CCITT(unescaped[1:bodyEnd])
	crcReal := binary.BigEndian.Uint16(unescaped[bodyEnd : bodyEnd+2])
	if crcCalc != crcReal {
		return nil, fmt.Errorf("crc mismatch: calc=%04X real=%04X", crcCalc, crcReal)
	}

	header := Header{
		MsgLength:    length,
		MsgSN:        binary.BigEndian.Uint32(unescaped[5:9]),
		BusinessType: binary.BigEndian.Uint16(unescaped[9:11]),
		GNSSCenterID: binary.BigEndian.Uint32(unescaped[11:15]),
		Version:      Version{Major: unescaped[15], Minor: unescaped[16], Patch: unescaped[17]},
		EncryptFlag:  unescaped[18],
		EncryptKey:   binary.BigEndian.Uint32(unescaped[19:23]),
	}

	headerLen := 30
	secs := int64(binary.BigEndian.Uint64(unescaped[23:31]))
	header.Timestamp = time.Unix(secs, 0)

	bodyStart := 1 + headerLen
	if bodyStart > bodyEnd {
		return nil, errors.New("body start beyond end")
	}
	return &Frame{
		Header:  header,
		BodyID:  header.BusinessType,
		RawBody: append([]byte(nil), unescaped[bodyStart:bodyEnd]...),
	}, nil
}

func crc16CCITT(data []byte) uint16 {
	var crc uint16 = 0xFFFF
	for _, b := range data {
		crc = uint16((crc << 8) ^ crcTable[(crc>>8)^uint16(b)])
	}
	return crc
}

var crcTable = func() [256]uint16 {
	const poly = 0x1021
	var table [256]uint16
	for i := 0; i < 256; i++ {
		var crc uint16 = uint16(i << 8)
		for j := 0; j < 8; j++ {
			if (crc & 0x8000) != 0 {
				crc = (crc << 1) ^ poly
			} else {
				crc <<= 1
			}
		}
		table[i] = crc
	}
	return table
}()

func encodeEscape(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	out := make([]byte, 0, len(src)+8)
	out = append(out, src[0])
	for i := 1; i < len(src)-1; i++ {
		switch src[i] {
		case 0x5b:
			out = append(out, 0x5a, 0x01)
		case 0x5a:
			out = append(out, 0x5a, 0x02)
		case 0x5d:
			out = append(out, 0x5e, 0x01)
		case 0x5e:
			out = append(out, 0x5e, 0x02)
		default:
			out = append(out, src[i])
		}
	}
	if len(src) > 1 {
		out = append(out, src[len(src)-1])
	}
	return out
}

func decodeEscape(src []byte) ([]byte, error) {
	if len(src) == 0 {
		return nil, nil
	}
	out := make([]byte, 0, len(src))
	for i := 0; i < len(src); i++ {
		b := src[i]
		if b == 0x5a || b == 0x5e {
			if i+1 >= len(src) {
				return nil, errors.New("dangling escape byte")
			}
			n := src[i+1]
			i++
			switch b {
			case 0x5a:
				switch n {
				case 0x01:
					out = append(out, 0x5b)
				case 0x02:
					out = append(out, 0x5a)
				default:
					return nil, fmt.Errorf("invalid escape 0x5a 0x%02x", n)
				}
			case 0x5e:
				switch n {
				case 0x01:
					out = append(out, 0x5d)
				case 0x02:
					out = append(out, 0x5e)
				default:
					return nil, fmt.Errorf("invalid escape 0x5e 0x%02x", n)
				}
			}
			continue
		}
		out = append(out, b)
	}
	return out, nil
}
