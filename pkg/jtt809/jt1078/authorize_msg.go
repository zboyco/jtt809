package jt1078

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/zboyco/jtt809/pkg/jtt809"
)

// 协议分层说明：
//
// JT/T 1078-2016 是视频通信协议，定义了视频相关的数据格式（如时效口令、视频请求等）。
// JT/T 809 是平台间通信协议，定义了平台间传输的封装格式。
//
// 0x1700 (视频鉴权) 消息体结构：
//   子业务类型标识(2字节) + JT/T 1078 数据
//
// 注意：0x1700 与 0x1200 使用不同的封装格式：
//   - 0x1200: 车牌号(21) + 颜色(1) + 子业务ID(2) + 长度(4) + 载荷 (SubBusinessPacket)
//   - 0x1700: 子业务ID(2) + 载荷 (更简单的格式，不包含车牌号和颜色)
//
// 例如，时效口令上报消息（0x1701）的完整结构：
//   1. 主业务类型: 0x1700 (MsgIDAuthorize)
//   2. 子业务类型: 0x1701 (SubMsgAuthorizeStartupReq) - 2字节
//   3. 平台唯一编码: 11字节
//   4. 归属地区政府平台使用的时效口令: 64字节
//   5. 跨域地区政府平台使用的时效口令: 64字节
//   总计: 2 + 11 + 64 + 64 = 141字节

// AuthorizeMsg 对应 UP_AUTHORIZE_MSG (0x1700)
// 视频相关鉴权消息
type AuthorizeMsg struct {
	SubBusinessID uint16 // 2 bytes - 子业务类型标识
	Payload       []byte // 变长 - JT/T 1078 数据
}

func (m AuthorizeMsg) MsgID() uint16 { return jtt809.MsgIDAuthorize }

func (m AuthorizeMsg) Encode() ([]byte, error) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, m.SubBusinessID)
	buf.Write(m.Payload)
	return buf.Bytes(), nil
}

// ParseAuthorizeMsg 解析 0x1700 消息体。
func ParseAuthorizeMsg(body []byte) (AuthorizeMsg, error) {
	if len(body) < 2 {
		return AuthorizeMsg{}, fmt.Errorf("authorize msg body too short: %d", len(body))
	}
	return AuthorizeMsg{
		SubBusinessID: binary.BigEndian.Uint16(body[0:2]),
		Payload:       body[2:],
	}, nil
}

// DownAuthorizeMsg 对应 DOWN_AUTHORIZE_MSG (0x9700)
// 下行视频鉴权消息
// 结构与 AuthorizeMsg 相同：子业务ID(2字节) + 载荷
type DownAuthorizeMsg struct {
	SubBusinessID uint16 // 2 bytes - 子业务类型标识
	Payload       []byte // 变长 - JT/T 1078 数据
}

func (m DownAuthorizeMsg) MsgID() uint16 { return jtt809.MsgIDDownAuthorize }

func (m DownAuthorizeMsg) Encode() ([]byte, error) {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, m.SubBusinessID)
	buf.Write(m.Payload)
	return buf.Bytes(), nil
}

// AuthorizeStartupReqMsg 对应 UP_AUTHORIZE_MSG_STARTUP_REQ (0x1702)
// 时效口令请求消息
// 消息体为空
type AuthorizeStartupReqMsg struct{}

func (AuthorizeStartupReqMsg) MsgID() uint16 { return 0x1702 } // SubMsgID

func (r AuthorizeStartupReqMsg) Encode() ([]byte, error) {
	return []byte{}, nil
}

func ParseAuthorizeStartupReqMsg(body []byte) (AuthorizeStartupReqMsg, error) {
	return AuthorizeStartupReqMsg{}, nil
}

// AuthorizeStartupReqAckMsg 对应 DOWN_AUTHORIZE_MSG_STARTUP_REQ_ACK (0x9702)
// 时效口令请求应答消息
// 消息体为空
type AuthorizeStartupReqAckMsg struct{}

func (AuthorizeStartupReqAckMsg) MsgID() uint16 { return 0x9702 } // SubMsgID

func (r AuthorizeStartupReqAckMsg) Encode() ([]byte, error) {
	return []byte{}, nil
}
