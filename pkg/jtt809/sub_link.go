package jtt809

import (
	"encoding/binary"
	"errors"
)

// From-link (从链路) 基础消息。

// SubLinkLoginRequest 从链路登录请求（0x9001），由下级向上级从链路发起鉴权。
type SubLinkLoginRequest struct {
	VerifyCode uint32 // 主链路登录成功后返回的校验码
}

func (SubLinkLoginRequest) MsgID() uint16 { return MsgIDDownlinkConnReq }

func (s SubLinkLoginRequest) Encode() ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], s.VerifyCode)
	return buf[:], nil
}

// SubLinkLoginResponse 从链路登录应答（0x9002），上级返回登录结果。
type SubLinkLoginResponse struct {
	Result byte
}

func (SubLinkLoginResponse) MsgID() uint16 { return 0x9002 }
func (s SubLinkLoginResponse) Encode() ([]byte, error) {
	return []byte{s.Result}, nil
}

// SubLinkHeartbeatRequest 从链路心跳请求（0x9005），业务体为空。
type SubLinkHeartbeatRequest struct{}

func (SubLinkHeartbeatRequest) MsgID() uint16           { return 0x9005 }
func (SubLinkHeartbeatRequest) Encode() ([]byte, error) { return []byte{}, nil }

// SubLinkHeartbeatResponse 从链路心跳应答（0x9006），业务体为空。
type SubLinkHeartbeatResponse struct{}

func (SubLinkHeartbeatResponse) MsgID() uint16           { return 0x9006 }
func (SubLinkHeartbeatResponse) Encode() ([]byte, error) { return []byte{}, nil }

// ParseSubLinkLoginResponse 解析从链路登录应答（0x9002），返回登录结果码。
func ParseSubLinkLoginResponse(frame *Frame) (*SubLinkLoginResponse, error) {
	if frame == nil {
		return nil, errors.New("frame is nil")
	}
	if frame.BodyID != 0x9002 {
		return nil, errors.New("unexpected body id")
	}
	if len(frame.RawBody) < 1 {
		return nil, errors.New("body too short")
	}
	return &SubLinkLoginResponse{Result: frame.RawBody[0]}, nil
}

// ParseSubLinkHeartbeatResponse 解析从链路心跳应答（0x9006），校验空载荷。
func ParseSubLinkHeartbeatResponse(frame *Frame) (*SubLinkHeartbeatResponse, error) {
	if frame == nil {
		return nil, errors.New("frame is nil")
	}
	if frame.BodyID != 0x9006 {
		return nil, errors.New("unexpected body id")
	}
	if len(frame.RawBody) != 0 {
		return nil, errors.New("heartbeat response body must be empty")
	}
	return &SubLinkHeartbeatResponse{}, nil
}

// SubLinkDisconnectNotify 从链路断开通知（0x9007），上级推送给下级，无需应答。
type SubLinkDisconnectNotify struct {
	ReasonCode byte
}

func (SubLinkDisconnectNotify) MsgID() uint16             { return 0x9007 }
func (n SubLinkDisconnectNotify) Encode() ([]byte, error) { return []byte{n.ReasonCode}, nil }

// BuildSubLinkLoginPackage 构造从链路登录请求完整报文（含转义）。
func BuildSubLinkLoginPackage(header Header, req SubLinkLoginRequest) ([]byte, error) {
	header.BusinessType = MsgIDDownlinkConnReq
	return EncodePackage(Package{Header: header, Body: req})
}

// BuildSubLinkHeartbeat 构造从链路心跳请求完整报文（含转义）。
func BuildSubLinkHeartbeat(header Header) ([]byte, error) {
	header.BusinessType = 0x9005
	return EncodePackage(Package{Header: header, Body: SubLinkHeartbeatRequest{}})
}

// ParseSubLinkDisconnectNotify 解析从链路断开通知，返回断开原因。
func ParseSubLinkDisconnectNotify(frame *Frame) (*SubLinkDisconnectNotify, error) {
	if frame == nil {
		return nil, errors.New("frame is nil")
	}
	if frame.BodyID != 0x9007 {
		return nil, errors.New("unexpected body id")
	}
	if len(frame.RawBody) < 1 {
		return nil, errors.New("body too short")
	}
	return &SubLinkDisconnectNotify{ReasonCode: frame.RawBody[0]}, nil
}
