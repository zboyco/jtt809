package jtt809

import (
	"errors"
	"fmt"
)

// GenerateResponse 仅用于测试场景，根据收到的帧自动生成应答包（不含转义编码），支持主链路登录/心跳/注销及从链路登录/心跳。
// 对登录请求需传入 auth 鉴权回调；其余业务可置为 nil。
func GenerateResponse(frame *Frame, auth AuthValidator) (*Package, error) {
	if frame == nil {
		return nil, errors.New("frame is nil")
	}
	switch frame.BodyID {
	case MsgIDLoginRequest:
		if auth == nil {
			return nil, errors.New("auth validator required for login response")
		}
		req, err := ParseLoginRequest(frame.RawBody)
		if err != nil {
			return nil, fmt.Errorf("parse login request: %w", err)
		}
		resp, err := auth(req)
		if err != nil {
			return nil, err
		}
		header := frame.Header.WithResponse(MsgIDLoginResponse)
		return &Package{Header: header, Body: resp}, nil
	case MsgIDHeartbeatRequest:
		header := frame.Header.WithResponse(MsgIDHeartbeatResponse)
		return &Package{Header: header, Body: HeartbeatResponse{}}, nil
	case MsgIDLogoutRequest:
		// 注销应答（空体）
		header := frame.Header.WithResponse(MsgIDLogoutResponse)
		return &Package{Header: header, Body: LogoutResponse{}}, nil
	case MsgIDDownlinkConnReq:
		header := frame.Header.WithResponse(0x9002)
		return &Package{Header: header, Body: SubLinkLoginResponse{Result: 0}}, nil
	case 0x9005:
		header := frame.Header.WithResponse(0x9006)
		return &Package{Header: header, Body: SubLinkHeartbeatResponse{}}, nil
	default:
		return nil, errors.New("unsupported message for automatic response")
	}
}
