package jtt809

import "testing"

// 从链路登录请求发送：使用构造器生成并校验业务 ID 与负载。
func TestSubLinkSendLoginRequest(t *testing.T) {
	header := Header{GNSSCenterID: 0x01020304}
	req := SubLinkLoginRequest{VerifyCode: 0x13572468}
	data, err := BuildSubLinkLoginPackage(header, req)
	if err != nil {
		t.Fatalf("build sub link login: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	if frame.BodyID != MsgIDDownlinkConnReq {
		t.Fatalf("unexpected body id: %x", frame.BodyID)
	}
	if len(frame.RawBody) != 4 {
		t.Fatalf("unexpected body length: %d", len(frame.RawBody))
	}
}

// 处理从链路登录应答。
func TestSubLinkHandleLoginResponse(t *testing.T) {
	data, err := EncodePackage(Package{Header: Header{}, Body: SubLinkLoginResponse{Result: 0x01}})
	if err != nil {
		t.Fatalf("encode sub link login resp: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	resp, err := ParseSubLinkLoginResponse(frame)
	if err != nil {
		t.Fatalf("parse sub link login resp: %v", err)
	}
	if resp.Result != 0x01 {
		t.Fatalf("unexpected result: %d", resp.Result)
	}
}

// 发送从链路心跳。
func TestSubLinkSendHeartbeat(t *testing.T) {
	header := Header{GNSSCenterID: 0x99}
	data, err := BuildSubLinkHeartbeat(header)
	if err != nil {
		t.Fatalf("build sub link heartbeat: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	if frame.BodyID != 0x9005 {
		t.Fatalf("unexpected heartbeat id: %x", frame.BodyID)
	}
	if len(frame.RawBody) != 0 {
		t.Fatalf("heartbeat body should be empty")
	}
}

// 处理从链路心跳应答。
func TestSubLinkHandleHeartbeatResponse(t *testing.T) {
	data, err := EncodePackage(Package{Header: Header{}, Body: SubLinkHeartbeatResponse{}})
	if err != nil {
		t.Fatalf("encode heartbeat resp: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	if _, err := ParseSubLinkHeartbeatResponse(frame); err != nil {
		t.Fatalf("parse heartbeat response: %v", err)
	}
}

// 处理从链路断开通知。
func TestSubLinkHandleDisconnectNotify(t *testing.T) {
	data, err := EncodePackage(Package{Header: Header{}, Body: SubLinkDisconnectNotify{ReasonCode: 2}})
	if err != nil {
		t.Fatalf("encode disconnect notify: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	notify, err := ParseSubLinkDisconnectNotify(frame)
	if err != nil {
		t.Fatalf("parse disconnect notify: %v", err)
	}
	if notify.ReasonCode != 2 {
		t.Fatalf("unexpected reason code: %d", notify.ReasonCode)
	}
}
