package jtt809

import (
	"encoding/binary"
	"errors"
	"testing"
)

// 覆盖主链路登录请求处理：解析登录请求并通过鉴权回调生成应答。
func TestMainLinkHandleLoginRequest(t *testing.T) {
	req := LoginRequest{
		UserID:          10001,
		Password:        "123456",
		DownLinkIP:      "127.0.0.1",
		DownLinkPort:    8080,
		ProtocolVersion: [3]byte{1, 0, 0},
	}
	packet, err := EncodePackage(Package{Header: Header{}, Body: req})
	if err != nil {
		t.Fatalf("encode login request: %v", err)
	}
	frame, err := DecodeFrame(packet)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	auth := SimpleAuthValidator(req.UserID, req.Password, 0x13572468)
	respPkg, err := GenerateResponse(frame, auth)
	if err != nil {
		t.Fatalf("generate login response: %v", err)
	}
	if respPkg.Header.BusinessType != MsgIDLoginResponse {
		t.Fatalf("unexpected response msg id: %x", respPkg.Header.BusinessType)
	}
	resp, ok := respPkg.Body.(LoginResponse)
	if !ok {
		t.Fatalf("unexpected response body type: %T", respPkg.Body)
	}
	if resp.Result != LoginOK || resp.VerifyCode != 0x13572468 {
		t.Fatalf("unexpected login response: %+v", resp)
	}
}

// 主动发送登录应答：根据请求头生成对应业务 ID 的应答包。
func TestMainLinkSendLoginResponse(t *testing.T) {
	reqHeader := Header{BusinessType: MsgIDLoginRequest, MsgSN: 10, GNSSCenterID: 1}
	resp := LoginResponse{Result: LoginOK, VerifyCode: 0xabcdef}
	data, err := BuildLoginResponsePackage(reqHeader, resp)
	if err != nil {
		t.Fatalf("build login response package: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode login response frame: %v", err)
	}
	if frame.BodyID != MsgIDLoginResponse {
		t.Fatalf("unexpected body id: %x", frame.BodyID)
	}
	parsed, err := ParseLoginResponse(frame.RawBody)
	if err != nil {
		t.Fatalf("parse login response body: %v", err)
	}
	if parsed.VerifyCode != resp.VerifyCode || parsed.Result != resp.Result {
		t.Fatalf("login response payload mismatch: %+v", parsed)
	}
}

// 处理车辆实时定位信息：编码 2019 版实时定位并解析子业务及定位载荷。
func TestMainLinkHandleRealTimeLocation2019(t *testing.T) {
	gnss := []byte{0x01, 0x02, 0x03}
	pos := &VehiclePosition{
		Encrypt:     1,
		GnssData:    gnss,
		PlatformID1: "11111111111",
		PlatformID2: "22222222222",
		PlatformID3: "33333333333",
		Alarm1:      1,
		Alarm2:      2,
		Alarm3:      3,
	}
	body := VehicleLocationUpload{
		VehicleNo:    "粤A12345",
		VehicleColor: VehicleColorBlue,
		Position2019: pos,
	}
	pkt, err := EncodePackage(Package{Header: Header{GNSSCenterID: 99, WithUTC: true}, Body: body})
	if err != nil {
		t.Fatalf("encode location upload: %v", err)
	}
	frame, err := DecodeFrame(pkt)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	sub, err := ParseSubBusiness(frame.RawBody)
	if err != nil {
		t.Fatalf("parse sub business: %v", err)
	}
	if sub.SubBusinessID != SubMsgRealLocation { // 2019 版仍复用 0x1202 标识
		t.Fatalf("unexpected sub business id: %x", sub.SubBusinessID)
	}
	loc, err := ParseVehiclePosition2019(sub.Payload)
	if err != nil {
		t.Fatalf("parse vehicle position 2019: %v", err)
	}
	if len(loc.GnssData) != len(gnss) || loc.PlatformID3 != pos.PlatformID3 || loc.Alarm2 != pos.Alarm2 {
		t.Fatalf("position payload mismatch: %+v", loc)
	}
}

// 主链路心跳处理与应答：生成心跳应答包。
func TestMainLinkHeartbeatAutoResponse(t *testing.T) {
	hbData, err := EncodePackage(Package{Header: Header{GNSSCenterID: 7}, Body: HeartbeatRequest{}})
	if err != nil {
		t.Fatalf("encode heartbeat: %v", err)
	}
	frame, err := DecodeFrame(hbData)
	if err != nil {
		t.Fatalf("decode heartbeat frame: %v", err)
	}
	respPkg, err := GenerateResponse(frame, nil)
	if err != nil {
		t.Fatalf("generate heartbeat response: %v", err)
	}
	if respPkg.Header.BusinessType != MsgIDHeartbeatResponse {
		t.Fatalf("unexpected heartbeat response id: %x", respPkg.Header.BusinessType)
	}
	if _, ok := respPkg.Body.(HeartbeatResponse); !ok {
		t.Fatalf("unexpected heartbeat response body type: %T", respPkg.Body)
	}
}

// 主链路断开通知解析。
func TestMainLinkDisconnectNotify(t *testing.T) {
	data, err := EncodePackage(Package{
		Header: Header{GNSSCenterID: 123},
		Body:   DisconnectInform{ErrorCode: 1},
	})
	if err != nil {
		t.Fatalf("encode disconnect inform: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	notify, err := ParseDisconnectInform(frame)
	if err != nil {
		t.Fatalf("parse disconnect inform: %v", err)
	}
	if notify.ErrorCode != 1 {
		t.Fatalf("unexpected error code: %d", notify.ErrorCode)
	}
}

// ParseLoginResponse 用于测试解析登录应答业务体。
func ParseLoginResponse(body []byte) (LoginResponse, error) {
	if len(body) < 5 {
		return LoginResponse{}, errors.New("login response body too short")
	}
	result := LoginResult(body[0])
	verify := binary.BigEndian.Uint32(body[1:5])
	return LoginResponse{Result: result, VerifyCode: verify}, nil
}
