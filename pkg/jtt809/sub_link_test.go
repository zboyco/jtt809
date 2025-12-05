package jtt809

import "testing"

func TestSubLinkLoginEncodeDecode(t *testing.T) {
	header := Header{GNSSCenterID: 9}
	req := SubLinkLoginRequest{VerifyCode: 0x55667788}
	data, err := BuildSubLinkLoginPackage(header, req)
	if err != nil {
		t.Fatalf("encode sub link login: %v", err)
	}
	frame, err := DecodeFrame(data)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	if frame.BodyID != MsgIDDownlinkConnReq {
		t.Fatalf("unexpected body id: %x", frame.BodyID)
	}
}

func TestSubLinkAutoResponse(t *testing.T) {
	// login response
	req := SubLinkLoginRequest{VerifyCode: 0x01020304}
	data, _ := EncodePackage(Package{Header: Header{GNSSCenterID: 2}, Body: req})
	frame, _ := DecodeFrame(data)
	respPkg, err := GenerateResponse(frame, nil)
	if err != nil {
		t.Fatalf("generate response: %v", err)
	}
	if respPkg.Header.BusinessType != 0x9002 {
		t.Fatalf("unexpected resp id: %x", respPkg.Header.BusinessType)
	}
	// heartbeat response
	hbData, _ := EncodePackage(Package{Header: Header{GNSSCenterID: 3}, Body: SubLinkHeartbeatRequest{}})
	hbFrame, _ := DecodeFrame(hbData)
	hbResp, err := GenerateResponse(hbFrame, nil)
	if err != nil {
		t.Fatalf("generate hb response: %v", err)
	}
	if hbResp.Header.BusinessType != 0x9006 {
		t.Fatalf("unexpected hb resp id: %x", hbResp.Header.BusinessType)
	}

	// disconnect notify parsing
	notify, err := ParseSubLinkDisconnectNotify(hbFrame)
	if err == nil || notify != nil {
		t.Fatalf("expected parse error for wrong body id")
	}
	discData, _ := EncodePackage(Package{Header: Header{GNSSCenterID: 4}, Body: SubLinkDisconnectNotify{ReasonCode: 1}})
	discFrame, _ := DecodeFrame(discData)
	disc, err := ParseSubLinkDisconnectNotify(discFrame)
	if err != nil {
		t.Fatalf("parse disconnect notify: %v", err)
	}
	if disc.ReasonCode != 1 {
		t.Fatalf("unexpected reason: %d", disc.ReasonCode)
	}
}

func TestParseSubLinkResponses(t *testing.T) {
	// login response parse
	respData, _ := EncodePackage(Package{Header: Header{GNSSCenterID: 5}, Body: SubLinkLoginResponse{Result: 7}})
	respFrame, err := DecodeFrame(respData)
	if err != nil {
		t.Fatalf("decode login resp frame: %v", err)
	}
	resp, err := ParseSubLinkLoginResponse(respFrame)
	if err != nil {
		t.Fatalf("parse login resp: %v", err)
	}
	if resp.Result != 7 {
		t.Fatalf("unexpected result: %d", resp.Result)
	}
	// heartbeat response parse
	hbData, _ := EncodePackage(Package{Header: Header{GNSSCenterID: 6}, Body: SubLinkHeartbeatResponse{}})
	hbFrame, _ := DecodeFrame(hbData)
	if _, err := ParseSubLinkHeartbeatResponse(hbFrame); err != nil {
		t.Fatalf("parse heartbeat resp: %v", err)
	}
	// heartbeat response with payload should fail
	badFrame := *hbFrame
	badFrame.BodyID = 0x9006
	badFrame.RawBody = []byte{0x01}
	if _, err := ParseSubLinkHeartbeatResponse(&badFrame); err == nil {
		t.Fatalf("expected error for non-empty heartbeat response body")
	}
}
