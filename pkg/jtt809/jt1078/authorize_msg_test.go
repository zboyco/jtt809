package jt1078

import (
	"testing"

	"github.com/zboyco/jtt809/pkg/jtt809"
)

func TestAuthorizeMsg(t *testing.T) {
	// Test 0x1701 (AuthorizeStartupReq) wrapped in 0x1700
	// 0x1700 消息体结构：子业务ID(2字节) + JT/T 1078 数据
	req := AuthorizeStartupReq{
		PlatformID:     "12345678901",
		AuthorizeCode1: "AUTH_CODE_1_TEST_64_BYTES_PADDING_PADDING_PADDING_PADDING_PADDING",
		AuthorizeCode2: "AUTH_CODE_2_TEST_64_BYTES_PADDING_PADDING_PADDING_PADDING_PADDING",
	}
	reqPayload, err := req.Encode()
	if err != nil {
		t.Fatalf("encode req failed: %v", err)
	}

	// 构造 0x1700 消息体
	authMsg := AuthorizeMsg{
		SubBusinessID: jtt809.SubMsgAuthorizeStartupReq,
		Payload:       reqPayload,
	}

	encoded, err := authMsg.Encode()
	if err != nil {
		t.Fatalf("encode auth msg failed: %v", err)
	}

	// 验证编码长度：2(子业务ID) + 139(JT/T 1078数据) = 141字节
	expectedLen := 2 + 11 + 64 + 64
	if len(encoded) != expectedLen {
		t.Errorf("expected length %d, got %d", expectedLen, len(encoded))
	}

	// 解析
	decoded, err := ParseAuthorizeMsg(encoded)
	if err != nil {
		t.Fatalf("parse auth msg failed: %v", err)
	}

	if decoded.SubBusinessID != jtt809.SubMsgAuthorizeStartupReq {
		t.Errorf("expected sub id 0x1701, got 0x%04X", decoded.SubBusinessID)
	}

	decodedReq, err := ParseAuthorizeStartupReq(decoded.Payload)
	if err != nil {
		t.Fatalf("parse inner req failed: %v", err)
	}
	if decodedReq.PlatformID != req.PlatformID {
		t.Errorf("expected platform id %s, got %s", req.PlatformID, decodedReq.PlatformID)
	}
}

func TestDownAuthorizeMsg(t *testing.T) {
	// Test 0x9702 (AuthorizeStartupReqAck) wrapped in 0x9700
	// 0x9700 消息体结构：子业务ID(2字节) + JT/T 1078 数据
	ack := AuthorizeStartupReqAckMsg{}
	ackPayload, _ := ack.Encode()

	downMsg := DownAuthorizeMsg{
		SubBusinessID: jtt809.SubMsgAuthorizeStartupReqAck,
		Payload:       ackPayload,
	}

	encoded, err := downMsg.Encode()
	if err != nil {
		t.Fatalf("encode down msg failed: %v", err)
	}

	// 验证编码长度：SubID(2) + Payload(0) = 2字节
	if len(encoded) != 2 {
		t.Errorf("expected length %d, got %d", 2, len(encoded))
	}

	// 验证 SubID: 0x9702
	if encoded[0] != 0x97 || encoded[1] != 0x02 {
		t.Errorf("expected sub id 0x9702, got 0x%02X%02X", encoded[0], encoded[1])
	}
}

func TestAuthorizeStartupReqMsg(t *testing.T) {
	// 3. Test 0x1702 (AuthorizeStartupReqMsg)
	// It's empty body
	msg := AuthorizeStartupReqMsg{}
	data, _ := msg.Encode()
	if len(data) != 0 {
		t.Errorf("expected empty body for 0x1702, got %d bytes", len(data))
	}
}
