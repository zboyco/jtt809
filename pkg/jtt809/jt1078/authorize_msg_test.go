package jt1078

import (
	"testing"

	"github.com/zboyco/jtt809/pkg/jtt809"
)

func TestAuthorizeMsg(t *testing.T) {
	// Test 0x1701 (AuthorizeStartupReq) wrapped in 0x1700
	// 0x1700 消息体结构：子业务ID(2字节) + JT/T 1078-2016 数据
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

	// 验证编码长度：2(子业务ID) + 139(JT/T 1078-2016数据) = 141字节
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
