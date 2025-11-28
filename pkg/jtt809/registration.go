package jtt809

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

// LoginResult 登录应答状态码，涵盖平台定义的鉴权结果。
type LoginResult byte

const (
	LoginOK              LoginResult = 0x00
	LoginIPError         LoginResult = 0x01
	LoginAccessCodeError LoginResult = 0x02
	LoginUnregistered    LoginResult = 0x03
	LoginPasswordError   LoginResult = 0x04
	LoginResourceBusy    LoginResult = 0x05
	LoginOtherError      LoginResult = 0x06
)

// LoginRequest 表示主链路登录请求（0x1001）的业务体，包含账号、密码、下级平台参数。
type LoginRequest struct {
	UserID          uint32
	Password        string
	AccessCode      uint32  // 2019版本新增：下级平台接入码
	DownLinkIP      string
	DownLinkPort    uint16
	ProtocolVersion [3]byte // 2019版本新增：协议版本号
}

func (l LoginRequest) MsgID() uint16 { return MsgIDLoginRequest }

func (l LoginRequest) Encode() ([]byte, error) {
	if err := l.validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.BigEndian, l.UserID)
	buf.Write(PadRightGBK(l.Password, 8))
	if l.AccessCode != 0 {
		_ = binary.Write(&buf, binary.BigEndian, l.AccessCode)
	}
	buf.Write(PadRightGBK(l.DownLinkIP, 32))
	_ = binary.Write(&buf, binary.BigEndian, l.DownLinkPort)
	buf.Write(l.ProtocolVersion[:])
	return buf.Bytes(), nil
}

func (l LoginRequest) validate() error {
	if len(l.Password) == 0 || len(l.Password) > 8 {
		return errors.New("password must be 1-8 characters")
	}
	if len(l.DownLinkIP) == 0 || len(l.DownLinkIP) > 32 {
		return errors.New("down link IP must be 1-32 characters")
	}
	return nil
}

// ParseLoginRequest 解析主链路登录请求业务体，返回结构化的登录参数。
// 仅支持 JT/T809-2019 版本协议
func ParseLoginRequest(body []byte) (LoginRequest, error) {
	// 2019版长度：4+8+4+32+2(+3) = 50-53字节（ProtocolVersion可选）
	if len(body) < 50 {
		return LoginRequest{}, errors.New("login body too short for 2019 version")
	}

	req := LoginRequest{
		UserID:     binary.BigEndian.Uint32(body[0:4]),
		Password:   strings.TrimRight(string(body[4:12]), "\x00"),
		AccessCode: binary.BigEndian.Uint32(body[12:16]),
		DownLinkIP: strings.TrimRight(string(body[16:48]), "\x00"),
		DownLinkPort: binary.BigEndian.Uint16(body[48:50]),
	}

	// 解析协议版本号（如果有）
	if len(body) >= 53 {
		copy(req.ProtocolVersion[:], body[50:53])
	}
	return req, nil
}

// LoginResponse 登录应答（0x1002），包含结果与校验码。
type LoginResponse struct {
	Result     LoginResult
	VerifyCode uint32
}

func (LoginResponse) MsgID() uint16 { return MsgIDLoginResponse }

func (l LoginResponse) Encode() ([]byte, error) {
	buf := []byte{byte(l.Result), 0x00, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint32(buf[1:], l.VerifyCode)
	return buf, nil
}

// AuthValidator 定义鉴权回调接口，可注入自定义帐号校验逻辑。
type AuthValidator func(LoginRequest) (LoginResponse, error)

// SimpleAuthValidator 提供基于固定账号/密码的简易鉴权实现，验证失败时返回对应错误码。
func SimpleAuthValidator(expectedUser uint32, expectedPassword string, verifyCode uint32) AuthValidator {
	return func(req LoginRequest) (LoginResponse, error) {
		if req.UserID != expectedUser {
			return LoginResponse{Result: LoginUnregistered, VerifyCode: verifyCode}, nil
		}
		if req.Password != expectedPassword {
			return LoginResponse{Result: LoginPasswordError, VerifyCode: verifyCode}, nil
		}
		return LoginResponse{Result: LoginOK, VerifyCode: verifyCode}, nil
	}
}

// BuildLoginPackage 直接构造登录请求完整报文（含头、业务体与转义）。
func BuildLoginPackage(header Header, req LoginRequest) ([]byte, error) {
	header.BusinessType = MsgIDLoginRequest
	return EncodePackage(Package{
		Header: header,
		Body:   req,
	})
}

// BuildLoginResponsePackage 根据请求头构造对应的登录应答报文，自动填充响应业务 ID。
func BuildLoginResponsePackage(requestHeader Header, resp LoginResponse) ([]byte, error) {
	header := requestHeader.WithResponse(MsgIDLoginResponse)
	return EncodePackage(Package{
		Header: header,
		Body:   resp,
	})
}
