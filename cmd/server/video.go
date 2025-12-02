package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	goserver "github.com/zboyco/go-server"
	"github.com/zboyco/jtt809/pkg/jtt809"
	"github.com/zboyco/jtt809/pkg/jtt809/jt1078"
)

// VideoRequest 表示向下级平台下发的实时音视频请求。
type VideoRequest struct {
	UserID       uint32 `json:"user_id"`
	VehicleNo    string `json:"vehicle_no"`
	VehicleColor byte   `json:"vehicle_color"`
	ChannelID    byte   `json:"channel_id"`
	AVItemType   byte   `json:"av_item_type"`
	GnssHex      string `json:"gnss_hex,omitempty"`
}

// MonitorRequest 表示车辆定位信息交换请求（订阅/取消订阅车辆GPS）。
type MonitorRequest struct {
	UserID       uint32 `json:"user_id"`
	VehicleNo    string `json:"vehicle_no"`
	VehicleColor byte   `json:"vehicle_color"`
	ReasonCode   byte   `json:"reason_code"` // 0=进入区域,1=人工指定,2=应急,3=其它
}

// RequestVideoStream 通过主链路向下级平台发送实时视频请求。
func (g *JT809Gateway) RequestVideoStream(req VideoRequest) error {
	if req.VehicleNo == "" {
		return errors.New("vehicle_no is required")
	}
	if req.VehicleColor == 0 {
		req.VehicleColor = jtt809.VehicleColorBlue
	}
	_, authCode := g.store.GetAuthCode(req.UserID)
	if authCode == "" {
		return fmt.Errorf("authorize_code not found in store for platform %d. Please wait for the platform to report the authorize code after login", req.UserID)
	}
	snap, ok := g.store.Snapshot(req.UserID)
	if !ok {
		return fmt.Errorf("platform %d not online", req.UserID)
	}
	if snap.MainSessionID == "" {
		return errors.New("main link is not established")
	}
	session, err := g.mainSrv.GetSessionByID(snap.MainSessionID)
	if err != nil {
		return fmt.Errorf("fetch session: %w", err)
	}
	var gnssData []byte
	if strings.TrimSpace(req.GnssHex) != "" {
		gnssData, err = hex.DecodeString(strings.TrimSpace(req.GnssHex))
		if err != nil {
			return fmt.Errorf("parse gnss hex: %w", err)
		}
		if len(gnssData) != 36 {
			return fmt.Errorf("gnss data must be 36 bytes, got %d", len(gnssData))
		}
	}
	body := jt1078.DownRealTimeVideoStartupReq{
		ChannelID:     req.ChannelID,
		AVItemType:    req.AVItemType,
		AuthorizeCode: authCode,
		GnssData:      gnssData,
	}
	payload, err := body.Encode()
	if err != nil {
		return fmt.Errorf("encode video request: %w", err)
	}
	subBody, err := buildSubBusinessBody(req.VehicleNo, req.VehicleColor, body.MsgID(), payload)
	if err != nil {
		return err
	}
	msg := jtt809.Package{
		Header: jtt809.Header{
			GNSSCenterID: snap.GNSSCenterID,
			BusinessType: jtt809.MsgIDDownRealTimeVideo,
			WithUTC:      true,
		},
		Body: rawBody{
			msgID:   jtt809.MsgIDDownRealTimeVideo,
			payload: subBody,
		},
	}
	data, err := jtt809.EncodePackage(msg)
	if err != nil {
		return fmt.Errorf("encode package: %w", err)
	}
	if err := sendFrame(session, data); err != nil {
		return err
	}
	slog.Info("video request sent", "user_id", req.UserID, "plate", req.VehicleNo, "channel", req.ChannelID)
	return nil
}

func sendFrame(session *goserver.AppSession, data []byte) error {
	if session == nil {
		return errors.New("session is nil")
	}
	if err := session.Send(data); err != nil {
		return fmt.Errorf("send frame: %w", err)
	}
	return nil
}

// rawBody 允许直接注入编码好的业务体。
type rawBody struct {
	msgID   uint16
	payload []byte
}

func (r rawBody) MsgID() uint16 { return r.msgID }

func (r rawBody) Encode() ([]byte, error) {
	return r.payload, nil
}

// RequestMonitorStartup 通过从链路向下级平台发送启动车辆定位信息交换请求。
func (g *JT809Gateway) RequestMonitorStartup(req MonitorRequest) error {
	if req.VehicleNo == "" {
		return errors.New("vehicle_no is required")
	}
	if req.VehicleColor == 0 {
		req.VehicleColor = jtt809.VehicleColorBlue
	}
	return g.sendMonitorRequest(req, true)
}

// RequestMonitorEnd 通过从链路向下级平台发送结束车辆定位信息交换请求。
func (g *JT809Gateway) RequestMonitorEnd(req MonitorRequest) error {
	if req.VehicleNo == "" {
		return errors.New("vehicle_no is required")
	}
	if req.VehicleColor == 0 {
		req.VehicleColor = jtt809.VehicleColorBlue
	}
	return g.sendMonitorRequest(req, false)
}

func (g *JT809Gateway) sendMonitorRequest(req MonitorRequest, startup bool) error {
	g.store.mu.RLock()
	state := g.store.platforms[req.UserID]
	g.store.mu.RUnlock()
	if state == nil {
		return fmt.Errorf("platform %d not online", req.UserID)
	}
	if state.SubClient == nil {
		return errors.New("sub link is not established")
	}
	var body jtt809.Body
	if startup {
		body = jtt809.ApplyForMonitorStartup{
			VehicleNo:    req.VehicleNo,
			VehicleColor: req.VehicleColor,
			ReasonCode:   jtt809.MonitorReasonCode(req.ReasonCode),
		}
	} else {
		body = jtt809.ApplyForMonitorEnd{
			VehicleNo:    req.VehicleNo,
			VehicleColor: req.VehicleColor,
			ReasonCode:   jtt809.MonitorReasonCode(req.ReasonCode),
		}
	}
	msg := jtt809.Package{
		Header: jtt809.Header{
			GNSSCenterID: state.GNSSCenterID,
			WithUTC:      true,
		},
		Body: body,
	}
	data, err := jtt809.EncodePackage(msg)
	if err != nil {
		return fmt.Errorf("encode package: %w", err)
	}
	g.logPacket("sub", "send", fmt.Sprintf("%d", req.UserID), data)
	if err := state.SubClient.Send(data); err != nil {
		return fmt.Errorf("send frame: %w", err)
	}
	action := "startup"
	if !startup {
		action = "end"
	}
	slog.Info("monitor request sent", "action", action, "user_id", req.UserID, "plate", req.VehicleNo)
	return nil
}

func buildSubBusinessBody(plate string, color byte, subID uint16, payload []byte) ([]byte, error) {
	plateBytes, err := jtt809.EncodeGBK(plate)
	if err != nil {
		return nil, fmt.Errorf("encode plate: %w", err)
	}
	buf := make([]byte, 0, 21+1+2+4+len(payload))
	field := make([]byte, 21)
	copy(field, plateBytes)
	buf = append(buf, field...)
	buf = append(buf, color)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], subID)
	buf = append(buf, tmp[:]...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)))
	buf = append(buf, length...)
	buf = append(buf, payload...)
	return buf, nil
}
