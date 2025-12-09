package server

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/zboyco/jtt809/pkg/jtt809"
	"github.com/zboyco/jtt809/pkg/jtt809/jt1078"
)

// VideoRequest 表示向下级平台下发的实时音视频请求。
type VideoRequest struct {
	UserID       uint32            `json:"user_id"`
	VehicleNo    string            `json:"vehicle_no"`
	VehicleColor jtt809.PlateColor `json:"vehicle_color"`
	ChannelID    byte              `json:"channel_id"`
	AVItemType   byte              `json:"av_item_type"`
	GnssHex      string            `json:"gnss_hex,omitempty"`
}

// RequestVideoStream 通过从链路向下级平台发送实时视频请求（0x9801 下行实时音视频）。
// 注意：0x9801 是上级→下级的下行消息，应该通过从链路发送；
//
//	0x1801 是下级→上级的上行消息，通过主链路发送。
func (g *JT809Gateway) RequestVideoStream(req VideoRequest) error {
	if req.VehicleNo == "" {
		return errors.New("vehicle_no is required")
	}
	if req.VehicleColor == 0 {
		req.VehicleColor = jtt809.PlateColorBlue
	}
	_, authCode := g.store.GetAuthCode(req.UserID)
	if authCode == "" {
		return fmt.Errorf("authorize_code not found in store for platform %d. Please wait for the platform to report the authorize code after login", req.UserID)
	}
	snap, ok := g.store.Snapshot(req.UserID)
	if !ok {
		return fmt.Errorf("platform %d not online", req.UserID)
	}
	// 视频请求是下行消息（0x9801），应该通过从链路发送
	if !snap.SubConnected {
		return errors.New("sub link is not established")
	}
	if snap.GNSSCenterID == 0 {
		return fmt.Errorf("gnss_center_id is missing for platform %d, abort send", req.UserID)
	}
	subClient, ok := g.store.GetSubClient(req.UserID)
	if !ok {
		return errors.New("sub link client not available")
	}
	var (
		gnssData []byte
		err      error
	)
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
	// 通过从链路发送
	if err := subClient.Send(data); err != nil {
		return fmt.Errorf("send frame: %w", err)
	}
	slog.Info("video request sent", "user_id", req.UserID, "plate", req.VehicleNo, "channel", req.ChannelID)
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

func buildSubBusinessBody(plate string, color jtt809.PlateColor, subID uint16, payload []byte) ([]byte, error) {
	plateBytes, err := jtt809.EncodeGBK(plate)
	if err != nil {
		return nil, fmt.Errorf("encode plate: %w", err)
	}
	buf := make([]byte, 0, 21+1+2+4+len(payload))
	field := make([]byte, 21)
	copy(field, plateBytes)
	buf = append(buf, field...)
	buf = append(buf, byte(color))
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], subID)
	buf = append(buf, tmp[:]...)
	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)))
	buf = append(buf, length...)
	buf = append(buf, payload...)
	return buf, nil
}
