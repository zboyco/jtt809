package server

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/zboyco/jtt809/pkg/jtt809"
)

// MonitorRequest 表示车辆定位信息交换请求（订阅/取消订阅车辆GPS）。
type MonitorRequest struct {
	UserID       uint32 `json:"user_id"`
	VehicleNo    string `json:"vehicle_no"`
	VehicleColor byte   `json:"vehicle_color"`
	ReasonCode   byte   `json:"reason_code"` // 0=进入区域,1=人工指定,2=应急,3=其它
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
	if state.GNSSCenterID == 0 {
		slog.Warn("skip monitor request, missing GNSSCenterID", "user_id", req.UserID, "vehicle", req.VehicleNo)
		return fmt.Errorf("gnss_center_id is missing for platform %d, abort send", req.UserID)
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
