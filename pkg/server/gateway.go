package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	goserver "github.com/zboyco/go-server"
	"github.com/zboyco/go-server/client"
	"github.com/zboyco/jtt809/pkg/jtt809"
	"github.com/zboyco/jtt809/pkg/jtt809/jt1078"
)

// LinkPolicy 链路策略配置
type LinkPolicy struct {
	PreferredLink string // "main" 或 "sub"
	AllowFallback bool   // 是否允许降级
}

// 链路策略配置表
var linkPolicies = map[uint16]LinkPolicy{
	jtt809.MsgIDLoginResponse:        {PreferredLink: "main", AllowFallback: false}, // 0x1002 主链路登录应答，不能降级
	jtt809.MsgIDDownlinkConnReq:      {PreferredLink: "sub", AllowFallback: false},  // 0x9001 从链路登录请求，不能降级
	jtt809.MsgIDDownHeartbeatRequest: {PreferredLink: "sub", AllowFallback: false},  // 0x9005 从链路心跳请求，不能降级
	jtt809.MsgIDDownDisconnectInform: {PreferredLink: "main", AllowFallback: false}, // 0x9007 从链路断开通知，只能主链路
}

// 默认策略：从链路，允许降级
var defaultLinkPolicy = LinkPolicy{
	PreferredLink: "sub",
	AllowFallback: true,
}

// JT809Gateway 负责承载主/从链路 TCP 服务与业务处理。
type JT809Gateway struct {
	cfg   Config
	auth  *Authenticator
	store *PlatformStore

	mainSrv *goserver.Server
	httpSrv *http.Server

	callbacks *Callbacks // 消息回调

	startOnce sync.Once
}

func NewJT809Gateway(cfg Config) (*JT809Gateway, error) {
	if len(cfg.Accounts) == 0 {
		return nil, errors.New("at least one account is required")
	}

	printStartupInfo(cfg)

	return &JT809Gateway{
		cfg:   cfg,
		auth:  NewAuthenticator(cfg.Accounts),
		store: NewPlatformStore(),
	}, nil
}

// SetCallbacks 设置回调函数，用于在收到特定消息时执行自定义业务逻辑
func (g *JT809Gateway) SetCallbacks(callbacks *Callbacks) {
	g.callbacks = callbacks
}

// Start 同时启动主链路、从链路服务，并阻塞直至 ctx 结束。
func (g *JT809Gateway) Start(ctx context.Context) error {
	var startErr error
	g.startOnce.Do(func() {
		if err := g.initServers(); err != nil {
			startErr = err
			return
		}
		go g.mainSrv.Start()
		g.startHTTPServer(ctx)
		go g.healthCheckLoop(ctx)
	})
	if startErr != nil {
		return startErr
	}
	<-ctx.Done()
	slog.Info("gateway shutting down", "reason", ctx.Err())
	return nil
}

func (g *JT809Gateway) initServers() error {
	mainHost, mainPort, err := normalizeHostPort(g.cfg.MainListen)
	if err != nil {
		return fmt.Errorf("parse main listen: %w", err)
	}
	g.mainSrv = goserver.NewTCP(mainHost, mainPort)

	if g.cfg.IdleTimeout > 0 {
		g.mainSrv.IdleSessionTimeOut = int(g.cfg.IdleTimeout.Seconds())
	} else {
		g.mainSrv.IdleSessionTimeOut = 0
	}

	if err := g.mainSrv.SetSplitFunc(splitJT809Frames); err != nil {
		return err
	}

	if err := g.mainSrv.SetOnMessage(g.handleMainMessage); err != nil {
		return err
	}

	_ = g.mainSrv.SetOnError(func(err error) {
		slog.Error("main link error", "err", err)
	})

	_ = g.mainSrv.SetOnSessionClosed(g.onSessionClosed)
	_ = g.mainSrv.SetOnNewSessionRegister(func(s *goserver.AppSession) {
		ip := g.getClientIP(s)
		if ip != "" {
			slog.Info("main link connected", "session", s.ID, "remote_ip", ip)
			return
		}
		slog.Info("main link connected", "session", s.ID)
	})
	return nil
}

// handleMainMessage 处理主链路报文。
func (g *JT809Gateway) handleMainMessage(session *goserver.AppSession, payload []byte) ([]byte, error) {
	g.logPacket("main", "recv", session.ID, payload)
	frame, err := jtt809.DecodeFrame(payload)
	if err != nil {
		slog.Warn("decode main frame failed", "session", session.ID, "err", err)
		return nil, nil
	}
	if _, ok := g.sessionUser(session); !ok && frame.BodyID != jtt809.MsgIDLoginRequest {
		// 未登录成功前的报文直接忽略
		slog.Warn("ignore message before login", "session", session.ID, "msg_id", fmt.Sprintf("0x%04X", frame.BodyID))
		return nil, nil
	}
	switch frame.BodyID {
	case jtt809.MsgIDLoginRequest:
		return g.handleMainLogin(session, frame)
	case jtt809.MsgIDHeartbeatRequest:
		return g.handleHeartbeat(session, frame, true)
	case jtt809.MsgIDLogoutRequest:
		user, ok := g.sessionUser(session)
		if ok {
			resp := jtt809.LogoutResponse{}
			if err := g.SendToSubordinate(user, frame.Header, resp); err != nil {
				slog.Error("send logout response failed", "user_id", user, "err", err)
			}
		}
		return nil, nil
	case jtt809.MsgIDDownDisconnectInform:
		g.handleDisconnectInform(session, frame)
	default:
		user, ok := g.sessionUser(session)
		if ok {
			g.handleBusinessMessage(user, frame, true)
		}
	}
	return nil, nil
}

// handleSubMessage 处理从链路报文（Active Mode）。
// 正常情况下从链路用于接收应答，但当主链路断开时，下级平台可能通过从链路发送请求。
func (g *JT809Gateway) handleSubMessage(userID uint32, payload []byte) {
	g.logPacket("sub", "recv", fmt.Sprintf("%d", userID), payload)
	frame, err := jtt809.DecodeFrame(payload)
	if err != nil {
		slog.Warn("decode sub frame failed", "user_id", userID, "err", err)
		return
	}

	switch frame.BodyID {
	case jtt809.MsgIDDownlinkConnReq:
		slog.Debug("received sub link login request on sub link", "user_id", userID)
	case jtt809.MsgIDDownlinkConnResp:
		slog.Debug("received sub link login response", "user_id", userID)
	case jtt809.MsgIDDisconnNotify:
		g.handleSubDisconnect(userID, frame)
	default:
		g.handleBusinessMessage(userID, frame, false)
	}
}

// handleBusinessMessage 处理可能在主链路或从链路接收的业务消息
func (g *JT809Gateway) handleBusinessMessage(userID uint32, frame *jtt809.Frame, receivedOnMain bool) {
	switch frame.BodyID {
	case jtt809.MsgIDDynamicInfo:
		g.handleDynamicInfo(userID, frame)
	case jtt809.MsgIDPlatformInfo:
		g.handlePlatformInfo(userID, frame)
	case jtt809.MsgIDRealTimeVideo:
		g.handleRealTimeVideo(userID, frame)
	case jtt809.MsgIDAuthorize:
		g.handleAuthorize(userID, frame)
	case jtt809.MsgIDAlarmInteract:
		g.handleAlarmInteract(nil, frame)
	case jtt809.MsgIDDownHeartbeatResponse:
		g.store.RecordHeartbeat(userID, false)
	default:
		linkType := "main"
		if !receivedOnMain {
			linkType = "sub"
		}
		slog.Debug("unhandled business message", "user_id", userID, "link", linkType, "msg_id", fmt.Sprintf("0x%04X", frame.BodyID))
	}
}

func (g *JT809Gateway) handleMainLogin(session *goserver.AppSession, frame *jtt809.Frame) ([]byte, error) {
	req, err := jtt809.ParseLoginRequest(frame.RawBody)
	if err != nil {
		slog.Warn("parse main login failed", "session", session.ID, "err", err)
		return nil, nil
	}
	clientIP := g.getClientIP(session)
	acc, resp := g.auth.Authenticate(req, clientIP)
	slog.Info("main login request", "session", session.ID, "user_id", req.UserID, "gnss", frame.Header.GNSSCenterID, "ip", clientIP, "result", resp.Result)
	if resp.Result == jtt809.LoginOK {
		session.SetAttr("userID", req.UserID)
		session.SetAttr("link", "main")
		g.store.BindMainSession(session.ID, req, acc.GnssCenterID, resp.VerifyCode)

		// 触发登录回调
		if g.callbacks != nil && g.callbacks.OnLogin != nil {
			go g.callbacks.OnLogin(req.UserID, &req, &resp)
		}

		// Start Sub Link Connection
		go g.connectSubLinkWithRetry(req.UserID, false)
	}

	// 主链路登录应答通过统一方法发送（配置为主链路，不允许降级）
	if err := g.SendToSubordinate(req.UserID, frame.Header, resp); err != nil {
		slog.Error("send login response failed", "user_id", req.UserID, "err", err)
	}

	if resp.Result != jtt809.LoginOK {
		// 登录失败后立即断开
		session.Close("login failed")
	}
	return nil, nil
}

func (g *JT809Gateway) connectSubLinkWithRetry(userID uint32, isReconnect bool) {
	// 设置重连标志，如果已经在重连则直接返回
	if !g.store.SetReconnecting(userID, true) {
		slog.Info("sub link already reconnecting, skip", "user_id", userID)
		return
	}
	defer g.store.SetReconnecting(userID, false)

	// 重试次数策略
	maxRetries := 3
	if !isReconnect {
		maxRetries = 1
	}

	for i := 0; i < maxRetries; i++ {
		// 检查从链路是否已连接（防止竞态条件导致重复连接）
		_, subActive := g.store.GetLinkStatus(userID)
		if subActive {
			slog.Info("sub link already connected, stop reconnecting", "user_id", userID)
			return
		}

		// 检查主链路是否仍然活跃
		snap, ok := g.store.Snapshot(userID)
		if !ok || snap.MainSessionID == "" {
			slog.Info("main link not active, stop reconnecting", "user_id", userID)
			return
		}

		if snap.DownLinkIP == "" || snap.DownLinkPort == 0 {
			slog.Warn("missing sub link address, stop reconnecting", "user_id", userID, "ip", snap.DownLinkIP, "port", snap.DownLinkPort)
			return
		}
		if snap.GNSSCenterID == 0 {
			slog.Warn("missing GNSSCenterID, stop sub link reconnect", "user_id", userID)
			return
		}

		if g.connectSubLink(snap.DownLinkIP, snap.DownLinkPort, userID, snap.GNSSCenterID, snap.VerifyCode) {
			return
		}

		// 仅在重连模式下等待重试
		if isReconnect && i < maxRetries-1 {
			time.Sleep(10 * time.Second) // 缩短等待时间以便快速重试
			slog.Info("retrying sub link connection", "user_id", userID, "attempt", i+1)
		}
	}

	// 重试失败，发送从链路断开通知
	errorCode := jtt809.DisconnectCannotConnectSub // 情景2：无法连接指定IP端口 (0x00)
	if isReconnect {
		errorCode = jtt809.DisconnectSubLinkBroken // 情景1：重连三次失败 (0x01)
	}

	slog.Warn("sub link connection failed, sending notification", "user_id", userID, "error_code", errorCode)
	g.sendDownDisconnectInform(userID, errorCode)
}

// sendDownDisconnectInform 发送从链路断开通知 (0x9007)
func (g *JT809Gateway) sendDownDisconnectInform(userID uint32, code jtt809.DisconnectErrorCode) {
	snap, ok := g.store.Snapshot(userID)
	if !ok || snap.MainSessionID == "" {
		return
	}

	// 构造消息
	msg := jtt809.DownDisconnectInform{ErrorCode: code}
	header := jtt809.Header{
		GNSSCenterID: snap.GNSSCenterID,
		Version:      jtt809.Version{Major: 1, Minor: 0, Patch: 0},
		EncryptFlag:  0,
		EncryptKey:   0,
	}

	// 通过统一方法发送（配置为主链路，不允许降级）
	if err := g.SendToSubordinate(userID, header, msg); err != nil {
		slog.Warn("send 0x9007 failed", "user_id", userID, "err", err)
	}
}

func (g *JT809Gateway) connectSubLink(ip string, port uint16, userID uint32, gnssCenterID uint32, verifyCode uint32) bool {
	slog.Info("connecting sub link", "ip", ip, "port", port, "user_id", userID)

	c := client.NewSimpleClient(goserver.TCP, ip, int(port))
	c.SetScannerSplitFunc(splitJT809Frames)

	if err := c.Connect(); err != nil {
		slog.Error("connect sub link failed", "err", err)
		return false
	}

	// 设置读写超时
	if conn := c.GetRawConn(); conn != nil {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	// Send Login
	req := jtt809.SubLinkLoginRequest{VerifyCode: verifyCode}
	pkg, _ := jtt809.BuildSubLinkLoginPackage(jtt809.Header{
		BusinessType: jtt809.MsgIDDownlinkConnReq,
		GNSSCenterID: gnssCenterID,
	}, req)

	g.logPacket("sub", "send", fmt.Sprintf("%d", userID), pkg)
	if err := c.Send(pkg); err != nil {
		slog.Error("send sub login failed", "err", err)
		c.Close()
		return false
	}

	// Read Response
	respData, err := c.Receive()
	if err != nil {
		slog.Error("read sub login response failed", "err", err)
		c.Close()
		return false
	}
	g.logPacket("sub", "recv", fmt.Sprintf("%d", userID), respData)

	frame, err := jtt809.DecodeFrame(respData)
	if err != nil {
		slog.Error("decode sub login response failed", "err", err)
		c.Close()
		return false
	}

	if frame.BodyID != 0x9002 {
		slog.Error("unexpected sub login response", "msg_id", fmt.Sprintf("0x%04X", frame.BodyID))
		c.Close()
		return false
	}

	loginResp, err := jtt809.ParseSubLinkLoginResponse(frame)
	if err != nil {
		slog.Error("parse sub login response failed", "err", err)
		c.Close()
		return false
	}

	if loginResp.Result != 0 {
		slog.Error("sub link login refused", "result", loginResp.Result)
		c.Close()
		return false
	}

	slog.Info("sub link connected and logged in", "user_id", userID)

	// 清除超时限制，后续由心跳保活
	if conn := c.GetRawConn(); conn != nil {
		conn.SetDeadline(time.Time{})
	}

	// 创建 context 用于控制从链路相关 goroutine 的生命周期
	ctx, cancel := context.WithCancel(context.Background())
	g.store.BindSubSession(userID, c, cancel)

	go g.readSubLinkLoop(ctx, c, userID, gnssCenterID, verifyCode, true)
	go g.keepAliveSubLink(ctx, c, userID)
	return true
}

func (g *JT809Gateway) readSubLinkLoop(ctx context.Context, c *client.SimpleClient, userID uint32, gnssCenterID uint32, verifyCode uint32, shouldReconnect bool) {
	defer func() {
		c.Close()
		g.store.ClearSubConn(userID)
		slog.Info("sub link closed", "user_id", userID)
		// 仅在需要重连时触发
		if shouldReconnect {
			go g.reconnectSubLink(userID)
		}
	}()

	// 启用一个 goroutine 监听 context 取消
	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		slog.Info("sub read loop stopping due to context cancel", "user_id", userID)
		c.Close() // 关闭连接以中断 Receive() 调用
		close(done)
	}()

	for {
		select {
		case <-done:
			return
		default:
			data, err := c.Receive()
			if err != nil {
				slog.Error("sub link read error", "user_id", userID, "err", err)
				return
			}
			g.handleSubMessage(userID, data)
		}
	}
}

func (g *JT809Gateway) reconnectSubLink(userID uint32) {
	time.Sleep(5 * time.Second)
	snap, ok := g.store.Snapshot(userID)
	if !ok || snap.MainSessionID == "" {
		slog.Info("skip sub link reconnect, main link not active", "user_id", userID)
		return
	}
	slog.Info("attempting sub link reconnect", "user_id", userID)
	g.connectSubLinkWithRetry(userID, true)
}

func (g *JT809Gateway) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			g.checkConnections()
		}
	}
}

func (g *JT809Gateway) checkConnections() {
	snapshots := g.store.Snapshots()
	now := time.Now()

	for _, snap := range snapshots {
		// 检查主链路断开超时情况
		if snap.MainSessionID == "" && snap.SubConnected && !snap.MainDisconnectedAt.IsZero() {
			// 主链路断开超过5分钟，关闭从链路以释放资源
			if now.Sub(snap.MainDisconnectedAt) > 5*time.Minute {
				slog.Warn("main link disconnected timeout, closing sub link",
					"user_id", snap.UserID,
					"disconnected_duration", now.Sub(snap.MainDisconnectedAt))
				g.store.CloseSubLink(snap.UserID)
			}
			// 主链路断开但还未超时，从链路保持
			continue
		}

		// 主链路正常的情况
		if snap.MainSessionID == "" {
			continue
		}

		// 检查从链路是否需要重连
		if !snap.SubConnected && snap.DownLinkIP != "" && snap.DownLinkPort > 0 {
			slog.Warn("sub link disconnected, triggering reconnect", "user_id", snap.UserID)
			go g.connectSubLinkWithRetry(snap.UserID, true)
		}
	}
	// 检查车辆定位状态
	g.checkVehiclePositions()
}

func (g *JT809Gateway) keepAliveSubLink(ctx context.Context, c *client.SimpleClient, userID uint32) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("sub heartbeat goroutine stopped", "user_id", userID)
			return
		case <-ticker.C:
			snap, ok := g.store.Snapshot(userID)
			if !ok {
				slog.Warn("skip sub heartbeat, snapshot missing", "user_id", userID)
				continue
			}
			if snap.GNSSCenterID == 0 {
				slog.Warn("skip sub heartbeat, missing GNSSCenterID", "user_id", userID)
				continue
			}
			hb, _ := jtt809.BuildSubLinkHeartbeat(jtt809.Header{
				GNSSCenterID: snap.GNSSCenterID,
			})
			g.logPacket("sub", "send", fmt.Sprintf("%d", userID), hb)
			if err := c.Send(hb); err != nil {
				slog.Warn("send sub heartbeat failed", "user_id", userID, "err", err)
				// 心跳失败，主动关闭连接以触发readSubLinkLoop退出
				c.Close()
				return
			}
		}
	}
}

func (g *JT809Gateway) handleHeartbeat(session *goserver.AppSession, frame *jtt809.Frame, isMain bool) ([]byte, error) {
	user, ok := g.sessionUser(session)
	if !ok {
		slog.Warn("heartbeat before login", "session", session.ID)
		return nil, nil
	}

	g.store.RecordHeartbeat(user, isMain)

	slog.Info("main link heartbeat", "session", session.ID, "user_id", user)
	resp := jtt809.HeartbeatResponse{}
	if err := g.SendToSubordinate(user, frame.Header, resp); err != nil {
		slog.Error("send heartbeat response failed", "user_id", user, "err", err)
	}
	return nil, nil
}

func (g *JT809Gateway) handleDynamicInfo(userID uint32, frame *jtt809.Frame) {
	pkt, err := jtt809.ParseSubBusiness(frame.RawBody)
	if err != nil {
		slog.Warn("parse sub business failed", "user_id", userID, "err", err)
		return
	}
	switch {
	case pkt.SubBusinessID == jtt809.SubMsgUploadVehicleReg:
		info, err := jtt809.ParseVehicleRegistration(pkt.Payload)
		if err != nil {
			slog.Warn("parse vehicle registration failed", "user_id", userID, "err", err)
			return
		}
		reg := &VehicleRegistration{
			PlatformID:        info.PlatformID,
			ProducerID:        info.ProducerID,
			TerminalModelType: info.TerminalModelType,
			IMEI:              info.IMEI,
			TerminalID:        info.TerminalID,
			TerminalSIM:       info.TerminalSIM,
		}
		g.store.UpdateVehicleRegistration(userID, pkt.Color, pkt.Plate, reg)
		slog.Info("vehicle registration", "user_id", userID, "plate", pkt.Plate, "platform", reg.PlatformID)

		// 触发车辆注册回调
		if g.callbacks != nil && g.callbacks.OnVehicleRegistration != nil {
			go g.callbacks.OnVehicleRegistration(userID, pkt.Plate, pkt.Color, reg)
		}

		// 自动订阅该车辆的实时定位数据
		go g.autoSubscribeVehicle(userID, pkt.Color, pkt.Plate)
	case pkt.SubBusinessID == jtt809.SubMsgRealLocation:
		pos, err := jtt809.ParseVehiclePosition(pkt.Payload)
		if err != nil {
			slog.Warn("parse vehicle position failed", "user_id", userID, "err", err)
			return
		}
		g.store.UpdateLocation(userID, pkt.Color, pkt.Plate, &pos, 0)

		// 触发车辆定位回调
		var gnssData *jtt809.GNSSData
		if gnss, err := jtt809.ParseGNSSData(pos.GnssData); err == nil {
			gnssData = &gnss
		}
		if g.callbacks != nil && g.callbacks.OnVehicleLocation != nil {
			go g.callbacks.OnVehicleLocation(userID, pkt.Plate, pkt.Color, &pos, gnssData)
		}
		if gnssData != nil {
			slog.Info("vehicle location", "user_id", userID, "plate", pkt.Plate, "lon", gnssData.Longitude, "lat", gnssData.Latitude)
		} else {
			slog.Info("vehicle location", "user_id", userID, "plate", pkt.Plate, "gnss_len", len(pos.GnssData))
		}
	case pkt.SubBusinessID == jtt809.SubMsgBatchLocation:
		if len(pkt.Payload) == 0 {
			return
		}
		count := int(pkt.Payload[0])
		reader := pkt.Payload[1:]
		parsed := 0
		for i := 0; i < count && len(reader) >= 5; i++ {
			gnssLen := int(binary.BigEndian.Uint32(reader[1:5]))
			totalLen := 1 + 4 + gnssLen + (11+4)*3
			if gnssLen < 0 || len(reader) < totalLen {
				break
			}
			pos, err := jtt809.ParseVehiclePosition(reader[:totalLen])
			if err != nil {
				slog.Warn("parse batch vehicle position failed", "user_id", userID, "index", i, "err", err)
				break
			}
			g.store.UpdateLocation(userID, pkt.Color, pkt.Plate, &pos, count)
			if gnss, err := jtt809.ParseGNSSData(pos.GnssData); err == nil {
				slog.Info("batch location item", "user_id", userID, "plate", pkt.Plate, "index", i, "lon", gnss.Longitude, "lat", gnss.Latitude)
			}
			reader = reader[totalLen:]
			parsed++
		}
		slog.Info("batch vehicle location", "user_id", userID, "plate", pkt.Plate, "count", parsed)

		// 触发批量定位回调
		if g.callbacks != nil && g.callbacks.OnBatchLocation != nil {
			go g.callbacks.OnBatchLocation(userID, pkt.Plate, pkt.Color, parsed)
		}
	case pkt.SubBusinessID == jtt809.SubMsgApplyForMonitorStartupAck:
		ack, err := jtt809.ParseMonitorAck(pkt.Payload)
		if err != nil {
			slog.Warn("parse monitor startup ack failed", "user_id", userID, "err", err, "payload_hex", fmt.Sprintf("%X", pkt.Payload))
			return
		}
		slog.Info("monitor startup ack received",
			"user_id", userID,
			"plate", pkt.Plate,
			"source_type", fmt.Sprintf("0x%04X", ack.SourceDataType),
			"source_sn", ack.SourceMsgSN,
			"data_length", ack.DataLength)

		// 触发启动车辆定位应答回调
		if g.callbacks != nil && g.callbacks.OnMonitorStartupAck != nil {
			go g.callbacks.OnMonitorStartupAck(userID, pkt.Plate, pkt.Color)
		}
	case pkt.SubBusinessID == jtt809.SubMsgApplyForMonitorEndAck:
		ack, err := jtt809.ParseMonitorAck(pkt.Payload)
		if err != nil {
			slog.Warn("parse monitor end ack failed", "user_id", userID, "err", err, "payload_hex", fmt.Sprintf("%X", pkt.Payload))
			return
		}
		// 收到应答表示下级平台已接收取消订阅请求
		slog.Info("monitor end ack received",
			"user_id", userID,
			"plate", pkt.Plate,
			"source_type", fmt.Sprintf("0x%04X", ack.SourceDataType),
			"source_sn", ack.SourceMsgSN)

		// 触发结束车辆定位应答回调
		if g.callbacks != nil && g.callbacks.OnMonitorEndAck != nil {
			go g.callbacks.OnMonitorEndAck(userID, pkt.Plate, pkt.Color)
		}
	default:
		slog.Debug("unhandled dynamic sub business", "user_id", userID, "sub_id", fmt.Sprintf("0x%04X", pkt.SubBusinessID))
	}
}

func (g *JT809Gateway) handlePlatformInfo(userID uint32, frame *jtt809.Frame) {
	pkt, err := jtt809.ParseSubBusiness(frame.RawBody)
	if err != nil {
		slog.Warn("parse platform info failed", "user_id", userID, "err", err)
		return
	}
	if pkt.SubBusinessID == jtt809.SubMsgPlatformQueryAck {
		ack, err := jtt809.ParsePlatformQueryAck(pkt)
		if err != nil {
			slog.Warn("parse platform query ack failed", "user_id", userID, "err", err)
			return
		}
		slog.Info("platform query ack", "user_id", userID, "object", ack.ObjectID, "info", ack.InfoContent)
		return
	}
	slog.Debug("unhandled platform info sub", "user_id", userID, "sub_id", fmt.Sprintf("0x%04X", pkt.SubBusinessID))
}

func (g *JT809Gateway) handleAlarmInteract(session *goserver.AppSession, frame *jtt809.Frame) {
	sessionID := ""
	if session != nil {
		sessionID = session.ID
	}
	slog.Debug("ignored alarm interact message", "session", sessionID, "msg_id", fmt.Sprintf("0x%04X", frame.BodyID))
}

func (g *JT809Gateway) handleDisconnectInform(session *goserver.AppSession, frame *jtt809.Frame) {
	disc, err := jtt809.ParseDisconnectInform(frame)
	if err != nil {
		slog.Warn("parse disconnect inform failed", "session", session.ID, "err", err)
		return
	}
	slog.Warn("platform disconnect notify", "session", session.ID, "code", disc.ErrorCode)
}

func (g *JT809Gateway) handleRealTimeVideo(userID uint32, frame *jtt809.Frame) {
	pkt, err := jtt809.ParseSubBusiness(frame.RawBody)
	if err != nil {
		slog.Warn("parse sub business failed", "user_id", userID, "err", err)
		return
	}
	if pkt.SubBusinessID == jtt809.SubMsgRealTimeVideoStartupAck {
		ack, err := jt1078.ParseRealTimeVideoStartupAck(pkt.Payload)
		if err != nil {
			slog.Warn("parse video ack failed", "user_id", userID, "err", err)
			return
		}
		g.store.RecordVideoAck(userID, pkt.Color, pkt.Plate, &VideoAckState{
			Result:     ack.Result,
			ServerIP:   ack.ServerIP,
			ServerPort: ack.ServerPort,
		})
		slog.Info("video stream ack", "user_id", userID, "plate", pkt.Plate, "server", ack.ServerIP, "port", ack.ServerPort, "result", ack.Result)

		// 触发视频应答回调
		if g.callbacks != nil && g.callbacks.OnVideoResponse != nil {
			go g.callbacks.OnVideoResponse(userID, pkt.Plate, pkt.Color, &VideoAckState{
				Result:     ack.Result,
				ServerIP:   ack.ServerIP,
				ServerPort: ack.ServerPort,
			})
		}
	}
}

func (g *JT809Gateway) handleSubDisconnect(userID uint32, frame *jtt809.Frame) {
	notify, err := jtt809.ParseDisconnectInform(frame)
	if err != nil {
		slog.Warn("parse main disconnect notify failed", "user_id", userID, "err", err)
		return
	}
	slog.Warn("main link disconnect notify", "user_id", userID, "code", notify.ErrorCode)
}

func isIPAllowed(ip string, allowIPs []string) bool {
	if len(allowIPs) == 0 {
		return true
	}
	for _, allow := range allowIPs {
		if allow == "*" {
			return true
		}
		if ip != "" && ip == allow {
			return true
		}
	}
	return false
}

func (g *JT809Gateway) getClientIP(session *goserver.AppSession) string {
	addr := session.RemoteAddr()
	host, _, err := net.SplitHostPort(addr.String())
	if err == nil {
		return host
	}
	return addr.String()
}

// SendToSubordinate 向下级平台发送消息（统一发送方法）
// 根据消息类型自动选择链路，支持降级
func (g *JT809Gateway) SendToSubordinate(userID uint32, header jtt809.Header, body jtt809.Body) error {
	msgID := body.MsgID()

	// 获取链路策略
	policy, ok := linkPolicies[msgID]
	if !ok {
		policy = defaultLinkPolicy
	}

	// 构造消息包
	pkg := jtt809.Package{
		Header: header.WithResponse(msgID),
		Body:   body,
	}
	data, err := jtt809.EncodePackage(pkg)
	if err != nil {
		return fmt.Errorf("encode package: %w", err)
	}

	// 获取链路状态
	mainActive, subActive := g.store.GetLinkStatus(userID)

	// 根据策略选择链路
	if policy.PreferredLink == "main" {
		// 首选主链路
		if mainActive {
			if err := g.sendOnMainLink(userID, data); err == nil {
				return nil
			}
			slog.Warn("send on main link failed", "user_id", userID, "msg_id", fmt.Sprintf("0x%04X", msgID), "err", err)
		}
		// 主链路不可用，尝试降级
		if policy.AllowFallback && subActive {
			slog.Info("main link unavailable, fallback to sub link", "user_id", userID, "msg_id", fmt.Sprintf("0x%04X", msgID))
			if err := g.sendOnSubLink(userID, data); err == nil {
				return nil
			}
		}
	} else {
		// 首选从链路
		if subActive {
			if err := g.sendOnSubLink(userID, data); err == nil {
				return nil
			}
			slog.Warn("send on sub link failed", "user_id", userID, "msg_id", fmt.Sprintf("0x%04X", msgID), "err", err)
		}
		// 从链路不可用，尝试降级
		if policy.AllowFallback && mainActive {
			slog.Info("sub link unavailable, fallback to main link", "user_id", userID, "msg_id", fmt.Sprintf("0x%04X", msgID))
			if err := g.sendOnMainLink(userID, data); err == nil {
				return nil
			}
		}
	}

	return fmt.Errorf("no available link for platform %d, msg_id=0x%04X", userID, msgID)
}

// sendOnMainLink 在主链路发送数据
func (g *JT809Gateway) sendOnMainLink(userID uint32, data []byte) error {
	sessionID, ok := g.store.GetMainSession(userID)
	if !ok {
		return fmt.Errorf("main session not found")
	}
	session, err := g.mainSrv.GetSessionByID(sessionID)
	if err != nil {
		return fmt.Errorf("get session failed: %w", err)
	}
	g.logPacket("main", "send", session.ID, data)
	return session.Send(data)
}

// sendOnSubLink 在从链路发送数据
func (g *JT809Gateway) sendOnSubLink(userID uint32, data []byte) error {
	subClient, ok := g.store.GetSubClient(userID)
	if !ok {
		return fmt.Errorf("sub client not found")
	}
	g.logPacket("sub", "send", fmt.Sprintf("%d", userID), data)
	return subClient.Send(data)
}

func (g *JT809Gateway) logPacket(link, dir, sessionID string, data []byte) {
	slog.Info("packet dump", "link", link, "dir", dir, "session", sessionID, "hex", fmt.Sprintf("%X", data))
}

func (g *JT809Gateway) sessionUser(session *goserver.AppSession) (uint32, bool) {
	val, err := session.GetAttr("userID")
	if err != nil {
		return 0, false
	}
	user, ok := val.(uint32)
	return user, ok
}

func (g *JT809Gateway) onSessionClosed(session *goserver.AppSession, reason string) {
	link, _ := session.GetAttr("link")
	slog.Info("session closed", "session", session.ID, "link", link, "reason", reason)
	g.store.RemoveSession(session.ID)
}

func splitJT809Frames(data []byte, atEOF bool) (advance int, token []byte, err error) {
	const (
		begin = byte(0x5b)
		end   = byte(0x5d)
	)
	start := bytes.IndexByte(data, begin)
	if start == -1 {
		if atEOF {
			return len(data), nil, nil
		}
		return 0, nil, nil
	}
	if start > 0 {
		return start, nil, nil
	}
	stop := bytes.IndexByte(data[1:], end)
	if stop == -1 {
		if atEOF {
			return len(data), nil, fmt.Errorf("dangling frame")
		}
		return 0, nil, nil
	}
	stop++ // compensate slicing offset
	return stop + 1, data[:stop+1], nil
}

func (g *JT809Gateway) handleAuthorize(userID uint32, frame *jtt809.Frame) {
	// 0x1700 消息体结构：子业务ID(2字节) + 载荷
	// 注意：不包含车牌号和颜色，与 0x1200 的 SubBusinessPacket 格式不同
	msg, err := jt1078.ParseAuthorizeMsg(frame.RawBody)
	if err != nil {
		slog.Warn("parse authorize msg failed", "user_id", userID, "err", err)
		return
	}
	switch msg.SubBusinessID {
	case jtt809.SubMsgAuthorizeStartupReq: // 0x1701
		req, err := jt1078.ParseAuthorizeStartupReq(msg.Payload)
		if err != nil {
			slog.Warn("parse authorize startup req failed", "user_id", userID, "err", err)
			return
		}
		authCode := req.AuthorizeCode1
		// 注意：0x1700 消息中没有车牌号和颜色信息，时效口令是平台级别的
		g.store.UpdateAuthCode(userID, req.PlatformID, authCode)
		slog.Info("video authorize report", "user_id", userID, "platform", req.PlatformID, "auth_code", authCode)

		// 触发鉴权回调
		if g.callbacks != nil && g.callbacks.OnAuthorize != nil {
			go g.callbacks.OnAuthorize(userID, req.PlatformID, authCode)
		}

	default:
		slog.Debug("unhandled authorize sub msg", "user_id", userID, "sub_id", fmt.Sprintf("0x%04X", msg.SubBusinessID))
	}
}

// autoSubscribeVehicle 在车辆注册后自动订阅该车辆的实时定位数据
func (g *JT809Gateway) autoSubscribeVehicle(userID uint32, color jtt809.PlateColor, vehicle string) {
	// 等待一小段时间，确保从链路已建立
	time.Sleep(2 * time.Second)

	req := MonitorRequest{
		UserID:       userID,
		VehicleNo:    vehicle,
		VehicleColor: color,
		ReasonCode:   byte(jtt809.MonitorReasonManual),
	}

	if err := g.RequestMonitorStartup(req); err != nil {
		slog.Warn("auto subscribe vehicle failed", "user_id", userID, "plate", vehicle, "err", err)
		return
	}

	slog.Info("auto subscribed vehicle", "user_id", userID, "plate", vehicle)
}

// checkVehiclePositions 检查所有车辆的定位状态，处理超时和离线车辆
func (g *JT809Gateway) checkVehiclePositions() {
	snapshots := g.store.Snapshots()
	now := time.Now()

	for _, snap := range snapshots {
		if snap.MainSessionID == "" || !snap.SubConnected {
			continue
		}

		for _, vehicle := range snap.Vehicles {
			vehicleKey := vehicleKey(vehicle.VehicleNo, vehicle.VehicleColor)

			// 处理已注册但还未订阅或订阅失败的车辆
			if vehicle.PositionTime.IsZero() {
				// 如果有注册信息，说明车辆已注册，尝试订阅
				if vehicle.Registration != nil {
					// 先判断注册时间是否超过10分钟，超过则删除
					if now.Sub(vehicle.Registration.ReceivedAt) > 10*time.Minute {
						g.store.RemoveVehicle(snap.UserID, vehicleKey)
						slog.Warn("vehicle registration expired, removed",
							"user_id", snap.UserID,
							"plate", vehicle.VehicleNo,
							"registration_time", vehicle.Registration.ReceivedAt.Format("2006-01-02 15:04:05"))
						continue
					}

					req := MonitorRequest{
						UserID:       snap.UserID,
						VehicleNo:    vehicle.VehicleNo,
						VehicleColor: vehicle.VehicleColor,
						ReasonCode:   byte(jtt809.MonitorReasonManual),
					}

					if err := g.RequestMonitorStartup(req); err != nil {
						slog.Warn("subscribe registered vehicle failed",
							"user_id", snap.UserID,
							"plate", vehicle.VehicleNo,
							"err", err)
						continue
					}

					slog.Info("subscribed registered vehicle",
						"user_id", snap.UserID,
						"plate", vehicle.VehicleNo)
				}
				continue
			}

			timeSinceLastPosition := now.Sub(vehicle.PositionTime)

			// 超过10分钟未上报定位，认定为离线，删除车辆
			if timeSinceLastPosition > 10*time.Minute {
				g.store.RemoveVehicle(snap.UserID, vehicleKey)
				slog.Warn("vehicle offline, removed",
					"user_id", snap.UserID,
					"plate", vehicle.VehicleNo,
					"last_position", vehicle.PositionTime.Format("2006-01-02 15:04:05"),
					"offline_duration", timeSinceLastPosition.String())
				continue
			}

			// 超过5分钟未上报定位，重新发送订阅请求
			if timeSinceLastPosition > 5*time.Minute {
				req := MonitorRequest{
					UserID:       snap.UserID,
					VehicleNo:    vehicle.VehicleNo,
					VehicleColor: vehicle.VehicleColor,
					ReasonCode:   byte(jtt809.MonitorReasonManual),
				}

				if err := g.RequestMonitorStartup(req); err != nil {
					slog.Warn("resubscribe vehicle failed",
						"user_id", snap.UserID,
						"plate", vehicle.VehicleNo,
						"err", err)
					continue
				}

				slog.Info("resubscribed vehicle due to position timeout",
					"user_id", snap.UserID,
					"plate", vehicle.VehicleNo,
					"last_position", vehicle.PositionTime.Format("2006-01-02 15:04:05"),
					"timeout_duration", timeSinceLastPosition.String())
			}
		}
	}
}

// SendDownlinkMessage 发送下行消息（主动下发）
// 使用统一的发送方法，根据消息类型自动选择链路并支持降级
func (g *JT809Gateway) SendDownlinkMessage(userID uint32, body jtt809.Body) error {
	snap, ok := g.store.Snapshot(userID)
	if !ok || snap.MainSessionID == "" {
		return fmt.Errorf("platform %d not online", userID)
	}

	header := jtt809.Header{
		GNSSCenterID: snap.GNSSCenterID,
		Version:      jtt809.Version{Major: 1, Minor: 0, Patch: 0},
		EncryptFlag:  0,
		EncryptKey:   0,
		BusinessType: body.MsgID(),
	}

	return g.SendToSubordinate(userID, header, body)
}
