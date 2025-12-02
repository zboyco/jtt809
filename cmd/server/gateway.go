package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	goserver "github.com/zboyco/go-server"
	"github.com/zboyco/go-server/client"
	"github.com/zboyco/jtt809/pkg/jtt809"
	"github.com/zboyco/jtt809/pkg/jtt809/jt1078"
)

// JT809Gateway 负责承载主/从链路 TCP 服务与业务处理。
type JT809Gateway struct {
	cfg   Config
	auth  *Authenticator
	store *PlatformStore

	mainSrv *goserver.Server
	httpSrv *http.Server

	startOnce sync.Once
}

func NewJT809Gateway(cfg Config) (*JT809Gateway, error) {
	if len(cfg.Accounts) == 0 {
		return nil, errors.New("at least one account is required")
	}
	return &JT809Gateway{
		cfg:   cfg,
		auth:  NewAuthenticator(cfg.Accounts),
		store: NewPlatformStore(),
	}, nil
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
	switch frame.BodyID {
	case jtt809.MsgIDLoginRequest:
		return g.handleMainLogin(session, frame)
	case jtt809.MsgIDHeartbeatRequest:
		return g.handleHeartbeat(session, frame, true)
	case jtt809.MsgIDLogoutRequest:
		return g.simpleResponse(session, "main", frame, jtt809.LogoutResponse{})
	case jtt809.MsgIDDynamicInfo:
		g.handleDynamicInfo(session, frame)
	case jtt809.MsgIDPlatformInfo:
		g.handlePlatformInfo(session, frame)
	case jtt809.MsgIDAlarmInteract:
		g.handleAlarmInteract(session, frame)
	case jtt809.MsgIDDisconnNotify:
		g.handleDisconnectInform(session, frame)
	case jtt809.MsgIDRealTimeVideo:
		g.handleRealTimeVideo(session, frame)
	case jtt809.MsgIDAuthorize:
		g.handleAuthorize(session, frame)
	default:
		slog.Debug("unhandled main message", "session", session.ID, "msg_id", fmt.Sprintf("0x%04X", frame.BodyID))
	}
	return nil, nil
}

// handleSubMessage 处理从链路报文（Active Mode）。
func (g *JT809Gateway) handleSubMessage(userID uint32, payload []byte) {
	g.logPacket("sub", "recv", fmt.Sprintf("%d", userID), payload)
	frame, err := jtt809.DecodeFrame(payload)
	if err != nil {
		slog.Warn("decode sub frame failed", "user_id", userID, "err", err)
		return
	}
	switch frame.BodyID {
	case jtt809.MsgIDDownlinkConnReq:
		// Active mode: we send this, we don't receive it (unless echo? no)
	case 0x9002: // Login Response
		// Handled in connectSubLink
	case 0x9006: // Heartbeat Response
		// Just log or update heartbeat time
		g.store.RecordHeartbeat(userID, false)
	case 0x9007: // Disconnect Notify
		// Server disconnected us?
		slog.Warn("sub link disconnect notify", "user_id", userID)
	default:
		slog.Debug("unhandled sub message", "user_id", userID, "msg_id", fmt.Sprintf("0x%04X", frame.BodyID))
	}
}

func (g *JT809Gateway) handleMainLogin(session *goserver.AppSession, frame *jtt809.Frame) ([]byte, error) {
	req, err := jtt809.ParseLoginRequest(frame.RawBody)
	if err != nil {
		slog.Warn("parse main login failed", "session", session.ID, "err", err)
		return nil, nil
	}
	acc, resp := g.auth.Authenticate(req)
	slog.Info("main login request", "session", session.ID, "user_id", req.UserID, "gnss", frame.Header.GNSSCenterID, "result", resp.Result)
	if resp.Result == jtt809.LoginOK {
		session.SetAttr("userID", req.UserID)
		session.SetAttr("link", "main")
		g.store.BindMainSession(session.ID, req, acc.Password)
		if _, err := session.GetAttr("verifyCode"); err != nil {
			session.SetAttr("verifyCode", acc.VerifyCode)
		}
		// Start Sub Link Connection
		go g.connectSubLinkWithRetry(req.DownLinkIP, req.DownLinkPort, req.UserID, acc.Password)
	}
	return g.simpleResponse(session, "main", frame, resp)
}

func (g *JT809Gateway) connectSubLinkWithRetry(ip string, port uint16, userID uint32, password string) {
	// 设置重连标志，如果已经在重连则直接返回
	if !g.store.SetReconnecting(userID, true) {
		slog.Info("sub link already reconnecting, skip", "user_id", userID)
		return
	}
	defer g.store.SetReconnecting(userID, false)

	for {
		// 检查主链路是否仍然活跃
		snap, ok := g.store.Snapshot(userID)
		if !ok || snap.MainSessionID == "" {
			slog.Info("main link not active, stop reconnecting", "user_id", userID)
			return
		}

		if g.connectSubLink(ip, port, userID, password) {
			return
		}
		time.Sleep(30 * time.Second)
		slog.Info("retrying sub link connection", "user_id", userID)
	}
}

func (g *JT809Gateway) connectSubLink(ip string, port uint16, userID uint32, password string) bool {
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
	req := jtt809.SubLinkLoginRequest{UserID: userID, Password: password}
	pkg, _ := jtt809.BuildSubLinkLoginPackage(jtt809.Header{
		MsgLength:    0, // auto
		MsgSN:        1,
		BusinessType: jtt809.MsgIDDownlinkConnReq,
		GNSSCenterID: 0, // TODO: correct GNSS ID
		Version:      jtt809.Version{Major: 1, Minor: 0, Patch: 0},
		EncryptFlag:  0,
		EncryptKey:   0,
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

	g.store.BindSubSession(userID, c)

	go g.readSubLinkLoop(c, userID, true)
	go g.keepAliveSubLink(c, userID)
	return true
}

func (g *JT809Gateway) readSubLinkLoop(c *client.SimpleClient, userID uint32, shouldReconnect bool) {
	defer func() {
		c.Close()
		g.store.ClearSubConn(userID)
		slog.Info("sub link closed", "user_id", userID)
		// 仅在需要重连时触发
		if shouldReconnect {
			go g.reconnectSubLink(userID)
		}
	}()
	for {
		data, err := c.Receive()
		if err != nil {
			slog.Error("sub link read error", "user_id", userID, "err", err)
			return
		}
		g.handleSubMessage(userID, data)
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
	g.connectSubLinkWithRetry(snap.DownLinkIP, snap.DownLinkPort, userID, snap.Password)
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
	for _, snap := range snapshots {
		if snap.MainSessionID == "" {
			continue
		}
		// 检查从链路是否需要重连
		if !snap.SubConnected && snap.DownLinkIP != "" && snap.DownLinkPort > 0 {
			slog.Warn("sub link disconnected, triggering reconnect", "user_id", snap.UserID)
			go g.connectSubLinkWithRetry(snap.DownLinkIP, snap.DownLinkPort, snap.UserID, snap.Password)
		}
	}
}

func (g *JT809Gateway) keepAliveSubLink(c *client.SimpleClient, userID uint32) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		hb, _ := jtt809.BuildSubLinkHeartbeat(jtt809.Header{
			MsgSN:   0, // TODO: maintain SN
			Version: jtt809.Version{Major: 1, Minor: 2, Patch: 19},
			WithUTC: true,
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

func (g *JT809Gateway) handleHeartbeat(session *goserver.AppSession, frame *jtt809.Frame, isMain bool) ([]byte, error) {
	if user, ok := g.sessionUser(session); ok {
		g.store.RecordHeartbeat(user, isMain)
		if isMain {
			slog.Info("main link heartbeat", "session", session.ID, "user_id", user)
		} else {
			slog.Info("sub link heartbeat", "session", session.ID, "user_id", user)
		}
	}
	if isMain {
		return g.simpleResponse(session, "main", frame, jtt809.HeartbeatResponse{})
	}
	return g.simpleResponse(session, "sub", frame, jtt809.SubLinkHeartbeatResponse{})
}

func (g *JT809Gateway) handleDynamicInfo(session *goserver.AppSession, frame *jtt809.Frame) {
	user, ok := g.sessionUser(session)
	if !ok {
		slog.Warn("dynamic info before login", "session", session.ID)
		return
	}
	pkt, err := jtt809.ParseSubBusiness(frame.RawBody)
	if err != nil {
		slog.Warn("parse sub business failed", "session", session.ID, "err", err)
		return
	}
	switch {
	case pkt.SubBusinessID == jtt809.SubMsgUploadVehicleReg:
		reg, err := parseVehicleRegistration(pkt.Payload)
		if err != nil {
			slog.Warn("parse vehicle registration failed", "session", session.ID, "err", err)
			return
		}
		g.store.UpdateVehicleRegistration(user, pkt.Color, pkt.Plate, reg)
		slog.Info("vehicle registration", "user_id", user, "plate", pkt.Plate, "platform", reg.PlatformID)
	case pkt.SubBusinessID == jtt809.SubMsgRealLocation:
		pos, err := jtt809.ParseVehiclePosition2019(pkt.Payload)
		if err != nil {
			slog.Warn("parse vehicle position 2019 failed", "session", session.ID, "err", err)
			return
		}
		g.store.UpdateLocation(user, pkt.Color, pkt.Plate, &pos, 0)
		if lon, lat, ok := extractLonLat(pos.GnssData); ok {
			slog.Info("vehicle location", "user_id", user, "plate", pkt.Plate, "lon", lon, "lat", lat)
		} else {
			slog.Info("vehicle location", "user_id", user, "plate", pkt.Plate, "gnss_len", len(pos.GnssData))
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
			pos, err := jtt809.ParseVehiclePosition2019(reader[:totalLen])
			if err != nil {
				slog.Warn("parse batch vehicle position 2019 failed", "session", session.ID, "index", i, "err", err)
				break
			}
			g.store.UpdateLocation(user, pkt.Color, pkt.Plate, &pos, count)
			if lon, lat, ok := extractLonLat(pos.GnssData); ok {
				slog.Info("batch location item", "user_id", user, "plate", pkt.Plate, "index", i, "lon", lon, "lat", lat)
			}
			reader = reader[totalLen:]
			parsed++
		}
		slog.Info("batch vehicle location (2019)", "user_id", user, "plate", pkt.Plate, "count", parsed)
	// 注意：0x1701 (时效口令上报) 应该通过 0x1700 (视频鉴权) 主业务类型传输，
	// 而不是通过 0x1200 (动态信息)。根据 JT/T 809 标准，视频相关消息应使用专门的 0x1700。
	// 如果收到 0x1200 中的 0x1701，记录警告但不处理。
	case pkt.SubBusinessID == jtt809.SubMsgAuthorizeStartupReq:
		slog.Warn("received 0x1701 in 0x1200, should use 0x1700 instead", "user_id", user, "plate", pkt.Plate)
	case pkt.SubBusinessID == jtt809.SubMsgRealTimeVideoStartupAck:
		ack, err := jt1078.ParseRealTimeVideoStartupAck(pkt.Payload)
		if err != nil {
			slog.Warn("parse video ack failed", "session", session.ID, "err", err)
			return
		}
		g.store.RecordVideoAck(user, pkt.Color, pkt.Plate, &VideoAckState{
			Result:     ack.Result,
			ServerIP:   ack.ServerIP,
			ServerPort: ack.ServerPort,
		})
		slog.Info("video stream ack", "user_id", user, "plate", pkt.Plate, "server", ack.ServerIP, "port", ack.ServerPort, "result", ack.Result)
	case pkt.SubBusinessID == jtt809.SubMsgApplyForMonitorStartupAck:
		result, err := jtt809.ParseMonitorAck(pkt.Payload)
		if err != nil {
			slog.Warn("parse monitor startup ack failed", "session", session.ID, "err", err)
			return
		}
		g.store.UpdateMonitorStatus(user, pkt.Color, pkt.Plate, result == jtt809.MonitorAckSuccess)
		slog.Info("monitor startup ack", "user_id", user, "plate", pkt.Plate, "result", result)
	case pkt.SubBusinessID == jtt809.SubMsgApplyForMonitorEndAck:
		result, err := jtt809.ParseMonitorAck(pkt.Payload)
		if err != nil {
			slog.Warn("parse monitor end ack failed", "session", session.ID, "err", err)
			return
		}
		if result == jtt809.MonitorAckSuccess {
			g.store.UpdateMonitorStatus(user, pkt.Color, pkt.Plate, false)
		}
		slog.Info("monitor end ack", "user_id", user, "plate", pkt.Plate, "result", result)
	default:
		slog.Debug("unhandled dynamic sub business", "user_id", user, "sub_id", fmt.Sprintf("0x%04X", pkt.SubBusinessID))
	}
}

func (g *JT809Gateway) handlePlatformInfo(session *goserver.AppSession, frame *jtt809.Frame) {
	pkt, err := jtt809.ParseSubBusiness(frame.RawBody)
	if err != nil {
		slog.Warn("parse platform info failed", "session", session.ID, "err", err)
		return
	}
	if pkt.SubBusinessID == jtt809.SubMsgPlatformQueryAck {
		ack, err := jtt809.ParsePlatformQueryAck(pkt)
		if err != nil {
			slog.Warn("parse platform query ack failed", "err", err)
			return
		}
		slog.Info("platform query ack", "object", ack.ObjectID, "info", ack.InfoContent)
		return
	}
	slog.Debug("unhandled platform info sub", "sub_id", fmt.Sprintf("0x%04X", pkt.SubBusinessID))
}

func (g *JT809Gateway) handleAlarmInteract(session *goserver.AppSession, frame *jtt809.Frame) {
	// 忽略主链路 0x1400 上报的报警数据，不用解析
	slog.Debug("ignored alarm interact message", "session", session.ID, "msg_id", fmt.Sprintf("0x%04X", frame.BodyID))
}

func (g *JT809Gateway) handleDisconnectInform(session *goserver.AppSession, frame *jtt809.Frame) {
	disc, err := jtt809.ParseDisconnectInform(frame)
	if err != nil {
		slog.Warn("parse disconnect inform failed", "session", session.ID, "err", err)
		return
	}
	slog.Warn("platform disconnect notify", "session", session.ID, "code", disc.ErrorCode)
}

func (g *JT809Gateway) handleRealTimeVideo(session *goserver.AppSession, frame *jtt809.Frame) {
	user, ok := g.sessionUser(session)
	if !ok {
		slog.Warn("real time video before login", "session", session.ID)
		return
	}
	pkt, err := jtt809.ParseSubBusiness(frame.RawBody)
	if err != nil {
		slog.Warn("parse sub business failed", "session", session.ID, "err", err)
		return
	}
	if pkt.SubBusinessID == jtt809.SubMsgRealTimeVideoStartupAck {
		ack, err := jt1078.ParseRealTimeVideoStartupAck(pkt.Payload)
		if err != nil {
			slog.Warn("parse video ack failed", "session", session.ID, "err", err)
			return
		}
		g.store.RecordVideoAck(user, pkt.Color, pkt.Plate, &VideoAckState{
			Result:     ack.Result,
			ServerIP:   ack.ServerIP,
			ServerPort: ack.ServerPort,
		})
		slog.Info("video stream ack", "user_id", user, "plate", pkt.Plate, "server", ack.ServerIP, "port", ack.ServerPort, "result", ack.Result)
	}
}

func (g *JT809Gateway) handleSubDisconnect(session *goserver.AppSession, frame *jtt809.Frame) {
	notify, err := jtt809.ParseSubLinkDisconnectNotify(frame)
	if err != nil {
		slog.Warn("parse sub disconnect notify failed", "session", session.ID, "err", err)
		return
	}
	slog.Warn("sub link disconnect", "session", session.ID, "reason", notify.ReasonCode)
}

func (g *JT809Gateway) simpleResponse(session *goserver.AppSession, link string, frame *jtt809.Frame, body jtt809.Body) ([]byte, error) {
	pkg := jtt809.Package{
		Header: frame.Header.WithResponse(body.MsgID()),
		Body:   body,
	}
	data, err := jtt809.EncodePackage(pkg)
	if err == nil {
		g.logPacket(link, "send", session.ID, data)
	}
	return data, err
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
	frame := make([]byte, stop+1)
	copy(frame, data[:stop+1])
	return stop + 1, frame, nil
}

func extractLonLat(gnss []byte) (float64, float64, bool) {
	if len(gnss) < 36 {
		return 0, 0, false
	}
	lon := float64(binary.BigEndian.Uint32(gnss[8:12])) / 1e6
	lat := float64(binary.BigEndian.Uint32(gnss[12:16])) / 1e6
	return lon, lat, true
}

// parseVehicleRegistration 解码 0x1201 注册载荷（2019版固定长度）。
func parseVehicleRegistration(payload []byte) (*VehicleRegistration, error) {
	const (
		lenPlatform = 11
		lenProducer = 11
		lenModel    = 30
		lenIMEI     = 15
		lenTermID   = 30
		lenSIM      = 13
	)
	total := lenPlatform + lenProducer + lenModel + lenIMEI + lenTermID + lenSIM
	if len(payload) < total {
		return nil, fmt.Errorf("registration payload too short: %d (expected %d)", len(payload), total)
	}
	offset := 0
	read := func(length int) []byte {
		v := payload[offset : offset+length]
		offset += length
		return v
	}
	platform, _ := jtt809.DecodeGBK(read(lenPlatform))
	producer, _ := jtt809.DecodeGBK(read(lenProducer))
	model, _ := jtt809.DecodeGBK(read(lenModel))
	imei, _ := jtt809.DecodeGBK(read(lenIMEI))
	terminalID, _ := jtt809.DecodeGBK(read(lenTermID))
	sim, _ := jtt809.DecodeGBK(read(lenSIM))
	return &VehicleRegistration{
		PlatformID:        platform,
		ProducerID:        producer,
		TerminalModelType: model,
		IMEI:              imei,
		TerminalID:        terminalID,
		TerminalSIM:       sim,
	}, nil
}

func (g *JT809Gateway) handleAuthorize(session *goserver.AppSession, frame *jtt809.Frame) {
	user, ok := g.sessionUser(session)
	if !ok {
		slog.Warn("authorize msg before login", "session", session.ID)
		return
	}
	// 0x1700 消息体结构：子业务ID(2字节) + 载荷
	// 注意：不包含车牌号和颜色，与 0x1200 的 SubBusinessPacket 格式不同
	msg, err := jt1078.ParseAuthorizeMsg(frame.RawBody)
	if err != nil {
		slog.Warn("parse authorize msg failed", "session", session.ID, "err", err)
		return
	}
	switch msg.SubBusinessID {
	case jtt809.SubMsgAuthorizeStartupReq: // 0x1701
		req, err := jt1078.ParseAuthorizeStartupReq(msg.Payload)
		if err != nil {
			slog.Warn("parse authorize startup req failed", "session", session.ID, "err", err)
			return
		}
		authCode := req.AuthorizeCode1
		// 注意：0x1700 消息中没有车牌号和颜色信息，时效口令是平台级别的
		g.store.UpdateAuthCode(user, req.PlatformID, authCode)
		slog.Info("video authorize report (0x1701)", "user_id", user, "platform", req.PlatformID, "auth_code", authCode)

	case jtt809.SubMsgAuthorizeStartupReqMsg: // 0x1702
		slog.Info("video authorize request (0x1702)", "user_id", user)

		downMsg := jt1078.DownAuthorizeMsg{
			SubBusinessID: jtt809.SubMsgAuthorizeStartupReqAck, // 0x9702
			Payload:       []byte{},
		}

		encodedBody, err := downMsg.Encode()
		if err != nil {
			slog.Error("encode down authorize msg failed", "err", err)
			return
		}

		respPkg := jtt809.Package{
			Header: frame.Header.WithResponse(jtt809.MsgIDDownAuthorize), // 0x9700
			Body: rawBody{
				msgID:   jtt809.MsgIDDownAuthorize,
				payload: encodedBody,
			},
		}

		data, err := jtt809.EncodePackage(respPkg)
		if err != nil {
			slog.Error("encode package failed", "err", err)
			return
		}

		if err := session.Send(data); err != nil {
			slog.Error("send authorize ack failed", "err", err)
		}
		slog.Info("sent authorize ack (0x9702)", "user_id", user)

	default:
		slog.Debug("unhandled authorize sub msg", "sub_id", fmt.Sprintf("0x%04X", msg.SubBusinessID))
	}
}
