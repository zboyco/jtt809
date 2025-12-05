package server

import (
	"fmt"
	"sync"
	"time"

	"github.com/zboyco/go-server/client"
	"github.com/zboyco/jtt809/pkg/jtt809"
)

// PlatformStore 维护下级平台与车辆状态。
type PlatformStore struct {
	mu           sync.RWMutex
	platforms    map[uint32]*PlatformState
	sessionIndex map[string]uint32
}

// PlatformState 表示单个下级平台的会话信息与车辆缓存。
type PlatformState struct {
	UserID        uint32
	GNSSCenterID  uint32
	DownLinkIP    string
	DownLinkPort  uint16
	MainSessionID string
	SubClient     *client.SimpleClient
	VerifyCode    uint32 // 用于从链路重连
	Reconnecting  bool   // 是否正在重连，防止重复重连

	LastMainHeartbeat time.Time
	LastSubHeartbeat  time.Time

	// 视频鉴权相关（平台级别，不与具体车辆关联）
	PlatformID string // 平台唯一编码
	AuthCode   string // 时效口令

	Vehicles map[string]*VehicleState
}

// VehicleState 保存车辆注册信息、最新定位与最后一次视频应答。
type VehicleState struct {
	Number string
	Color  byte

	Registration *VehicleRegistration

	Position     *jtt809.VehiclePosition
	PositionTime time.Time
	BatchCount   int

	LastVideoAck *VideoAckState
}

// VehicleRegistration 描述车辆注册上报内容。
type VehicleRegistration struct {
	PlatformID        string
	ProducerID        string
	TerminalModelType string
	IMEI              string
	TerminalID        string
	TerminalSIM       string
	ReceivedAt        time.Time
}

// VideoAckState 表示下级平台返回的视频流地址信息。
type VideoAckState struct {
	Result     byte
	ServerIP   string
	ServerPort uint16
	ReceivedAt time.Time
}

// PlatformSnapshot 用于对外展示平台及车辆状态。
type PlatformSnapshot struct {
	UserID        uint32            `json:"user_id"`
	GNSSCenterID  uint32            `json:"gnss_center_id"`
	DownLinkIP    string            `json:"down_link_ip"`
	DownLinkPort  uint16            `json:"down_link_port"`
	MainSessionID string            `json:"main_session_id"`
	SubConnected  bool              `json:"sub_connected"`
	VerifyCode    uint32            `json:"-"` // 不对外暴露
	LastMainBeat  time.Time         `json:"last_main_heartbeat"`
	LastSubBeat   time.Time         `json:"last_sub_heartbeat"`
	PlatformID    string            `json:"platform_id,omitempty"` // 平台唯一编码
	AuthCode      string            `json:"auth_code,omitempty"`   // 时效口令
	Vehicles      []VehicleSnapshot `json:"vehicles"`
}

// VehicleSnapshot 为单车数据提供可序列化视图。
type VehicleSnapshot struct {
	VehicleNo    string                  `json:"vehicle_no"`
	VehicleColor byte                    `json:"vehicle_color"`
	Registration *VehicleRegistration    `json:"registration,omitempty"`
	Position     *jtt809.VehiclePosition `json:"location,omitempty"`
	PositionTime time.Time               `json:"location_time,omitempty"`
	Longitude    float64                 `json:"longitude,omitempty"`
	Latitude     float64                 `json:"latitude,omitempty"`
	BatchCount   int                     `json:"batch_count,omitempty"`
	LastVideoAck *VideoAckState          `json:"video_ack,omitempty"`
}

// NewPlatformStore 初始化状态存储。
func NewPlatformStore() *PlatformStore {
	return &PlatformStore{
		platforms:    make(map[uint32]*PlatformState),
		sessionIndex: make(map[string]uint32),
	}
}

// BindMainSession 在主链路登录成功后建立会话映射。
func (s *PlatformStore) BindMainSession(sessionID string, req jtt809.LoginRequest, gnssCenterID uint32, verifyCode uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.ensurePlatformLocked(req.UserID)
	state.GNSSCenterID = gnssCenterID
	state.DownLinkIP = req.DownLinkIP
	state.DownLinkPort = req.DownLinkPort
	state.MainSessionID = sessionID
	state.VerifyCode = verifyCode
	state.LastMainHeartbeat = time.Now()
	s.sessionIndex[sessionID] = req.UserID
}

// BindSubSession 记录从链路连接。
func (s *PlatformStore) BindSubSession(userID uint32, c *client.SimpleClient) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.ensurePlatformLocked(userID)
	if state.SubClient != nil {
		state.SubClient.Close()
	}
	state.SubClient = c
	state.LastSubHeartbeat = time.Now()
}

// RecordHeartbeat 更新心跳时间。
func (s *PlatformStore) RecordHeartbeat(userID uint32, isMain bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.ensurePlatformLocked(userID)
	if isMain {
		state.LastMainHeartbeat = time.Now()
	} else {
		state.LastSubHeartbeat = time.Now()
	}
}

// RemoveSession 在连接关闭时清理索引。
func (s *PlatformStore) RemoveSession(sessionID string) {
	s.mu.Lock()
	userID, ok := s.sessionIndex[sessionID]
	if !ok {
		s.mu.Unlock()
		return
	}
	state := s.platforms[userID]
	if state == nil {
		delete(s.sessionIndex, sessionID)
		s.mu.Unlock()
		return
	}
	var clientToClose *client.SimpleClient
	if state.MainSessionID == sessionID {
		state.MainSessionID = ""
		// 保存连接引用，在锁外关闭以避免死锁
		// 主链路断开时，从链路不需要重连
		clientToClose = state.SubClient
		state.SubClient = nil
	}
	delete(s.sessionIndex, sessionID)
	s.mu.Unlock()

	// 在锁外关闭连接，避免与readSubLinkLoop的defer中的ClearSubConn死锁
	if clientToClose != nil {
		clientToClose.Close()
	}
}

// UpdateVehicleRegistration 存储车辆注册信息。
func (s *PlatformStore) UpdateVehicleRegistration(userID uint32, color byte, vehicle string, reg *VehicleRegistration) {
	if reg == nil {
		return
	}
	reg.ReceivedAt = time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.ensurePlatformLocked(userID)
	v := state.ensureVehicleLocked(vehicleKey(vehicle, color), vehicle, color)
	v.Registration = reg
}

// UpdateLocation 写入最新定位数据。
func (s *PlatformStore) UpdateLocation(userID uint32, color byte, vehicle string, pos *jtt809.VehiclePosition, batchCount int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.ensurePlatformLocked(userID)
	v := state.ensureVehicleLocked(vehicleKey(vehicle, color), vehicle, color)
	if pos != nil {
		cp := *pos
		v.Position = &cp
		v.PositionTime = time.Now()
	}
	if batchCount > 0 {
		v.BatchCount = batchCount
	}
}

// RecordVideoAck 缓存最新视频流地址。
func (s *PlatformStore) RecordVideoAck(userID uint32, color byte, vehicle string, ack *VideoAckState) {
	if ack == nil {
		return
	}
	ack.ReceivedAt = time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.ensurePlatformLocked(userID)
	v := state.ensureVehicleLocked(vehicleKey(vehicle, color), vehicle, color)
	v.LastVideoAck = ack
}

// UpdateAuthCode 存储平台的时效口令
// 注意：根据 JT/T 809-2019 标准，0x1700 消息中的时效口令是平台级别的，
// 不与具体车辆关联，因此存储在 PlatformState 中。
func (s *PlatformStore) UpdateAuthCode(userID uint32, platformID string, authCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.ensurePlatformLocked(userID)
	state.PlatformID = platformID
	state.AuthCode = authCode
}

// GetAuthCode 获取平台的时效口令
func (s *PlatformStore) GetAuthCode(userID uint32) (platformID string, authCode string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.platforms[userID]
	if !ok {
		return "", ""
	}
	return state.PlatformID, state.AuthCode
}

// Snapshot 返回指定 userID 的深拷贝视图。
func (s *PlatformStore) Snapshot(userID uint32) (PlatformSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state, ok := s.platforms[userID]
	if !ok {
		return PlatformSnapshot{}, false
	}
	return state.snapshotLocked(), true
}

// Snapshots 列出所有平台状态。
func (s *PlatformStore) Snapshots() []PlatformSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]PlatformSnapshot, 0, len(s.platforms))
	for _, st := range s.platforms {
		result = append(result, st.snapshotLocked())
	}
	return result
}

// PlatformForSession 返回 sessionID 对应的平台 ID。
func (s *PlatformStore) PlatformForSession(sessionID string) (uint32, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.sessionIndex[sessionID]
	return user, ok
}

// ClearSubConn 清理从链路连接状态
func (s *PlatformStore) ClearSubConn(userID uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state, ok := s.platforms[userID]; ok {
		state.SubClient = nil
	}
}

// SetReconnecting 设置重连标志
func (s *PlatformStore) SetReconnecting(userID uint32, reconnecting bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.platforms[userID]
	if !ok {
		return false
	}
	// 如果已经在重连，返回false表示不应该启动新的重连
	if reconnecting && state.Reconnecting {
		return false
	}
	state.Reconnecting = reconnecting
	return true
}

func (s *PlatformStore) ensurePlatformLocked(userID uint32) *PlatformState {
	state, ok := s.platforms[userID]
	if ok {
		return state
	}
	state = &PlatformState{
		UserID:   userID,
		Vehicles: make(map[string]*VehicleState),
	}
	s.platforms[userID] = state
	return state
}

func (state *PlatformState) ensureVehicleLocked(key string, number string, color byte) *VehicleState {
	v, ok := state.Vehicles[key]
	if ok {
		return v
	}
	v = &VehicleState{
		Number: number,
		Color:  color,
	}
	state.Vehicles[key] = v
	return v
}

// RemoveVehicle 删除指定车辆
func (s *PlatformStore) RemoveVehicle(userID uint32, vehicleKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.platforms[userID]
	if !ok {
		return
	}
	delete(state.Vehicles, vehicleKey)
}

func (state *PlatformState) snapshotLocked() PlatformSnapshot {
	snap := PlatformSnapshot{
		UserID:        state.UserID,
		GNSSCenterID:  state.GNSSCenterID,
		DownLinkIP:    state.DownLinkIP,
		DownLinkPort:  state.DownLinkPort,
		MainSessionID: state.MainSessionID,
		SubConnected:  state.SubClient != nil,
		VerifyCode:    state.VerifyCode,
		LastMainBeat:  state.LastMainHeartbeat,
		LastSubBeat:   state.LastSubHeartbeat,
		PlatformID:    state.PlatformID,
		AuthCode:      state.AuthCode,
		Vehicles:      make([]VehicleSnapshot, 0, len(state.Vehicles)),
	}
	for _, v := range state.Vehicles {
		vs := VehicleSnapshot{
			VehicleNo:    v.Number,
			VehicleColor: v.Color,
			BatchCount:   v.BatchCount,
			PositionTime: v.PositionTime,
		}
		if v.Registration != nil {
			cp := *v.Registration
			vs.Registration = &cp
		}
		if v.Position != nil {
			cp := *v.Position
			vs.Position = &cp
			if gnss, err := jtt809.ParseGNSSData(cp.GnssData); err == nil {
				vs.Longitude = gnss.Longitude
				vs.Latitude = gnss.Latitude
			}
		}
		if v.LastVideoAck != nil {
			cp := *v.LastVideoAck
			vs.LastVideoAck = &cp
		}
		snap.Vehicles = append(snap.Vehicles, vs)
	}
	return snap
}

func vehicleKey(no string, color byte) string {
	return fmt.Sprintf("%s#%d", no, color)
}
