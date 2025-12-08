package server

import (
	"github.com/zboyco/jtt809/pkg/jtt809"
)

// Callbacks 定义 JT809Gateway 支持的所有回调函数
// 所有回调函数都是可选的，未设置时不会被调用
type Callbacks struct {
	// OnLogin 平台登录请求回调
	// 参数: userID - 用户ID, req - 登录请求, resp - 登录应答
	OnLogin func(userID uint32, req *jtt809.LoginRequest, resp *jtt809.LoginResponse)

	// OnVehicleRegistration 车辆注册消息回调
	// 参数: userID - 用户ID, plate - 车牌号, color - 车牌颜色, reg - 注册信息
	OnVehicleRegistration func(userID uint32, plate string, color jtt809.PlateColor, reg *VehicleRegistration)

	// OnVehicleLocation 车辆实时定位回调
	// 参数: userID - 用户ID, plate - 车牌号, color - 车牌颜色, pos - 定位数据, gnss - GNSS数据(解析失败时为nil)
	OnVehicleLocation func(userID uint32, plate string, color jtt809.PlateColor, pos *jtt809.VehiclePosition, gnss *jtt809.GNSSData)

	// OnBatchLocation 车辆批量定位回调
	// 参数: userID - 用户ID, plate - 车牌号, color - 车牌颜色, count - 批次中的定位数量
	OnBatchLocation func(userID uint32, plate string, color jtt809.PlateColor, count int)

	// OnVideoResponse 实时视频应答回调
	// 参数: userID - 用户ID, plate - 车牌号, color - 车牌颜色, videoAck - 视频应答信息
	OnVideoResponse func(userID uint32, plate string, color jtt809.PlateColor, videoAck *VideoAckState)

	// OnAuthorize 鉴权消息(视频授权码)回调
	// 参数: userID - 用户ID, platformID - 平台ID, authorizeCode - 授权码
	OnAuthorize func(userID uint32, platformID string, authorizeCode string)

	// OnMonitorStartupAck 启动车辆定位信息交换应答回调
	// 参数: userID - 用户ID, plate - 车牌号, color - 车牌颜色
	OnMonitorStartupAck func(userID uint32, plate string, color jtt809.PlateColor)

	// OnMonitorEndAck 结束车辆定位信息交换应答回调
	// 参数: userID - 用户ID, plate - 车牌号, color - 车牌颜色
	OnMonitorEndAck func(userID uint32, plate string, color jtt809.PlateColor)
}
