package jtt809

// VehicleColor 表示车辆颜色编码，参考 JT/T 809-2019 车辆颜色类型。
const (
	VehicleColorBlue          byte = 0x01 // 蓝色
	VehicleColorYellow        byte = 0x02 // 黄色
	VehicleColorBlack         byte = 0x03 // 黑色
	VehicleColorWhite         byte = 0x04 // 白色
	VehicleColorGreen         byte = 0x05 // 绿色
	VehicleColorOther         byte = 0x09 // 其他
	VehicleColorAgriYellow    byte = 0x91 // 农黄色
	VehicleColorYellowGreen   byte = 0x93 // 黄绿色
	VehicleColorAgriGreen     byte = 0x92 // 农绿色
	VehicleColorGradientGreen byte = 0x94 // 渐变绿
)

// SubBusinessType 定义子业务数据类型，截取常用值以支持定位、查岗等业务。
const (
	SubMsgRealLocation     uint16 = 0x1202 // 实时上传车辆定位信息
	SubMsgBatchLocation    uint16 = 0x1203 // 车辆定位信息自动补报
	SubMsgUploadVehicleReg uint16 = 0x1201 // 上传车辆注册信息
	SubMsgWarnSuperviseReq uint16 = 0x9401 // 报警督办请求
	SubMsgPlatformQueryAck uint16 = 0x1301 // 平台查岗应答

	// 下行子业务 (上级平台->下级平台)
	SubMsgApplyForMonitorStartup uint16 = 0x9205 // 启动车辆定位信息交换请求
	SubMsgApplyForMonitorEnd     uint16 = 0x9206 // 结束车辆定位信息交换请求

	// 上行应答子业务 (下级平台->上级平台)
	SubMsgApplyForMonitorStartupAck uint16 = 0x1205 // 启动车辆定位信息交换应答
	SubMsgApplyForMonitorEndAck     uint16 = 0x1206 // 结束车辆定位信息交换应答

	// JT/T 1078-2016 子业务
	SubMsgAuthorizeStartupReq     uint16 = 0x1701 // 时效口令上报消息 (UP_AUTHORIZE_MSG_STARTUP)
	SubMsgRealTimeVideoStartupAck     uint16 = 0x1801 // 实时音视频请求应答消息 (UP_REALVIDEO_MSG_STARTUP_ACK)
	SubMsgDownRealTimeVideoStartupReq uint16 = 0x9801 // 实时音视频请求消息 (DOWN_REALVIDEO_MSG_STARTUP)
)

// MonitorReasonCode 启动/结束车辆定位信息交换请求原因
type MonitorReasonCode byte

const (
	MonitorReasonEnterArea MonitorReasonCode = 0x00 // 车辆进入指定区域
	MonitorReasonManual    MonitorReasonCode = 0x01 // 人工指定交换
	MonitorReasonEmergency MonitorReasonCode = 0x02 // 应急状态下车辆定位信息回传
	MonitorReasonOther     MonitorReasonCode = 0x03 // 其它原因
)

// WarnSrc 表示报警信息来源。
type WarnSrc byte

const (
	WarnSrcVehicle    WarnSrc = 0x01
	WarnSrcEnterprise WarnSrc = 0x02
	WarnSrcGovernment WarnSrc = 0x03
	WarnSrcOther      WarnSrc = 0x09
)

// WarnType 表示报警类型，列举常见值。
type WarnType uint16

const (
	WarnTypeOverspeed              WarnType = 0x0001
	WarnTypeFatigueDriving         WarnType = 0x0002
	WarnTypeEmergency              WarnType = 0x0003
	WarnTypeEnterRegion            WarnType = 0x0004
	WarnTypeLeaveRegion            WarnType = 0x0005
	WarnTypeRouteDeviation         WarnType = 0x000B
	WarnTypeOther                  WarnType = 0x000E
	WarnTypeTimeoutParking         WarnType = 0xA001
	WarnTypeUploadIntervalAbnormal WarnType = 0xA002
)

// SupervisionLevel 表示督办级别。
type SupervisionLevel byte

const (
	SupervisionLevelUrgent SupervisionLevel = 0x00
	SupervisionLevelNormal SupervisionLevel = 0x01
)
