# JT/T 809 上级平台服务器

## 📖 简介

JT/T 809 上级平台服务器实现了道路运输车辆卫星定位系统平台间数据交换协议，用于接收下级平台上报的车辆定位、状态等信息，并提供车辆监控、视频请求等功能。

### 核心特性

- ✅ 支持 JT/T 809-2011 和 JT/T 809-2019 协议版本
- ✅ 主链路和从链路双向通信
- ✅ 多下级平台并发接入
- ✅ 车辆注册信息管理
- ✅ 实时GPS定位数据接收
- ✅ 实时视频流请求（JT/T 1078）
- ✅ 车辆定位信息订阅/取消订阅
- ✅ HTTP管理接口
- ✅ 连接空闲超时控制

---

## 🚀 快速启动

### 1. 构建服务

```bash
cd /Users/shannon/go/src/github.com/zboyco/jtt809
go build -o server ./cmd/server
```

### 2. 启动服务（使用默认配置）

```bash
./server
```

**默认配置：**
- 主链路监听端口: `10709`
- HTTP管理端口: `18080`
- 默认账号:
  - 用户ID: `10001`
  - 密码: `pass809`
  - 校验码: `0x13572468` (十进制: `324469864`)
  - 协议版本: `2011`

### 3. 启动服务（自定义配置）

```bash
./server \
  -main :10709 \
  -http :18080 \
  -idle 300 \
  -account "88888:mypassword:123456:2019"
```

**参数说明：**
- `-main`: 主链路监听地址（格式: `host:port`）
- `-http`: HTTP管理接口地址
- `-idle`: 连接空闲超时时间（秒），`<=0` 表示不超时
- `-account`: 下级平台账号，可重复指定多个
  - 格式: `userID:password:verifyCode[:version]`
  - version 可选值: `2011` 或 `2019`

**多账号示例：**
```bash
./server \
  -account "10001:pass809:0x13572468:2011" \
  -account "20001:pass2019:0x12345678:2019"
```

---

## 🧪 使用模拟器测试

### 1. 构建模拟器

```bash
go build -o simulator ./cmd/simulator
```

### 2. 启动模拟器

```bash
./simulator -sub 9001 -uid 10001 -pwd pass809
```

**模拟器参数：**
- `-main`: 上级平台主链路地址（默认: `127.0.0.1:10709`）
- `-sub`: 本地从链路监听端口（默认: `9000`）
- `-uid`: 用户ID（默认: `10001`）
- `-pwd`: 密码（默认: `pass809`）
- `-ip`: 本地IP地址，用于告知上级平台（默认: `127.0.0.1`）

### 3. 完整测试流程

**终端1 - 启动服务器：**
```bash
./server
```

**终端2 - 启动模拟器：**
```bash
./simulator -sub 9001
```

**预期输出：**

服务器端：
```
time=... level=INFO msg="main link connected" session=...
time=... level=INFO msg="packet dump" link=main dir=recv session=...
time=... level=INFO msg="main login request" session=... user_id=10001 result=0
time=... level=INFO msg="connecting sub link" addr=127.0.0.1:9001 user_id=10001
time=... level=INFO msg="sub link connected and logged in" user_id=10001
```

模拟器端：
```
Sub Link listening on 127.0.0.1:9001
Connecting to Main Link 127.0.0.1:10709...
Connected to Main Link
Login Response Received
Sub Link Incoming Connection from 127.0.0.1:xxxxx
Sub Link Login Request Received
```

---

## 🌐 HTTP 管理接口

HTTP 管理接口提供服务监控、平台状态查询、视频请求和车辆定位订阅等功能。

### 1. 健康检查

**端点**: `GET /healthz`

**用途**: 检查服务运行状态，用于监控系统集成

**请求示例**:
```bash
curl http://localhost:18080/healthz
```

**响应示例**:
```json
{
  "status": "ok"
}
```

---

### 2. 查看所有平台状态

**端点**: `GET /api/platforms`

**用途**: 获取所有已连接下级平台的状态快照，包括平台信息、车辆数据等

**请求示例**:
```bash
curl http://localhost:18080/api/platforms
```

**响应说明**: 返回所有平台的详细状态信息，包括：
- 平台连接状态
- 主链路和从链路信息
- 车辆列表及最新位置数据

---

### 3. 请求实时视频流

**端点**: `POST /api/video/request`

**用途**: 向下级平台请求指定车辆的实时视频流地址（JT/T 1078 协议）

**请求示例**:
```bash
curl -X POST http://localhost:18080/api/video/request \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 10001,
    "vehicle_no": "粤B12345",
    "vehicle_color": 2,
    "channel_id": 1,
    "av_item_type": 0,
    "gnss_hex": ""
  }'
```

**请求参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `user_id` | uint32 | 是 | 下级平台用户ID |
| `vehicle_no` | string | 是 | 车牌号 |
| `vehicle_color` | uint8 | 否 | 车牌颜色（默认2-蓝色） |
| `channel_id` | uint8 | 否 | 通道ID（默认1） |
| `av_item_type` | uint8 | 是 | 音视频类型：0-音视频，1-视频，2-双向对讲，3-监听，4-中心广播，5-透传 |
| `gnss_hex` | string | 否 | GNSS数据（Hex编码，36字节） |

**车牌颜色枚举**:
- `1`: 黑色
- `2`: 蓝色（默认）
- `3`: 黄色
- `4`: 白色
- `9`: 其他

**响应示例**:
```json
{
  "status": "sent"
}
```

**注意**: 此接口仅发送请求到下级平台，实际的视频流地址会通过异步响应返回

---

### 4. 订阅车辆定位信息

**端点**: `POST /api/monitor/startup`

**用途**: 向下级平台发送启动车辆定位信息交换请求，订阅指定车辆的GPS定位数据

**请求示例**:
```bash
curl -X POST http://localhost:18080/api/monitor/startup \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 10001,
    "vehicle_no": "粤B12345",
    "vehicle_color": 2,
    "reason_code": 1
  }'
```

**请求参数**:
| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `user_id` | uint32 | 是 | 下级平台用户ID |
| `vehicle_no` | string | 是 | 车牌号 |
| `vehicle_color` | uint8 | 否 | 车牌颜色（默认2-蓝色） |
| `reason_code` | uint8 | 否 | 申请原因：0-进入区域，1-人工指定，2-应急，3-其它（默认0） |

**响应示例**:
```json
{
  "status": "sent"
}
```

---

### 5. 取消订阅车辆定位信息

**端点**: `POST /api/monitor/end`

**用途**: 向下级平台发送结束车辆定位信息交换请求，取消订阅指定车辆的GPS定位数据

**请求示例**:
```bash
curl -X POST http://localhost:18080/api/monitor/end \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 10001,
    "vehicle_no": "粤B12345",
    "vehicle_color": 2,
    "reason_code": 1
  }'
```

**请求参数**: 与订阅接口相同

**响应示例**:
```json
{
  "status": "sent"
}
```

---

## 🔗 与真实下级平台对接

### 对接前准备

**提供给下级平台的信息：**
1. **上级平台IP**: `您的服务器公网IP`
2. **主链路端口**: `10709`（或您配置的端口）
3. **分配的账号信息**:
   - 用户ID: `10001`（或您分配的ID）
   - 密码: `pass809`（或您设置的密码）
   - 校验码: `0x13572468`（或您设置的值）
   - 协议版本: `2011` 或 `2019`

**注意事项：**
1. ✅ 服务器只需开放**主链路端口**（如 `10709`）
2. ✅ 服务器会**主动连接**下级平台上报的从链路地址
3. ⚠️ 确保服务器能够**出站连接**到下级平台的IP和端口
4. ⚠️ 如果下级平台在NAT后，请确认他们的从链路端口已做端口映射

### 防火墙配置

**入站规则：**
```bash
# 主链路端口
sudo ufw allow 10709/tcp

# HTTP管理端口（可选，仅内网访问）
sudo ufw allow from 192.168.0.0/16 to any port 18080
```

**出站规则：**
```bash
# 允许出站连接（用于连接下级平台的从链路）
# 通常默认允许，无需特别配置
```

---

## ❓ 常见问题

### Q1: 下级平台连接后，从链路建立失败？
**A:** 检查：
1. 下级平台在登录请求中上报的 `DownLinkIP` 和 `DownLinkPort` 是否正确
2. 服务器能否访问该IP和端口（使用 `telnet` 或 `nc` 测试）
3. 查看服务器日志中的 "connecting sub link" 和错误信息

### Q2: 日志量太大怎么办？
**A:** 当前所有日志都是 `INFO` 级别，包括Hex Dump。如需减少日志：
- 生产环境建议修改 `main.go` 中的日志级别为 `slog.LevelWarn`
- 或使用日志管理工具过滤

### Q3: 如何查看实时车辆定位？
**A:** 访问 HTTP 接口：
```bash
# 查看所有平台及车辆
curl http://localhost:18080/api/platforms | jq
```

### Q4: 视频请求发送后没有响应？
**A:** 检查：
1. 下级平台是否支持 JT/T 1078 协议
2. 车牌号和车牌颜色是否正确
3. 授权码是否有效
4. 查看服务器日志中的错误信息

### Q5: 订阅车辆定位后没有收到数据？
**A:** 检查：
1. 从链路是否已建立（查看日志）
2. 下级平台是否支持该功能
3. 车辆是否在线且有定位数据

---

## 📚 技术支持

如遇到问题，请检查：
1. 服务器日志输出
2. 下级平台日志
3. 网络连通性（主链路和从链路）
4. 账号配置是否匹配

---

## 🔧 协议实现

本服务器实现了以下 JT/T 809 标准消息：

**主链路（下级平台 → 上级平台）**:
- `0x1001`: 主链路登录请求
- `0x1002`: 主链路登录应答
- `0x1005`: 主链路心跳请求
- `0x1006`: 主链路心跳应答
- `0x1200`: 车辆动态信息交换（上行）
  - `0x1201`: 上传车辆注册信息
  - `0x1202`: 实时上传车辆定位信息
- `0x1800`: 实时音视频（上行）
  - `0x1801`: 实时音视频请求应答

**从链路（上级平台 → 下级平台）**:
- `0x9001`: 从链路连接请求
- `0x9002`: 从链路连接应答
- `0x9005`: 从链路心跳请求
- `0x9006`: 从链路心跳应答
- `0x9200`: 车辆动态信息交换（下行）
  - `0x9205`: 申请交换指定车辆定位信息请求
  - `0x9206`: 取消交换指定车辆定位信息请求
- `0x9800`: 实时音视频（下行）
  - `0x9801`: 实时音视频请求
