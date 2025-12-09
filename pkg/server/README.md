# JT/T 809-2019 上级平台服务器

## 📖 简介

JT/T 809-2019 上级平台服务器实现了道路运输车辆卫星定位系统平台间数据交换协议，用于接收下级平台上报的车辆定位、状态等信息，并提供车辆监控、视频请求等功能。

### 核心特性

- ✅ 支持 JT/T 809-2019 协议版本
- ✅ 主链路和从链路双向通信
- ✅ 智能链路选择与自动降级
- ✅ 多下级平台并发接入
- ✅ 车辆注册信息管理
- ✅ 实时GPS定位数据接收
- ✅ 实时视频流请求（JT/T 1078-2016）
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

### 3. 启动服务（自定义配置）

```bash
./server \
  -main :10709 \
  -http :18080 \
  -idle 300 \
  -account "88888:mypassword:123456"
```

**参数说明：**
- `-main`: 主链路监听地址（格式: `host:port`）
- `-http`: HTTP管理接口地址
- `-idle`: 连接空闲超时时间（秒），`<=0` 表示不超时
- `-account`: 下级平台账号，可重复指定多个
  - 格式: `userID:password:gnssCenterID`

**多账号示例：**
```bash
./server \
  -account "10001:pass809:0x13572468" \
  -account "20001:passdemo:0x12345678"
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
- 时效口令（`auth_code`）和平台编码（`platform_id`）
- 车辆列表及最新位置数据

**响应字段**：
| 字段 | 类型 | 说明 |
|------|------|------|
| `user_id` | uint32 | 下级平台用户ID |
| `platform_id` | string | 平台唯一编码 |
| `auth_code` | string | 时效口令（用于视频鉴权） |
| `gnss_center_id` | uint32 | GNSS中心ID |
| `main_session_id` | string | 主链路会话ID |
| `sub_connected` | bool | 从链路是否已连接 |
| `vehicles` | array | 车辆列表 |

---

### 3. 请求实时视频流

**端点**: `POST /api/video/request`

**用途**: 向下级平台请求指定车辆的实时视频流地址（JT/T 1078-2016 协议）

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

## 🔗 与真实下级平台对接

### 对接前准备

**提供给下级平台的信息：**
1. **上级平台IP**: `您的服务器公网IP`
2. **主链路端口**: `10709`（或您配置的端口）
3. **分配的账号信息**:
   - 用户ID: `10001`（或您分配的ID）
   - 密码: `pass809`（或您设置的密码）
   - 校验码: `0x13572468`（或您设置的值）

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
1. 下级平台是否支持 JT/T 1078-2016 协议
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

本服务器实现了以下 JT/T 809-2019 标准消息：

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
- `0x9007`: 从链路断开通知
- `0x9200`: 车辆动态信息交换（下行）
  - `0x9205`: 申请交换指定车辆定位信息请求
  - `0x9206`: 取消交换指定车辆定位信息请求
- `0x9800`: 实时音视频（下行）
  - `0x9801`: 实时音视频请求

**授权消息（上行）**:
- `0x1700`: 授权消息
  - `0x1701`: 时效口令上报请求

---

## 🔐 时效口令（授权码）

### 什么是时效口令

时效口令（AuthorizeCode）是 JT/T 1078-2016 视频传输协议中用于鉴权的授权码，由下级平台通过 `0x1700` 授权消息主动上报给上级平台。时效口令是**平台级别**的，不与具体车辆关联。

### 工作流程

```
下级平台                           上级平台
    │                                 │
    │──── 0x1701 时效口令上报 ────────→│
    │                                 │ 存储时效口令
    │                                 │
    │←──── 0x9801 视频请求 ────────────│ 使用时效口令
    │                                 │
    │──── 0x1801 视频地址应答 ─────────→│
    │                                 │
```

### 时效口令的获取

1. **自动接收**：下级平台连接后会主动上报时效口令（`0x1701` 消息）
2. **自动存储**：服务器自动存储每个平台的时效口令
3. **自动使用**：发送视频请求时自动附带对应平台的时效口令

### 查看时效口令

通过 HTTP API 查看已获取的时效口令：

```bash
curl http://localhost:18080/api/platforms | jq
```

**响应示例**：
```json
{
  "user_id": 10001,
  "platform_id": "31010000000",
  "auth_code": "ABC123XYZ",
  "gnss_center_id": 324469864,
  "main_session_id": "session_xxx",
  "sub_connected": true,
  "vehicles": [...]
}
```

**字段说明**：
- `platform_id`: 平台唯一编码
- `auth_code`: 时效口令（用于视频鉴权）

### 回调支持

如需在收到时效口令时执行自定义逻辑，可设置 `OnAuthorize` 回调：

```go
gateway.SetCallbacks(&server.Callbacks{
    OnAuthorize: func(userID uint32, platformID string, authCode string) {
        log.Printf("收到时效口令: 平台=%s, 口令=%s", platformID, authCode)
        // 自定义处理逻辑
    },
})
```

### 注意事项

- ⚠️ 时效口令由下级平台生成和管理，上级平台只负责接收和使用
- ⚠️ 时效口令可能会定期更新，服务器会自动更新存储的最新值
- ⚠️ 如果下级平台未上报时效口令，视频请求可能会失败

---

## 🔀 智能链路选择与降级机制

### 设计原理

服务器实现了统一的消息发送方法，根据 JT/T 809-2019 协议规范自动选择合适的链路，并在链路不可用时自动降级到备用链路。

### 链路策略

| 消息类型 | 消息ID | 首选链路 | 允许降级 | 说明 |
|---------|--------|---------|---------|------|
| 主链路登录应答 | 0x1002 | 主链路 | ❌ | 从链路尚未建立 |
| 主链路心跳应答 | 0x1006 | 从链路 | ✅ | 协议规定 |
| 从链路登录请求 | 0x9001 | 从链路 | ❌ | 协议规定 |
| 从链路心跳请求 | 0x9005 | 从链路 | ❌ | 协议规定 |
| 从链路断开通知 | 0x9007 | 主链路 | ❌ | 协议规定 |
| 其他下行消息 | 0x9xxx | 从链路 | ✅ | 默认策略 |

### 降级流程

```
发送消息
    ↓
查询链路策略（map 或默认）
    ↓
尝试首选链路
    ↓
成功？ ──是──→ 返回成功
    ↓ 否
允许降级？ ──否──→ 返回错误
    ↓ 是
尝试备用链路
    ↓
成功？ ──是──→ 记录降级日志 → 返回成功
    ↓ 否
返回错误
```

### 降级日志示例

**正常发送**：
```
level=INFO msg="packet dump" link=sub dir=send session=10001
```

**降级发送**：
```
level=WARN msg="send on sub link failed" user_id=10001 msg_id=0x1006 err=...
level=INFO msg="sub link unavailable, fallback to main link" user_id=10001 msg_id=0x1006
level=INFO msg="packet dump" link=main dir=send session=xxx
```

### 优势

- ✅ **高可用性**：单链路故障不影响通信
- ✅ **协议兼容**：严格遵循 JT/T 809-2019 规范
- ✅ **自动切换**：无需人工干预
- ✅ **完整日志**：便于故障排查
