package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/zboyco/jtt809/pkg/jtt809"
	"github.com/zboyco/jtt809/pkg/server"
)

func main() {
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse config: %v\n", err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	gateway, err := server.NewJT809Gateway(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init gateway: %v\n", err)
		os.Exit(2)
	}

	// 设置回调函数，用于处理各类消息
	gateway.SetCallbacks(&server.Callbacks{
		OnLogin: func(userID uint32, req *jtt809.LoginRequest, resp *jtt809.LoginResponse) {
			slog.Info("【业务回调】平台登录",
				"user_id", userID,
				"result", resp.Result,
				"down_link", fmt.Sprintf("%s:%d", req.DownLinkIP, req.DownLinkPort))
			// 在这里可以执行业务逻辑，如：
			// - 记录登录日志到数据库
			// - 发送登录通知
			// - 更新平台在线状态
		},
		OnVehicleRegistration: func(userID uint32, plate string, color jtt809.PlateColor, reg *server.VehicleRegistration) {
			slog.Info("【业务回调】车辆注册",
				"user_id", userID,
				"plate", plate,
				"color", color,
				"terminal_id", reg.TerminalID)
			// 在这里可以执行业务逻辑，如：
			// - 保存车辆注册信息到数据库
			// - 更新车辆档案
			// - 发送注册通知
		},
		OnVehicleLocation: func(userID uint32, plate string, color jtt809.PlateColor, pos *jtt809.VehiclePosition, gnss *jtt809.GNSSData) {
			if gnss != nil {
				slog.Info("【业务回调】车辆定位",
					"user_id", userID,
					"plate", plate,
					"lon", gnss.Longitude,
					"lat", gnss.Latitude,
					"speed", gnss.Speed)
			}
			// 在这里可以执行业务逻辑，如：
			// - 存储定位数据到时序数据库
			// - 触发地理围栏判断
			// - 更新车辆实时位置
		},
		OnBatchLocation: func(userID uint32, plate string, color jtt809.PlateColor, count int) {
			slog.Info("【业务回调】批量定位",
				"user_id", userID,
				"plate", plate,
				"count", count)
			// 批量定位数据处理
		},
		OnVideoResponse: func(userID uint32, plate string, color jtt809.PlateColor, videoAck *server.VideoAckState) {
			slog.Info("【业务回调】视频应答",
				"user_id", userID,
				"plate", plate,
				"server", fmt.Sprintf("%s:%d", videoAck.ServerIP, videoAck.ServerPort),
				"result", videoAck.Result)
			// 在这里可以执行业务逻辑，如：
			// - 保存视频流地址
			// - 通知前端更新视频播放器
		},
		OnAuthorize: func(userID uint32, platformID string, authorizeCode string) {
			slog.Info("【业务回调】视频鉴权",
				"user_id", userID,
				"platform_id", platformID,
				"auth_code", authorizeCode)
			// 在这里可以执行业务逻辑，如：
			// - 保存授权码
			// - 更新鉴权状态
		},
		OnMonitorStartupAck: func(userID uint32, plate string, color jtt809.PlateColor) {
			slog.Info("【业务回调】车辆监控开启应答",
				"user_id", userID,
				"plate", plate,
				"color", color)
		},
		OnMonitorEndAck: func(userID uint32, plate string, color jtt809.PlateColor) {
			slog.Info("【业务回调】车辆监控结束应答",
				"user_id", userID,
				"plate", plate,
				"color", color)
		},
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := gateway.Start(ctx); err != nil && err != context.Canceled {
		slog.Error("gateway stopped with error", "err", err)
	}
}

// parseConfig 解析命令行参数，返回标准化配置。
func parseConfig() (server.Config, error) {
	var (
		mainAddr  = flag.String("main", ":10709", "主链路监听地址，格式 host:port")
		httpAddr  = flag.String("http", ":18080", "管理与调度 HTTP 地址")
		idleSec   = flag.Int("idle", 300, "连接空闲超时时间，单位秒，<=0 表示不超时")
		accountFS server.MultiAccountFlag
	)
	flag.Var(&accountFS, "account", "下级平台账号，格式 userID:password:gnssCenterID，可重复指定")
	flag.Parse()

	cfg := server.Config{
		MainListen: *mainAddr,
		HTTPListen: *httpAddr,
		IdleTimeout: func() time.Duration {
			if *idleSec <= 0 {
				return 0
			}
			return time.Duration(*idleSec) * time.Second
		}(),
	}

	if len(accountFS) == 0 {
		// 默认账号，方便快速体验。
		accountFS = append(accountFS, server.Account{
			UserID:       10001,
			Password:     "pass809",
			GnssCenterID: 324469864,
		})
	}
	cfg.Accounts = accountFS
	return cfg, nil
}
