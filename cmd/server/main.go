package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

func main() {
	cfg, err := parseConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse config: %v\n", err)
		os.Exit(2)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	printStartupInfo(cfg)

	gateway, err := NewJT809Gateway(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init gateway: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := gateway.Start(ctx); err != nil && err != context.Canceled {
		slog.Error("gateway stopped with error", "err", err)
	}
}

func printStartupInfo(cfg Config) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("  JT/T 809 上级平台服务器")
	fmt.Println(strings.Repeat("=", 80))

	// 服务信息
	fmt.Println("\n📡 服务信息:")
	fmt.Printf("  ├─ 主链路监听地址: %s\n", cfg.MainListen)
	if cfg.HTTPListen != "" {
		fmt.Printf("  ├─ HTTP管理地址:   %s\n", cfg.HTTPListen)
	} else {
		fmt.Printf("  ├─ HTTP管理地址:   未启用\n")
	}
	if cfg.IdleTimeout > 0 {
		fmt.Printf("  └─ 连接空闲超时:   %v\n", cfg.IdleTimeout)
	} else {
		fmt.Printf("  └─ 连接空闲超时:   无限制\n")
	}

	// 账号信息
	fmt.Println("\n🔑 下级平台账号列表:")
	fmt.Println("  ┌────────┬──────────────┬───────────────┐")
	fmt.Println("  │ 用户ID │    密码      │   校验码      │")
	fmt.Println("  ├────────┼──────────────┼───────────────┤")
	for _, acc := range cfg.Accounts {
		fmt.Printf("  │ %-6d │ %-12s │ 0x%08X    │\n",
			acc.UserID, acc.Password, acc.VerifyCode)
	}
	fmt.Println("  └────────┴──────────────┴───────────────┘")

	// 使用说明
	fmt.Println("\n💡 下级平台对接说明:")
	fmt.Println("  1. 连接主链路地址:", cfg.MainListen)
	fmt.Println("  2. 使用上表中的账号信息进行登录")
	fmt.Println("  3. 登录时上报从链路IP和端口，服务器将主动连接")

	if cfg.HTTPListen != "" {
		fmt.Println("\n🌐 HTTP管理接口:")
		fmt.Printf("  ├─ 健康检查:     GET  http://%s/healthz\n", cfg.HTTPListen)
		fmt.Printf("  ├─ 平台状态:     GET  http://%s/api/platforms\n", cfg.HTTPListen)
		fmt.Printf("  ├─ 请求视频流:   POST http://%s/api/video/request\n", cfg.HTTPListen)
		fmt.Printf("  ├─ 订阅车辆GPS:  POST http://%s/api/monitor/startup\n", cfg.HTTPListen)
		fmt.Printf("  └─ 取消订阅GPS:  POST http://%s/api/monitor/end\n", cfg.HTTPListen)
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("服务器正在启动...")
	fmt.Println(strings.Repeat("=", 80) + "\n")
}
