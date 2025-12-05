package server

import (
	"fmt"
	"strings"
)

func printStartupInfo(cfg Config) {
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("  JT/T 809-2019 上级平台服务器")
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
	fmt.Println("  │ 用户ID │    密码      │   平台接入码  │")
	fmt.Println("  ├────────┼──────────────┼───────────────┤")
	for _, acc := range cfg.Accounts {
		fmt.Printf("  │ %-6d │ %-12s │ %10d    │\n",
			acc.UserID, acc.Password, acc.GnssCenterID)
	}
	fmt.Println("  └────────┴──────────────┴───────────────┘")

	// 使用说明
	fmt.Println("\n💡 下级平台对接说明:")
	fmt.Println("  1. 连接主链路地址:", cfg.MainListen)
	fmt.Println("  2. 使用上表中的账号信息进行登录")
	fmt.Println("  3. 登录时上报从链路IP和端口，服务器将主动连接")

	if cfg.HTTPListen != "" {
		fmt.Println("\n🌐 HTTP管理接口:")
		fmt.Printf("  ├─ 监控系统:     GET  http://%s/ui\n", cfg.HTTPListen)
		fmt.Printf("  ├─ 健康检查:     GET  http://%s/healthz\n", cfg.HTTPListen)
		fmt.Printf("  ├─ 平台状态:     GET  http://%s/api/platforms\n", cfg.HTTPListen)
		fmt.Printf("  └─ 请求视频流:   POST http://%s/api/video/request\n", cfg.HTTPListen)
	}

	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Println("服务器正在启动...")
	fmt.Println(strings.Repeat("=", 80) + "\n")
}
