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
