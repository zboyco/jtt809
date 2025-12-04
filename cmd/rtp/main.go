package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/zboyco/jtt809/pkg/jtt1078"
)

var port = flag.String("port", ":8080", "监听端口")

func main() {
	flag.Parse()

	// 创建视频转码服务器实例
	s := jtt1078.NewVideoServer(*port)

	// 启动服务器
	fmt.Printf("🚀 JT/T 1078-2016 RTP 代理服务器\n")
	fmt.Printf("👂 监听端口: %s\n", *port)
	fmt.Printf("💡 使用方式: http://localhost%s/proxy?url=[视频源地址]\n", *port)
	fmt.Printf("💡 FLV方式: http://localhost%s/proxy.flv?url=[视频源地址]\n", *port)

	// 设置信号处理，优雅关闭
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// 启动服务器（阻塞）
	go func() {
		if err := s.Start(); err != nil {
			log.Fatal(err)
		}
	}()

	// 等待退出信号
	<-sigChan
	fmt.Println("\n🛑 收到退出信号，正在关闭服务器...")
}
