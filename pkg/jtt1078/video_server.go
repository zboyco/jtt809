package jtt1078

import (
	"fmt"
	"log"
	"net/http"
)

// ================= Constants Definition =================
var (
	magicHeader = []byte{0x30, 0x31, 0x63, 0x64}
	startCode   = []byte{0x00, 0x00, 0x00, 0x01}
)

// ================= Core Structures =================

// Server represents the RTP proxy server
type Server struct {
	port    string
	manager *StreamManager
}

// ================= Server Instance =================

// NewVideoServer creates a new server instance
func NewVideoServer(port string) *Server {
	return &Server{
		port:    port,
		manager: &StreamManager{},
	}
}

// Start starts the server
func (s *Server) Start() error {
	// Enable detailed logging: date time microseconds
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)

	http.HandleFunc("/proxy", s.handleProxyRaw)
	http.HandleFunc("/proxy.flv", s.handleProxyFLV)

	fmt.Println("===================================================")
	fmt.Println("🚀 JT/T 1078-2016")
	fmt.Println("✨ 功能: 视频秒开 | 多路复用 | 延迟自动修复 | 全链路日志")
	fmt.Printf("👂 监听端口: %s\n", s.port)
	fmt.Println("===================================================")

	return http.ListenAndServe(s.port, nil)
}

// ================= HTTP Handlers =================

func (s *Server) handleProxyRaw(w http.ResponseWriter, r *http.Request) {
	targetURL, clientIP := parseRequest(r)
	if targetURL == "" {
		http.Error(w, "missing url", 400)
		return
	}

	w.Header().Set("Content-Type", "video/x-h264")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	s.runStreamLoop(w, flusher, targetURL, clientIP, false)
}

func (s *Server) handleProxyFLV(w http.ResponseWriter, r *http.Request) {
	targetURL, clientIP := parseRequest(r)
	if targetURL == "" {
		http.Error(w, "missing url", 400)
		return
	}

	w.Header().Set("Content-Type", "video/x-flv")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	// Send FLV Header
	w.Write([]byte{'F', 'L', 'V', 0x01, 0x01, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00})
	s.runStreamLoop(w, flusher, targetURL, clientIP, true)
}

func (s *Server) runStreamLoop(w http.ResponseWriter, flusher http.Flusher, targetURL, clientIP string, isFLV bool) {
	broadcaster := s.manager.GetOrCreateBroadcaster(targetURL)

	clientChan := make(chan []byte, 1000)

	// Subscribe (internal logging)
	cachedGOP := broadcaster.Subscribe(clientChan, clientIP)
	defer broadcaster.Unsubscribe(clientChan)

	var muxer *FlvMuxer
	if isFLV {
		muxer = NewFlvMuxer()
	}

	processFrame := func(frame []byte) error {
		if isFLV {
			tags, err := muxer.WriteFrame(frame)
			if err != nil {
				return nil
			}
			for _, tag := range tags {
				if _, err := w.Write(tag); err != nil {
					return err
				}
			}
		} else {
			if _, err := w.Write(frame); err != nil {
				return err
			}
		}
		return nil
	}

	// 1. Send cache (instant opening)
	for _, frame := range cachedGOP {
		if err := processFrame(frame); err != nil {
			return
		}
	}
	flusher.Flush()

	// 2. Real-time forwarding
	for {
		frameData, isOpen := <-clientChan
		if !isOpen {
			return
		}
		if err := processFrame(frameData); err != nil {
			return
		}
		flusher.Flush()
	}
}
