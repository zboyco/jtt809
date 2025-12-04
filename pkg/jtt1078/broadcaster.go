package jtt1078

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"log"
	"net/http"
	"sync"
	"time"
)

// Broadcaster handles broadcasting video streams to multiple clients
type Broadcaster struct {
	url     string
	clients map[chan []byte]string // Store IP for logging
	lock    sync.RWMutex
	running bool
	manager *StreamManager // Reference to manager

	// GOP Cache
	gopCache [][]byte
	gopLock  sync.RWMutex

	frameAssemblyBuffer *bytes.Buffer
}

// Subscribe adds a client to the broadcaster and returns cached GOP
func (b *Broadcaster) Subscribe(ch chan []byte, clientIP string) [][]byte {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.clients[ch] = clientIP

	// Log: client joined
	log.Printf("➕ [Client Join] IP: %s | 在线: %d | 流: ...%s",
		clientIP, len(b.clients), shortenURL(b.url))

	b.gopLock.RLock()
	defer b.gopLock.RUnlock()
	snapshot := make([][]byte, len(b.gopCache))
	copy(snapshot, b.gopCache)
	return snapshot
}

// Unsubscribe removes a client from the broadcaster
func (b *Broadcaster) Unsubscribe(ch chan []byte) {
	b.lock.Lock()
	defer b.lock.Unlock()
	ip := b.clients[ch]
	delete(b.clients, ch)

	// Log: client left
	log.Printf("➖ [Client Left] IP: %s | 在线: %d | 流: ...%s",
		ip, len(b.clients), shortenURL(b.url))

	if len(b.clients) == 0 {
		log.Printf("🗑️ [Stream Stop] 无人观看，销毁流任务: ...%s", shortenURL(b.url))
		b.manager.streams.Delete(b.url)
		b.running = false
	}
}

// updateGOPCache updates the GOP cache with a new frame
func (b *Broadcaster) updateGOPCache(frame []byte, isKeyFrame bool) {
	b.gopLock.Lock()
	defer b.gopLock.Unlock()

	if isKeyFrame {
		b.gopCache = b.gopCache[:0]
	}

	// 【重要修复】防止缓存无限增长导致 Web 端延迟过大
	if len(b.gopCache) > 500 {
		b.gopCache = b.gopCache[:0]
	}

	b.gopCache = append(b.gopCache, frame)
}

// broadcast sends a frame to all connected clients
func (b *Broadcaster) broadcast(frame []byte) {
	b.lock.RLock()
	defer b.lock.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- frame:
		default:
		}
	}
}

// StartPulling starts pulling the video stream from the source
func (b *Broadcaster) StartPulling() {
	log.Printf("🔗 [Source Connect] 开始连接上级平台...")

	client := &http.Client{Timeout: 0}
	req, _ := http.NewRequest("GET", b.url, nil)
	req.Header.Set("User-Agent", "JT1078-Proxy/LogVersion") // Add UA to prevent rejection
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("❌ [Source Error] 连接失败: %v", err)
		b.manager.streams.Delete(b.url)
		return
	}
	defer resp.Body.Close()

	log.Printf("✅ [Source OK] 连接成功，开始拉流")

	scanner := bufio.NewScanner(resp.Body)
	buf := make([]byte, 2<<20)
	scanner.Buffer(buf, 5<<20)
	scanner.Split(func(d []byte, atEOF bool) (int, []byte, error) {
		if atEOF && len(d) == 0 {
			return 0, nil, nil
		}
		i := bytes.Index(d, magicHeader)
		if i < 0 {
			if atEOF {
				return len(d), nil, nil
			}
			return 0, nil, nil
		}
		if i > 0 {
			return i, nil, nil
		}
		if len(d) < 16 {
			return 0, nil, nil
		}
		hLen := 30
		dt := d[15] >> 4
		if dt == 3 {
			hLen = 26
		} else if dt == 4 {
			hLen = 18
		}
		if len(d) < hLen {
			return 0, nil, nil
		}
		pLen := hLen + int(binary.BigEndian.Uint16(d[hLen-2:hLen]))
		if len(d) < pLen {
			return 0, nil, nil
		}
		return pLen, d[:pLen], nil
	})

	lastLogTime := time.Now()
	totalBytes := 0

	for b.running && scanner.Scan() {
		packet := scanner.Bytes()
		totalBytes += len(packet)

		// Log: heartbeat, print traffic every 30 seconds
		if time.Since(lastLogTime) > 30*time.Second {
			log.Printf("💓 [KeepAlive] 流 ...%s 正常 | 30秒流量: %.2f MB",
				shortenURL(b.url), float64(totalBytes)/1024/1024)
			lastLogTime = time.Now()
			totalBytes = 0
		}

		b.processPacket(packet)
	}

	log.Printf("🛑 [Source Disconnect] 源断开: ...%s", shortenURL(b.url))
	b.manager.streams.Delete(b.url)
}

// processPacket processes a received packet
func (b *Broadcaster) processPacket(packet []byte) {
	if len(packet) < 16 {
		return
	}
	tag := packet[15] & 0x0F
	dt := packet[15] >> 4
	hLen := 30
	if dt == 3 {
		hLen = 26
	} else if dt == 4 {
		hLen = 18
	}
	if len(packet) < hLen {
		return
	}
	body := packet[hLen:]

	if dt <= 2 {
		if tag == 0 || tag == 1 {
			b.frameAssemblyBuffer.Write(startCode)
		}
		b.frameAssemblyBuffer.Write(body)
		if tag == 0 || tag == 2 {
			fullFrame := make([]byte, b.frameAssemblyBuffer.Len())
			copy(fullFrame, b.frameAssemblyBuffer.Bytes())

			isKey := (dt == 0)
			b.updateGOPCache(fullFrame, isKey)
			b.broadcast(fullFrame)
			b.frameAssemblyBuffer.Reset()
		}
	}
}
