package jtt1078

import (
	"bytes"
	"log"
	"sync"
)

// StreamManager manages multiple video streams
type StreamManager struct {
	streams sync.Map
}

// GetOrCreateBroadcaster gets an existing broadcaster for the targetURL or creates a new one
func (m *StreamManager) GetOrCreateBroadcaster(targetURL string) *Broadcaster {
	if val, ok := m.streams.Load(targetURL); ok {
		return val.(*Broadcaster)
	}

	newB := &Broadcaster{
		url:                 targetURL,
		clients:             make(map[chan []byte]string),
		running:             true,
		manager:             m, // Set manager reference
		gopCache:            make([][]byte, 0, 500),
		frameAssemblyBuffer: bytes.NewBuffer(make([]byte, 0, 512*1024)),
	}
	actual, loaded := m.streams.LoadOrStore(targetURL, newB)
	b := actual.(*Broadcaster)
	if !loaded {
		// Log: new stream started
		log.Printf("✨ [New Stream] 启动拉流任务: %s", shortenURL(targetURL))
		go b.StartPulling()
	}
	return b
}
