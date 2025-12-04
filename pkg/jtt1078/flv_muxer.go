package jtt1078

import (
	"bytes"
	"encoding/binary"
	"time"
)

// FlvMuxer handles FLV muxing with intelligent clock
type FlvMuxer struct {
	pps, sps       []byte
	sentConf       bool
	timestamp      uint32    // Current FLV timestamp
	lastSystemTime time.Time // Last send time
}

// NewFlvMuxer creates a new FLV muxer
func NewFlvMuxer() *FlvMuxer {
	return &FlvMuxer{
		timestamp:      0,
		lastSystemTime: time.Time{}, // Zero value initialization
	}
}

// WriteFrame writes a frame and returns FLV tags
func (m *FlvMuxer) WriteFrame(frame []byte) ([][]byte, error) {
	nalus := bytes.Split(frame, startCode)
	var tags [][]byte

	// --- Core repair logic start ---
	now := time.Now()

	// If it's the first frame
	if m.lastSystemTime.IsZero() {
		m.lastSystemTime = now
	}

	// Calculate time difference from last frame (milliseconds)
	delta := uint32(now.Sub(m.lastSystemTime).Milliseconds())

	// Strategy:
	// 1. If delta is very small (< 10ms), it means we're sending GOP cache at full speed (Burst mode)
	//    Force increment by 30fps (33ms) to help client quickly build buffer.
	// 2. If delta is normal (> 10ms), it's a live stream (Live mode)
	//    Increment by actual elapsed time, perfectly matching upstream network rhythm.

	increment := delta
	if increment < 10 {
		increment = 33 // Force 33ms (about 30fps)
	}

	// Prevent timestamp jumps (e.g. if upstream disconnected for 10 seconds and reconnected)
	// Limit maximum interval to prevent player from jumping progress bar
	// But for monitoring streams, reflecting real stuttering might be better than frame skipping
	// Here we temporarily don't impose a hard limit, or limit to 500ms (max half second pause between frames)
	/*
		if increment > 1000 {
			increment = 33 // Abnormal jump fallback
		}
	*/

	m.timestamp += increment
	m.lastSystemTime = now // Update last send time

	ts := m.timestamp
	// --- Core repair logic end ---

	var vp bytes.Buffer
	isKey := false

	for _, nal := range nalus {
		if len(nal) == 0 {
			continue
		}
		t := nal[0] & 0x1F
		if t == 7 {
			m.sps = make([]byte, len(nal))
			copy(m.sps, nal)
		}
		if t == 8 {
			m.pps = make([]byte, len(nal))
			copy(m.pps, nal)
		}
		if t == 5 {
			isKey = true
		}
		binary.Write(&vp, binary.BigEndian, uint32(len(nal)))
		vp.Write(nal)
	}

	if len(m.sps) > 0 && len(m.pps) > 0 && !m.sentConf {
		tags = append(tags, m.createSeqHeader())
		m.sentConf = true
	}

	if vp.Len() > 0 {
		f := byte(0x27)
		if isKey {
			f = 0x17
		}
		d := new(bytes.Buffer)
		d.WriteByte(f)
		d.WriteByte(0x01)
		d.Write([]byte{0, 0, 0})
		d.Write(vp.Bytes())
		tags = append(tags, createFLVTag(9, d.Bytes(), ts))
	}
	return tags, nil
}

// createSeqHeader creates the sequence header
func (m *FlvMuxer) createSeqHeader() []byte {
	d := new(bytes.Buffer)
	d.WriteByte(0x17)
	d.WriteByte(0x00)
	d.Write([]byte{0, 0, 0})
	d.WriteByte(0x01)
	d.WriteByte(m.sps[1])
	d.WriteByte(m.sps[2])
	d.WriteByte(m.sps[3])
	d.WriteByte(0xFF)
	d.WriteByte(0xE1)
	binary.Write(d, binary.BigEndian, uint16(len(m.sps)))
	d.Write(m.sps)
	d.WriteByte(0x01)
	binary.Write(d, binary.BigEndian, uint16(len(m.pps)))
	d.Write(m.pps)
	return createFLVTag(9, d.Bytes(), 0)
}

// createFLVTag creates an FLV tag
func createFLVTag(t byte, d []byte, ts uint32) []byte {
	sz := len(d)
	tot := 11 + sz + 4
	buf := make([]byte, tot)
	buf[0] = t
	buf[1] = byte(sz >> 16)
	buf[2] = byte(sz >> 8)
	buf[3] = byte(sz)
	buf[4] = byte(ts >> 16)
	buf[5] = byte(ts >> 8)
	buf[6] = byte(ts)
	buf[7] = byte(ts >> 24)
	copy(buf[11:], d)
	binary.BigEndian.PutUint32(buf[tot-4:], uint32(tot-4))
	return buf
}
