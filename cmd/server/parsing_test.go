package main

import (
	"testing"

	"github.com/zboyco/jtt809/pkg/jtt809"
)

func TestParseVehicleRegistration(t *testing.T) {
	// Helper to encode GBK string
	encode := func(s string) []byte {
		b, _ := jtt809.EncodeGBK(s)
		return b
	}

	// Helper to create payload
	createPayload := func(platform, producer, model, imei, termID, sim string) []byte {
		const (
			lenPlatform = 11
			lenProducer = 11
			lenModel    = 30
			lenIMEI     = 15
			lenTermID   = 30
			lenSIM      = 13
		)
		buf := make([]byte, 0)

		pad := func(b []byte, length int) []byte {
			padded := make([]byte, length)
			copy(padded, b)
			return padded
		}

		buf = append(buf, pad(encode(platform), lenPlatform)...)
		buf = append(buf, pad(encode(producer), lenProducer)...)
		buf = append(buf, pad(encode(model), lenModel)...)
		buf = append(buf, pad(encode(imei), lenIMEI)...)
		buf = append(buf, pad(encode(termID), lenTermID)...)
		buf = append(buf, pad(encode(sim), lenSIM)...)
		return buf
	}

	t.Run("Parse 2019 payload", func(t *testing.T) {
		payload := createPayload("Plat2", "Prod2", "Model2", "IMEI2", "TID2", "SIM2")
		reg, err := parseVehicleRegistration(payload)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if reg.PlatformID != "Plat2" {
			t.Errorf("expected Plat2, got %s", reg.PlatformID)
		}
		if reg.TerminalModelType != "Model2" {
			t.Errorf("expected Model2, got %s", reg.TerminalModelType)
		}
	})

	t.Run("Payload too short", func(t *testing.T) {
		payload := []byte{0x01, 0x02}
		if _, err := parseVehicleRegistration(payload); err == nil {
			t.Error("expected error for short payload")
		}
	})
}
