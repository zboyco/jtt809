package server

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/zboyco/jtt809/pkg/jtt809"
)

//go:embed web
var webFS embed.FS

func (g *JT809Gateway) startHTTPServer(ctx context.Context) {
	if g.cfg.HTTPListen == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", g.handleHealth)
	mux.HandleFunc("/api/platforms", g.handlePlatforms)
	mux.HandleFunc("/api/video/request", g.handleVideoRequest)

	// 嵌入的静态文件服务
	webContent, err := fs.Sub(webFS, "web")
	if err != nil {
		slog.Error("failed to load embedded web files", "err", err)
	} else {
		mux.Handle("/ui/", http.StripPrefix("/ui/", http.FileServer(http.FS(webContent))))
	}

	g.httpSrv = &http.Server{
		Addr:    g.cfg.HTTPListen,
		Handler: mux,
	}

	go func() {
		slog.Info("http server listening", "addr", g.cfg.HTTPListen)
		if err := g.httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("http server failed", "err", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.httpSrv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Warn("http server shutdown", "err", err)
		}
	}()
}

func (g *JT809Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, map[string]string{"status": "ok"})
}

func (g *JT809Gateway) handlePlatforms(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, g.store.Snapshots())
}

func (g *JT809Gateway) handleVideoRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	defer r.Body.Close()
	body := io.LimitReader(r.Body, 1<<20)
	var req VideoRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.VehicleColor == 0 {
		req.VehicleColor = jtt809.VehicleColorBlue
	}

	if err := g.RequestVideoStream(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, map[string]string{"status": "sent"})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("write json failed", "err", err)
	}
}
