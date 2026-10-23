package main

// xraystatus.go: وضعیت Xray برای نمایش در صفحه‌ی اصلی.

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type xrayStatus struct {
	Installed      bool   `json:"installed"`
	Version        string `json:"version"`
	Service        string `json:"service"` // active | inactive | failed | ...
	Inbounds       int    `json:"inbounds"`
	ActiveInbounds int    `json:"active_inbounds"`
	Clients        int    `json:"clients"`
	ActiveClients  int    `json:"active_clients"`
}

var xrayVersionCache struct {
	mu  sync.Mutex
	val string
}

// xrayVersion نسخه‌ی Xray را یک بار می‌خواند و نگه می‌دارد.
func xrayVersion() string {
	xrayVersionCache.mu.Lock()
	defer xrayVersionCache.mu.Unlock()
	if xrayVersionCache.val != "" {
		return xrayVersionCache.val
	}
	out, err := runXray("version")
	if err != nil {
		return ""
	}
	line := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if len(line) > 80 {
		line = line[:80]
	}
	xrayVersionCache.val = line
	return line
}

// xrayServiceState وضعیت سرویس systemd با نام xray را برمی‌گرداند.
func xrayServiceState() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "systemctl", "is-active", "xray").CombinedOutput()
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "unknown"
	}
	return s
}

func currentXrayStatus() xrayStatus {
	var s xrayStatus
	if _, err := os.Stat(xrayBin); err == nil {
		s.Installed = true
		s.Version = xrayVersion()
	}
	s.Service = xrayServiceState()
	if st, err := loadStore(); err == nil {
		now := time.Now()
		for _, in := range st.Inbounds {
			s.Inbounds++
			if !in.Disabled {
				s.ActiveInbounds++
			}
		}
		for _, c := range st.Clients {
			s.Clients++
			if clientUsable(c, now) {
				s.ActiveClients++
			}
		}
	}
	return s
}

// registerXrayStatusRoute مسیر GET /api/xray/status را ثبت می‌کند.
func registerXrayStatusRoute(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	m.HandleFunc("GET /api/xray/status", auth(func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, currentXrayStatus())
	}))
}
