package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func bindInbound(t *Tunnel) string {
	if t.Inbound == 0 {
		if t.Role == "client" {
			t.Ports = nil
		}
		return ""
	}
	if t.Role != "client" {
		return "اتصال تانل‌ها به اینباند ها فقط روی سرور خارج ممکن است"
	}
	st, err := loadStore()
	if err != nil {
		return "خواندن لیست اینباندها ناموفق بود"
	}
	for _, in := range st.Inbounds {
		if in.Port == t.Inbound {
			t.Ports = []string{strconv.Itoa(in.Port)}
			return ""
		}
	}
	return fmt.Sprintf("اینباندی با پورت %d روی این سرور پیدا نشد", t.Inbound)
}

func inboundRemarks() map[int]string {
	out := map[int]string{}
	st, err := loadStore()
	if err != nil {
		return out
	}
	for _, in := range st.Inbounds {
		name := in.Remark
		if name == "" {
			name = in.Protocol
		}
		out[in.Port] = name
	}
	return out
}

func registerTunnelBindRoute(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	m.HandleFunc("POST /api/tunnels/{name}/bind", auth(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Inbound int `json:"inbound"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req) != nil || req.Inbound < 0 || req.Inbound > 65535 {
			bad(w, "ورودی نامعتبر")
			return
		}
		mu.Lock()
		defer mu.Unlock()
		old, ok := tunnels[r.PathValue("name")]
		if !ok {
			reply(w, 404, map[string]string{"error": "تانل پیدا نشد"})
			return
		}
		t := old
		t.Inbound = req.Inbound
		if t.Role == "client" && t.Inbound != 0 && t.Allow == "" {
			if h, _, err := net.SplitHostPort(t.Addr); err == nil {
				t.Allow = h
			}
		}
		if e := bindInbound(&t); e != "" {
			bad(w, e)
			return
		}
		if e := validate(&t); e != "" {
			bad(w, e)
			return
		}
		if strings.Join(t.Ports, ",") != strings.Join(old.Ports, ",") {
			if err := create(t); err != nil {
				reply(w, 500, map[string]string{"error": err.Error()})
				return
			}
		} else {
			tunnels[t.Name] = t
			save()
		}
		reply(w, 200, map[string]string{"ok": "1"})
	}))
}

func irServerAddr() string {
	mu.Lock()
	defer mu.Unlock()
	best := ""
	for _, t := range tunnels {
		if t.Role != "client" {
			continue
		}
		host, _, err := net.SplitHostPort(t.Addr)
		if err != nil || host == "" {
			continue
		}
		if t.Inbound != 0 {
			return host
		}
		if best == "" {
			best = host
		}
	}
	return best
}
