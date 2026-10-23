package main

// xrayapi.go: مسیرهای HTTP برای مدیریت inbound و کلاینت Xray.
// احراز هویت و CSRF از همان wrapper ِ auth در main.go گرفته می‌شود.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
)

// registerXrayRoutes را از main.go صدا بزن، قبل از ListenAndServe.
func registerXrayRoutes(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	registerXrayClientRoutes(m, auth)
	registerXraySecRoutes(m, auth)
	registerXrayStatusRoute(m, auth)
	registerXrayShareRoutes(m, auth)
	m.HandleFunc("GET /api/xray/inbounds", auth(func(w http.ResponseWriter, r *http.Request) {
		st, err := loadStore()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		safe := make([]Inbound, 0, len(st.Inbounds))
		for _, in := range st.Inbounds {
			safe = append(safe, redactInbound(in))
		}
		sort.SliceStable(safe, func(i, j int) bool {
			if safe[i].SortOrder != safe[j].SortOrder {
				return safe[i].SortOrder < safe[j].SortOrder
			}
			return safe[i].Port < safe[j].Port
		})
		reply(w, 200, safe)
	}))

	m.HandleFunc("POST /api/xray/inbounds", auth(func(w http.ResponseWriter, r *http.Request) {
		var in Inbound
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&in) != nil {
			reply(w, 400, map[string]string{"error": "ورودی نامعتبر"})
			return
		}
		if err := addInbound(in); err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]string{"ok": "1"})
	}))

	m.HandleFunc("GET /api/xray/clients", auth(func(w http.ResponseWriter, r *http.Request) {
		st, err := loadStore()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, st.Clients)
	}))

	// GET /api/xray/link?server=IP-ایران&name=NAME      (vless، vmess، trojan)
	// GET /api/xray/link?server=IP-ایران&inbound=PORT    (shadowsocks، بدون کلاینت)
	m.HandleFunc("GET /api/xray/link", auth(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		server := q.Get("server")
		if !validServerAddr(server) {
			reply(w, 400, map[string]string{"error": "server باید IP یا نام میزبان معتبر باشد"})
			return
		}
		st, err := loadStore()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}

		if pStr := q.Get("inbound"); pStr != "" {
			port, err := strconv.Atoi(pStr)
			if err != nil {
				reply(w, 400, map[string]string{"error": "inbound باید عدد باشد"})
				return
			}
			for _, in := range st.Inbounds {
				if in.Port == port && in.Protocol == "shadowsocks" && !in.Disabled {
					reply(w, 200, map[string]string{"link": buildLink(nil, in, server)})
					return
				}
			}
			reply(w, 404, map[string]string{"error": "inbound shadowsocks با این پورت پیدا نشد"})
			return
		}

		name := q.Get("name")
		if name == "" {
			reply(w, 400, map[string]string{"error": "name یا inbound الزامی است"})
			return
		}
		for _, c := range st.Clients {
			if c.Name != name {
				continue
			}
			for _, in := range st.Inbounds {
				if c.attachedTo(in.Port) && !in.ExcludeSub && !in.Disabled {
					link := buildLink(&c, in, server)
					if link == "" {
						reply(w, 400, map[string]string{"error": "لینک برای این پروتکل ساخته نشد"})
						return
					}
					resp := map[string]string{"link": link}
					if in.Network == "kcp" {
						resp["note"] = "این inbound روی UDP (mKCP) است و از تانل TCP عبور نمی‌کند. server را IP سرور خارج بگذار و پورت UDP را در فایروال باز کن."
					}
					reply(w, 200, resp)
					return
				}
			}
		}
		reply(w, 404, map[string]string{"error": "کلاینت پیدا نشد"})
	}))
}
