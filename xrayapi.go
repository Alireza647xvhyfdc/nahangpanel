package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
)

func registerXrayRoutes(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	registerXrayClientRoutes(m, auth)
	registerXraySecRoutes(m, auth)
	registerXrayStatusRoute(m, auth)
	registerXrayShareRoutes(m, auth)
	registerXrayVersionRoutes(m, auth)
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
		if sellerOf(r) != "" {
			type sellerInbound struct {
				Port     int    `json:"port"`
				Protocol string `json:"protocol"`
				Remark   string `json:"remark"`
				Network  string `json:"network,omitempty"`
				Security string `json:"security"`
				Disabled bool   `json:"disabled,omitempty"`
			}
			view := make([]sellerInbound, 0, len(safe))
			for _, in := range safe {
				view = append(view, sellerInbound{Port: in.Port, Protocol: in.Protocol, Remark: in.Remark, Network: in.Network, Security: in.Security, Disabled: in.Disabled})
			}
			reply(w, 200, view)
			return
		}
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
		if s := sellerOf(r); s != "" {
			mine := []Client{}
			for _, c := range st.Clients {
				if c.Owner == s {
					mine = append(mine, c)
				}
			}
			reply(w, 200, mine)
			return
		}
		reply(w, 200, st.Clients)
	}))

	m.HandleFunc("GET /api/xray/link", auth(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		server := q.Get("server")
		if server == "" {
			server = requestServer(r)
		}
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
