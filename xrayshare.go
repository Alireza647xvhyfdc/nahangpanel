package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Device struct {
	HWID      string `json:"hwid"`
	FirstSeen int64  `json:"first_seen"`
	LastSeen  int64  `json:"last_seen"`
}

var (
	errHWIDRequired = errors.New("این لینک نیاز به HWID دارد؛ اپ کلاینت باید هدر x-hwid را بفرستد")
	errHWIDInvalid  = errors.New("HWID نامعتبر است")
	errDeviceLimit  = errors.New("تعداد دستگاه‌های این کلاینت به حد مجاز رسیده است")
	reHWID          = regexp.MustCompile(`^[A-Za-z0-9_\-:.]{4,128}$`)
)

func requestServer(r *http.Request) string {
	if s := irServerAddr(); s != "" {
		return s
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		return r.Host
	}
	return host
}

func newSubToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func admitDevice(c *Client, hwid string, now time.Time) (changed bool, err error) {
	if c.HWIDLimit <= 0 {
		return false, nil
	}
	if hwid == "" {
		return false, errHWIDRequired
	}
	if !reHWID.MatchString(hwid) {
		return false, errHWIDInvalid
	}
	for i := range c.Devices {
		if c.Devices[i].HWID == hwid {
			if now.Unix()-c.Devices[i].LastSeen >= 60 {
				c.Devices[i].LastSeen = now.Unix()
				return true, nil
			}
			return false, nil
		}
	}
	if len(c.Devices) >= c.HWIDLimit {
		return false, errDeviceLimit
	}
	c.Devices = append(c.Devices, Device{HWID: hwid, FirstSeen: now.Unix(), LastSeen: now.Unix()})
	return true, nil
}

func findClientByToken(st *Store, token string) *Client {
	if token == "" {
		return nil
	}
	for i := range st.Clients {
		if subtle.ConstantTimeCompare([]byte(st.Clients[i].SubToken), []byte(token)) == 1 {
			return &st.Clients[i]
		}
	}
	return nil
}

func ensureSubTokens() error {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	st, err := loadStore()
	if err != nil {
		return err
	}
	changed := false
	for i := range st.Clients {
		if st.Clients[i].SubToken == "" {
			t, err := newSubToken()
			if err != nil {
				return err
			}
			st.Clients[i].SubToken = t
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return saveStore(st)
}

func registerXrayShareRoutes(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	m.HandleFunc("GET /sub/{token}", func(w http.ResponseWriter, r *http.Request) {
		server := r.URL.Query().Get("server")
		if server == "" {
			server = irServerAddr()
		}
		if server == "" {
			host, _, err := net.SplitHostPort(r.Host)
			if err != nil {
				host = r.Host
			}
			server = host
		}
		if !validServerAddr(server) {
			http.Error(w, "server نامعتبر است", http.StatusBadRequest)
			return
		}

		xrayMu.Lock()
		defer xrayMu.Unlock()
		st, err := loadStore()
		if err != nil {
			http.Error(w, "خطای داخلی", http.StatusInternalServerError)
			return
		}
		c := findClientByToken(st, r.PathValue("token"))
		if c == nil {
			http.Error(w, "یافت نشد", http.StatusNotFound)
			return
		}
		now := time.Now()
		if !clientUsable(*c, now) {
			http.Error(w, "غیرفعال یا منقضی", http.StatusForbidden)
			return
		}
		changed, err := admitDevice(c, strings.TrimSpace(r.Header.Get("x-hwid")), now)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		if changed {
			if err := saveStore(st); err != nil {
				http.Error(w, "خطای ذخیره‌سازی", http.StatusInternalServerError)
				return
			}
		}

		var links []string
		for _, in := range st.Inbounds {
			if !c.attachedTo(in.Port) || in.ExcludeSub || in.Disabled {
				continue
			}
			if l := buildLink(c, in, server); l != "" {
				links = append(links, l)
			}
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))))
	})

	m.HandleFunc("POST /api/xray/clients/{name}/devices/reset", auth(func(w http.ResponseWriter, r *http.Request) {
		xrayMu.Lock()
		defer xrayMu.Unlock()
		st, err := loadStore()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		c := findClientByName(st, r.PathValue("name"))
		if c == nil || !ownsClient(r, c) {
			reply(w, 404, map[string]string{"error": "کلاینت پیدا نشد"})
			return
		}
		c.Devices = nil
		if err := saveStore(st); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]string{"ok": "1"})
	}))

	m.HandleFunc("POST /api/xray/clients/{name}/enable", auth(func(w http.ResponseWriter, r *http.Request) {
		xrayMu.Lock()
		defer xrayMu.Unlock()
		st, err := loadStore()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		c := findClientByName(st, r.PathValue("name"))
		if c == nil || !ownsClient(r, c) {
			reply(w, 404, map[string]string{"error": "کلاینت پیدا نشد"})
			return
		}
		if c.DisabledReason == sellerLimitReason {
			reply(w, 403, map[string]string{"error": errSellerLimited.Error()})
			return
		}
		c.Enabled = true
		c.DisabledReason = ""
		ipMon.reset(c.Name)
		if err := writeXrayConfig(st); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := saveStore(st); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]string{"ok": "1"})
	}))
}

func findClientByName(st *Store, name string) *Client {
	for i := range st.Clients {
		if st.Clients[i].Name == name {
			return &st.Clients[i]
		}
	}
	return nil
}

type backupFile struct {
	Format  string            `json:"format"`
	Version int               `json:"version"`
	Tunnels map[string]Tunnel `json:"tunnels,omitempty"`
	Xray    *Store            `json:"xray,omitempty"`
}

func restoreXrayStore(in *Store) (int, error) {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	for _, ib := range in.Inbounds {
		if e := validateInbound(ib); e != "" {
			return 0, fmt.Errorf("inbound پورت %d: %s", ib.Port, e)
		}
	}
	seen := map[string]bool{}
	for i := range in.Clients {
		c := &in.Clients[i]
		if !reRemark.MatchString(c.Name) {
			return 0, fmt.Errorf("نام کلاینت %q نامعتبر است", c.Name)
		}
		if seen[c.Name] {
			return 0, fmt.Errorf("نام کلاینت %q تکراری است", c.Name)
		}
		seen[c.Name] = true
		if !reUUID.MatchString(c.ID) {
			return 0, fmt.Errorf("UUID کلاینت %q نامعتبر است", c.Name)
		}
		if c.SubToken == "" {
			t, err := newSubToken()
			if err != nil {
				return 0, err
			}
			c.SubToken = t
		}
	}
	old, err := loadStore()
	if err != nil {
		return 0, err
	}
	if err := writeXrayConfig(in); err != nil {
		return 0, err
	}
	if err := saveStore(in); err != nil {
		_ = writeXrayConfig(old)
		return 0, err
	}
	return len(in.Clients), nil
}
