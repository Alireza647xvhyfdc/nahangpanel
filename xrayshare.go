package main

// xrayshare.go: لینک اشتراک (/sub/{token})، شمارش HWID، و فعال‌سازی دوباره‌ی کلاینت.
// توکن اشتراک جداست تا UUID کلاینت هرگز داخل URL نرود.

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

// Device یک دستگاه ثبت‌شده برای کلاینت است (با شناسهٔ HWID که اپ کلاینت می‌فرستد).
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

// newSubToken یک توکن تصادفی و URL-safe می‌سازد.
func newSubToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// admitDevice بررسی می‌کند دستگاه مجاز است و در صورت نیاز ثبتش می‌کند.
// changed برمی‌گرداند که آیا لیست دستگاه‌ها تغییر کرده (برای ذخیره‌سازی).
// HWIDLimit = ۰ یعنی بدون محدودیت دستگاه و هیچ چیزی ثبت نمی‌شود.
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
			if now.Unix()-c.Devices[i].LastSeen >= 60 { // فقط هر دقیقه ذخیره کن
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

// findClientByToken کلاینت را با توکن اشتراک پیدا می‌کند (مقایسهٔ ثابت‌زمان).
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

// ensureSubTokens به کلاینت‌های قدیمی که توکن ندارند یک توکن می‌دهد.
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

// registerXrayShareRoutes مسیرهای اشتراک و مدیریت دستگاه/فعال‌سازی را ثبت می‌کند.
// /sub بدون احراز هویت پنل است؛ امنیتش با توکن تصادفی تأمین می‌شود.
func registerXrayShareRoutes(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	m.HandleFunc("GET /sub/{token}", func(w http.ResponseWriter, r *http.Request) {
		// server: IP سرور ایران (کاربر به آن وصل می‌شود). اگر نبود، میزبان همین درخواست.
		server := r.URL.Query().Get("server")
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

	// POST /api/xray/clients/{name}/devices/reset  -> پاک کردن لیست دستگاه‌ها
	m.HandleFunc("POST /api/xray/clients/{name}/devices/reset", auth(func(w http.ResponseWriter, r *http.Request) {
		xrayMu.Lock()
		defer xrayMu.Unlock()
		st, err := loadStore()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		c := findClientByName(st, r.PathValue("name"))
		if c == nil {
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

	// POST /api/xray/clients/{name}/enable  -> فعال‌سازی دوباره (بعد از قطع خودکار به‌خاطر IP)
	m.HandleFunc("POST /api/xray/clients/{name}/enable", auth(func(w http.ResponseWriter, r *http.Request) {
		xrayMu.Lock()
		defer xrayMu.Unlock()
		st, err := loadStore()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		c := findClientByName(st, r.PathValue("name"))
		if c == nil {
			reply(w, 404, map[string]string{"error": "کلاینت پیدا نشد"})
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

// findClientByName کلاینت را با نام پیدا می‌کند.
func findClientByName(st *Store, name string) *Client {
	for i := range st.Clients {
		if st.Clients[i].Name == name {
			return &st.Clients[i]
		}
	}
	return nil
}

// backupFile فرمت پشتیبان نسخهٔ ۲: تانل‌ها و وضعیت کامل Xray.
// فایل‌های قدیمی (فقط نقشهٔ تانل‌ها) هم در restore پذیرفته می‌شوند.
type backupFile struct {
	Format  string            `json:"format"`
	Version int               `json:"version"`
	Tunnels map[string]Tunnel `json:"tunnels,omitempty"`
	Xray    *Store            `json:"xray,omitempty"`
}

// restoreXrayStore وضعیت Xray را از پشتیبان می‌گذارد. خودش xrayMu را می‌گیرد.
// اگر کانفیگ نامعتبر باشد، هیچ‌چیز تغییر نمی‌کند؛ اگر ذخیره ناموفق باشد، کانفیگ قبلی برمی‌گردد.
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
	if err := writeXrayConfig(in); err != nil { // xray -test قبل از ذخیره
		return 0, err
	}
	if err := saveStore(in); err != nil {
		_ = writeXrayConfig(old)
		return 0, err
	}
	return len(in.Clients), nil
}
