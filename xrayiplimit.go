package main

// xrayiplimit.go: شمارش IP مبدأ هر کلاینت از access log خود Xray.
// اگر تعداد IPهای متمایز در پنجرهٔ زمانی از IP Limit بیشتر شود، کلاینت خودکار غیرفعال می‌شود
// (با دکمهٔ «فعال کردن» در پنل دوباره روشن می‌شود).
//
// محدودیت مهم: اگر ترافیک از تانل پنل عبور کند، Xray فقط 127.0.0.1 را به‌عنوان مبدأ می‌بیند
// و این شمارش برای آن کاربران کار نمی‌کند. این بخش فقط اتصال مستقیم به سرور خارج را می‌شمارد.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	accessLogPath     = "/var/log/xray/access.log"
	ipWindow          = 10 * time.Minute
	ipCheckEvery      = 30 * time.Second
	accessLogMaxBytes = 100 << 20 // بعد از این حجم فایل خالی می‌شود
	accessReadMax     = 16 << 20  // سقف خواندن در هر بار
)

// خط نمونه: 2026/10/23 18:00:00 [from] 1.2.3.4:5678 accepted tcp:example.com:443 [in-443 >> direct] email: name
var reAccess = regexp.MustCompile(`^\S+ \S+ (?:from )?(\[[^\]]+\]|[^\s\[\]]+):\d+ accepted .*email: (\S+)\s*$`)

// parseAccessLine IP مبدأ و نام کلاینت را از یک خط access log می‌گیرد.
func parseAccessLine(line string) (ip, email string, ok bool) {
	m := reAccess.FindStringSubmatch(line)
	if m == nil {
		return "", "", false
	}
	ip = strings.Trim(m[1], "[]")
	if net.ParseIP(ip) == nil {
		return "", "", false
	}
	return ip, m[2], true
}

// ipTracker آخرین زمان دیده‌شدن هر IP برای هر کلاینت را نگه می‌دارد.
type ipTracker struct {
	mu     sync.Mutex
	offset int64
	seen   map[string]map[string]time.Time // client -> ip -> last seen
}

var ipMon = &ipTracker{seen: map[string]map[string]time.Time{}}

func (t *ipTracker) observe(client, ip string, now time.Time) {
	if ip == "127.0.0.1" || ip == "::1" {
		return // اتصال داخلی تانل، IP کاربر نیست
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen[client] == nil {
		t.seen[client] = map[string]time.Time{}
	}
	t.seen[client][ip] = now
}

// distinct تعداد IPهای متمایز داخل پنجره را برمی‌گرداند و قدیمی‌ها را پاک می‌کند.
func (t *ipTracker) distinct(client string, now time.Time) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for ip, last := range t.seen[client] {
		if now.Sub(last) > ipWindow {
			delete(t.seen[client], ip)
			continue
		}
		n++
	}
	return n
}

func (t *ipTracker) reset(client string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.seen, client)
}

// ingestAccessLog خطوط جدید access log را می‌خواند و IPها را ثبت می‌کند.
func ingestAccessLog(now time.Time) error {
	f, err := os.Open(accessLogPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}

	ipMon.mu.Lock()
	off := ipMon.offset
	if info.Size() < off { // فایل چرخیده یا خالی شده
		off = 0
	}
	ipMon.mu.Unlock()

	if info.Size()-off > accessReadMax {
		off = info.Size() - accessReadMax // خطوط خیلی قدیمی را رد کن
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return err
	}

	// فقط خطوط کامل (تا آخرین \n) پردازش می‌شوند.
	br := bufio.NewReader(f)
	consumed := off
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break // خط ناقص آخر فایل را بعداً می‌خوانیم
		}
		consumed += int64(len(line))
		if ip, email, ok := parseAccessLine(strings.TrimRight(line, "\r\n")); ok {
			ipMon.observe(email, ip, now)
		}
	}

	ipMon.mu.Lock()
	ipMon.offset = consumed
	ipMon.mu.Unlock()

	if info.Size() > accessLogMaxBytes {
		_ = os.Truncate(accessLogPath, 0)
		ipMon.mu.Lock()
		ipMon.offset = 0
		ipMon.mu.Unlock()
	}
	return nil
}

// checkIPLimits کلاینت‌هایی که از IP Limit گذشته‌اند را غیرفعال می‌کند.
func checkIPLimits(now time.Time) error {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	st, err := loadStore()
	if err != nil {
		return err
	}
	changed := false
	var violated []string
	for i := range st.Clients {
		c := &st.Clients[i]
		if c.IPLimit <= 0 || !c.Enabled {
			continue
		}
		if n := ipMon.distinct(c.Name, now); n > c.IPLimit {
			c.Enabled = false
			c.DisabledReason = fmt.Sprintf("ip_limit: %d IP به جای %d", n, c.IPLimit)
			changed = true
			violated = append(violated, c.Name)
		}
	}
	if !changed {
		return nil
	}
	if err := writeXrayConfig(st); err != nil {
		return err
	}
	if err := saveStore(st); err != nil {
		return err
	}
	for _, name := range violated {
		ipMon.reset(name)
		go notify(fmt.Sprintf("⚠️ کلاینت %s به‌خاطر بیش از حد IP غیرفعال شد", name))
	}
	return nil
}

// startXrayMonitor مهاجرت توکن‌ها را انجام می‌دهد و حلقهٔ بررسی IP را روشن می‌کند.
func startXrayMonitor() {
	if err := ensureSubTokens(); err != nil {
		fmt.Println("ساخت توکن اشتراک ناموفق:", err)
	}
	if err := ensureStatsConfig(); err != nil {
		fmt.Println("به‌روزرسانی کانفیگ آمار:", err)
	}
	go func() {
		t := time.NewTicker(ipCheckEvery)
		defer t.Stop()
		for now := range t.C {
			if err := ingestAccessLog(now); err != nil {
				fmt.Println("خواندن access log:", err)
			}
			if err := checkIPLimits(now); err != nil {
				fmt.Println("بررسی IP Limit:", err)
			}
			if err := tickTraffic(now); err != nil {
				fmt.Println("بررسی ترافیک:", err)
			}
		}
	}()
}

// ensureAccessLogDir پوشهٔ access log را می‌سازد تا Xray بتواند فایل را بنویسد.
func ensureAccessLogDir() error {
	return os.MkdirAll(filepath.Dir(accessLogPath), 0o755)
}
