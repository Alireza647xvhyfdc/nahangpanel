package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	accessLogPath     = "/var/log/xray/access.log"
	ipWindow          = 10 * time.Minute
	ipCheckEvery      = 30 * time.Second
	accessLogMaxBytes = 100 << 20
	accessReadMax     = 16 << 20
)

var reAccess = regexp.MustCompile(`^\S+ \S+ (?:from )?(\[[^\]]+\]|[^\s\[\]]+):\d+ accepted .*email: (\S+)\s*$`)

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

type ipTracker struct {
	mu     sync.Mutex
	offset int64
	seen   map[string]map[string]time.Time
}

var ipMon = &ipTracker{seen: map[string]map[string]time.Time{}}

func (t *ipTracker) observe(client, ip string, now time.Time) {
	if ip == "127.0.0.1" || ip == "::1" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.seen[client] == nil {
		t.seen[client] = map[string]time.Time{}
	}
	t.seen[client][ip] = now
}

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
	if info.Size() < off {
		off = 0
	}
	ipMon.mu.Unlock()

	if info.Size()-off > accessReadMax {
		off = info.Size() - accessReadMax
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return err
	}

	br := bufio.NewReader(f)
	consumed := off
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
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
			if err := enforceSellers(now); err != nil {
				fmt.Println("بررسی محدودیت فروشنده:", err)
			}
		}
	}()
}

func ensureAccessLogDir() error {
	dir := filepath.Dir(accessLogPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("ساخت پوشهٔ لاگ Xray: %w", err)
	}
	f, err := os.OpenFile(accessLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("ساخت فایل لاگ Xray: %w", err)
	}
	f.Close()
	if err := chownForXray(dir, accessLogPath); err != nil {
		return err
	}
	return nil
}

func chownForXray(dir, file string) error {
	out, err := exec.Command("systemctl", "show", "xray", "-p", "User", "--value").Output()
	if err != nil {
		return nil
	}
	name := strings.TrimSpace(string(out))
	if name == "" || name == "root" {
		return nil
	}
	u, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("کاربر %q که xray با آن اجرا می‌شود پیدا نشد: %w", name, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.Chown(dir, uid, gid); err != nil {
		return fmt.Errorf("تغییر مالکیت پوشهٔ لاگ: %w", err)
	}
	if err := os.Chown(file, uid, gid); err != nil {
		return fmt.Errorf("تغییر مالکیت فایل لاگ: %w", err)
	}
	return nil
}
