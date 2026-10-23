package main

// xraytraffic.go: مصرف ترافیک کلاینت و inbound از API آمار Xray و اجرای قوانین:
//   - Traffic Limit (کلاینت و inbound Total Flow): رسیدن به سقف → غیرفعال
//   - Traffic Reset (daily/weekly/monthly): در زمان ریست، مصرف صفر و در صورت غیرفعال‌بودن به‌خاطر حجم، فعال
//   - انقضا: کلاینت منقضی از کانفیگ خارج می‌شود (قبلاً فقط موقع ساخت کانفیگ بررسی می‌شد)
//   - Auto renewal: با رسیدن به انقضا، به اندازهٔ دورهٔ اولیه تمدید و حجم صفر می‌شود
//   - Start after first use: انقضا از اولین ترافیک کلاینت شروع می‌شود
//   - Inbound Expires: پس از زمان انقضا inbound غیرفعال می‌شود
//
// نکته: هر بار که آمار خوانده می‌شود با -reset صفر می‌شود و مقدار در Store جمع می‌شود.
// اگر Xray بین دو بررسی ری‌استارت شود، مصرف همان بازه (حداکثر ۳۰ ثانیه) از دست می‌رود.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	xrayAPIPort   = 10085
	xrayAPIServer = "127.0.0.1:10085"
	bytesPerGB    = int64(1) << 30
)

// addPeriod یک دوره را به زمان from اضافه می‌کند. ریست ماهانه روی همان روز ماه می‌ماند.
func addPeriod(from time.Time, policy string) time.Time {
	switch policy {
	case "daily":
		return from.Add(24 * time.Hour)
	case "weekly":
		return from.Add(7 * 24 * time.Hour)
	case "monthly":
		return from.AddDate(0, 1, 0)
	}
	return time.Time{}
}

// nextResetAfter اولین زمان ریست را از لحظهٔ now می‌دهد (برای کلاینت تازه). never یا خالی یعنی ۰.
func nextResetAfter(now time.Time, policy string) int64 {
	t := addPeriod(now, policy)
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// advanceReset زمان ریست را جلو می‌برد تا از now بزرگ‌تر شود، بدون اینکه از برنامه عقب بیفتد.
// اگر پنل چند دوره خاموش بوده باشد، همه را طی می‌کند تا ریست بعدی درست باشد.
func advanceReset(prev int64, policy string, now time.Time) int64 {
	if addPeriod(now, policy).IsZero() {
		return 0
	}
	if prev <= 0 {
		return nextResetAfter(now, policy)
	}
	t := time.Unix(prev, 0)
	for i := 0; !t.After(now) && i < 10000; i++ {
		t = addPeriod(t, policy)
	}
	return t.Unix()
}

// parseStats خروجی `xray api statsquery` را به map نام→مقدار تبدیل می‌کند.
// Xray مقدار int64 را در JSON گاهی به‌صورت رشته می‌دهد؛ هر دو پشتیبانی می‌شوند.
func parseStats(out []byte) (map[string]int64, error) {
	res := map[string]int64{}
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return res, nil
	}
	var resp struct {
		Stat []struct {
			Name  string          `json:"name"`
			Value json.RawMessage `json:"value"`
		} `json:"stat"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		return nil, fmt.Errorf("خروجی آمار نامعتبر: %w", err)
	}
	for _, s := range resp.Stat {
		raw := strings.Trim(string(s.Value), `" `)
		if raw == "" || raw == "null" {
			continue
		}
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("مقدار آمار نامعتبر برای %s: %w", s.Name, err)
		}
		res[s.Name] += v
	}
	return res, nil
}

// usageFromStats نام‌های آمار را به مصرف کلاینت و inbound تبدیل می‌کند.
// user>>>EMAIL>>>traffic>>>uplink|downlink و inbound>>>TAG>>>traffic>>>uplink|downlink
func usageFromStats(stats map[string]int64) (clients, inbounds map[string]int64) {
	clients = map[string]int64{}
	inbounds = map[string]int64{}
	for name, v := range stats {
		p := strings.Split(name, ">>>")
		if len(p) != 4 || p[2] != "traffic" {
			continue
		}
		switch p[0] {
		case "user":
			clients[p[1]] += v
		case "inbound":
			inbounds[p[1]] += v
		}
	}
	return clients, inbounds
}

// readXrayStats آمار تجمعی Xray را می‌خواند. عمداً -reset استفاده نمی‌شود:
// اگر Xray بین دو بررسی ری‌استارت شود، مقدار صفرشده از دست می‌رفت.
func readXrayStats() (map[string]int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, xrayBin, "api", "statsquery", "--server="+xrayAPIServer).Output()
	if err != nil {
		return nil, fmt.Errorf("statsquery: %w", err)
	}
	return parseStats(out)
}

// applyLimits همهٔ قوانین مصرف، انقضا و ریست را روی Store اعمال می‌کند.
// اگر کانفیگ Xray با وضعیت جدید فرق داشته باشد، بازنویسی و ریستارت می‌شود.
func applyLimits(now time.Time, clientBytes, inboundBytes map[string]int64) error {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	st, err := loadStore()
	if err != nil {
		return err
	}
	nowU := now.Unix()
	var notes []string

	for i := range st.Clients {
		c := &st.Clients[i]
		if n := clientBytes[c.Name]; n > 0 {
			c.UsedBytes += n
			if c.StartAfterFirstUse && c.FirstUseAt == 0 {
				c.FirstUseAt = nowU
				if c.Period > 0 {
					c.Expire = nowU + c.Period
				}
			}
		}
		// Auto renewal: پس از انقضا به اندازهٔ دوره تمدید و حجم صفر می‌شود
		if c.AutoRenew && c.Period > 0 && c.Expire > 0 && nowU > c.Expire {
			c.Expire = nowU + c.Period
			c.UsedBytes = 0
			if c.DisabledReason == "traffic_limit" {
				c.Enabled, c.DisabledReason = true, ""
			}
		}
		// Traffic reset دوره‌ای
		if c.NextReset > 0 && nowU >= c.NextReset {
			c.UsedBytes = 0
			c.NextReset = advanceReset(c.NextReset, c.TrafficReset, now)
			if c.DisabledReason == "traffic_limit" {
				c.Enabled, c.DisabledReason = true, ""
			}
		}
		// سقف حجم
		if c.LimitGB > 0 && c.Enabled && c.UsedBytes >= int64(c.LimitGB)*bytesPerGB {
			c.Enabled = false
			c.DisabledReason = "traffic_limit"
			notes = append(notes, fmt.Sprintf("کلاینت %s به‌خاطر رسیدن به سقف حجم غیرفعال شد", c.Name))
		}
	}

	for i := range st.Inbounds {
		in := &st.Inbounds[i]
		if n := inboundBytes[fmt.Sprintf("in-%d", in.Port)]; n > 0 {
			in.UsedBytes += n
		}
		if in.TrafficReset == "" {
			in.TrafficReset = "never"
		}
		if in.NextReset > 0 && nowU >= in.NextReset {
			in.UsedBytes = 0
			in.NextReset = advanceReset(in.NextReset, in.TrafficReset, now)
			if in.DisabledReason == "traffic_limit" {
				in.Disabled, in.DisabledReason = false, ""
			}
		}
		if in.TotalFlow > 0 && !in.Disabled && in.UsedBytes >= in.TotalFlow {
			in.Disabled = true
			in.DisabledReason = "traffic_limit"
			notes = append(notes, fmt.Sprintf("inbound پورت %d به‌خاطر رسیدن به Total Flow غیرفعال شد", in.Port))
		}
		if in.Expires > 0 && !in.Disabled && nowU > in.Expires {
			in.Disabled = true
			in.DisabledReason = "expired"
			notes = append(notes, fmt.Sprintf("inbound پورت %d منقضی شد", in.Port))
		}
	}

	if err := saveStore(st); err != nil {
		return err
	}
	if err := syncXrayConfig(st); err != nil {
		return err
	}
	for _, n := range notes {
		go notify("⚠️ " + n)
	}
	return nil
}

// syncXrayConfig فقط وقتی کانفیگ را بازنویسی می‌کند که با فایل فعلی فرق داشته باشد.
// این باعث می‌شود کلاینت‌های منقضی‌شده هم خودکار از Xray حذف شوند.
func syncXrayConfig(st *Store) error {
	desired, err := buildXrayJSON(st)
	if err != nil {
		return err
	}
	current, err := os.ReadFile(xrayConfigPath)
	if err == nil && bytes.Equal(current, desired) {
		return nil
	}
	return writeXrayConfig(st)
}

// trafficTracker آخرین مقدار تجمعی دیده‌شده را نگه می‌دارد تا مصرف جدید حساب شود.
type trafficTracker struct {
	mu       sync.Mutex
	baseline bool
	last     map[string]int64
}

var traffic = &trafficTracker{last: map[string]int64{}}

// deltas اختلاف مقادیر تجمعی با بررسی قبلی را برمی‌گرداند.
// بار اول فقط پایه را می‌گذارد (مصرف قبل از شروع پنل حساب نمی‌شود، تا دوباره‌شماری نشود).
// اگر مقدار کم شده باشد، یعنی Xray ری‌استارت شده و مقدار فعلی از صفر شروع شده است.
func (t *trafficTracker) deltas(cur map[string]int64) map[string]int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]int64{}
	first := !t.baseline
	for name, v := range cur {
		prev, seen := t.last[name]
		switch {
		case first:
			// پایه: چیزی اضافه نمی‌شود
		case !seen:
			out[name] = v // کلاینت یا inbound تازه: مصرفش از صفر شروع شده
		case v >= prev:
			out[name] = v - prev
		default:
			out[name] = v // ری‌استارت Xray
		}
		t.last[name] = v
	}
	t.baseline = true
	return out
}

// tickTraffic یک بار آمار را می‌خواند و قوانین را اجرا می‌کند.
// اگر آمار در دسترس نباشد (مثلاً Xray خاموش است) همان بار رد می‌شود تا کانفیگ بی‌دلیل ریستارت نشود.
func tickTraffic(now time.Time) error {
	stats, err := readXrayStats()
	if err != nil {
		return err
	}
	cb, ib := usageFromStats(traffic.deltas(stats))
	return applyLimits(now, cb, ib)
}

// ensureStatsConfig اگر کانفیگ قدیمی بدون API آمار است، یک بار بازنویسی می‌کند.
func ensureStatsConfig() error {
	cur, err := os.ReadFile(xrayConfigPath)
	if err != nil || bytes.Contains(cur, []byte("StatsService")) {
		return nil // فایلی نیست یا قبلاً درست است
	}
	xrayMu.Lock()
	defer xrayMu.Unlock()
	st, err := loadStore()
	if err != nil {
		return err
	}
	return writeXrayConfig(st)
}
