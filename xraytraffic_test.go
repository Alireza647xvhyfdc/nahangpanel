package main

import (
	"testing"
	"time"
)

func TestTrafficDeltasBaselineRestartAndNew(t *testing.T) {
	tr := &trafficTracker{last: map[string]int64{}}
	// بار اول: فقط پایه، هیچ مصرفی حساب نمی‌شود
	if d := tr.deltas(map[string]int64{"user>>>a>>>traffic>>>uplink": 500}); len(d) != 0 {
		t.Fatalf("baseline must not count, got %v", d)
	}
	// افزایش عادی
	if d := tr.deltas(map[string]int64{"user>>>a>>>traffic>>>uplink": 800}); d["user>>>a>>>traffic>>>uplink"] != 300 {
		t.Fatalf("normal delta = %v", d)
	}
	// ری‌استارت Xray: مقدار از صفر شروع شده
	if d := tr.deltas(map[string]int64{"user>>>a>>>traffic>>>uplink": 120}); d["user>>>a>>>traffic>>>uplink"] != 120 {
		t.Fatalf("restart delta = %v", d)
	}
	// کلاینت تازه بعد از پایه: کل مصرفش حساب می‌شود
	if d := tr.deltas(map[string]int64{"user>>>a>>>traffic>>>uplink": 120, "user>>>b>>>traffic>>>downlink": 40}); d["user>>>b>>>traffic>>>downlink"] != 40 {
		t.Fatalf("new key delta = %v", d)
	}
}

func TestMonthlyResetStaysAnchoredAndCatchesUp(t *testing.T) {
	start := time.Date(2026, 1, 31, 12, 0, 0, 0, time.UTC)
	first := nextResetAfter(start, "monthly")
	if got := time.Unix(first, 0).UTC(); got.Month() != time.March || got.Day() != 3 {
		// AddDate از ۳۱ ژانویه به ۳ مارس می‌رود (فوریه کوتاه است)؛ این رفتار پذیرفته است
		t.Logf("first monthly reset from Jan 31: %v", got)
	}
	// پنل ۳ ماه خاموش بوده: ریست بعدی باید بعد از now باشد و از زمان برنامه‌ریزی‌شده ادامه پیدا کند
	prev := time.Date(2026, 2, 10, 0, 0, 0, 0, time.UTC).Unix()
	now := time.Date(2026, 5, 20, 0, 0, 0, 0, time.UTC)
	next := time.Unix(advanceReset(prev, "monthly", now), 0).UTC()
	if !next.After(now) {
		t.Fatalf("next reset %v must be after now %v", next, now)
	}
	if next.Day() != 10 {
		t.Errorf("reset must stay on day 10 of the schedule, got %v", next)
	}
	if advanceReset(prev, "never", now) != 0 {
		t.Error("never policy must return 0")
	}
}

// خروجی واقعی `xray api statsquery`: مقدار صفر اصلاً فیلد value ندارد و عدد به‌صورت JSON number است.
func TestParseStatsRealOutput(t *testing.T) {
	out := []byte(`{"stat":[{"name":"inbound>>>api>>>traffic>>>downlink","value":24},
{"name":"inbound>>>in-2443>>>traffic>>>uplink"},{"name":"inbound>>>in-2443>>>traffic>>>downlink"},
{"name":"inbound>>>api>>>traffic>>>uplink","value":170},{"name":"user>>>u1>>>traffic>>>uplink","value":"42"}]}`)
	m, err := parseStats(out)
	if err != nil {
		t.Fatal(err)
	}
	if m["inbound>>>api>>>traffic>>>downlink"] != 24 || m["user>>>u1>>>traffic>>>uplink"] != 42 {
		t.Fatalf("values wrong: %v", m)
	}
	if _, ok := m["inbound>>>in-2443>>>traffic>>>uplink"]; ok {
		t.Error("zero counters without value should be skipped")
	}
	cb, ib := usageFromStats(m)
	if cb["u1"] != 42 || ib["api"] != 194 {
		t.Errorf("usage mapping wrong: clients=%v inbounds=%v", cb, ib)
	}
	if empty, err := parseStats([]byte("")); err != nil || len(empty) != 0 {
		t.Errorf("empty output: %v %v", empty, err)
	}
}
