package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseAccessLine(t *testing.T) {
	ok := []struct{ line, ip, email string }{
		{"2026/10/23 18:00:00 1.2.3.4:5678 accepted tcp:example.com:443 [in-443 >> direct] email: alice", "1.2.3.4", "alice"},
		{"2026/10/23 18:00:00 from 1.2.3.4:5678 accepted tcp:example.com:443 [in-443 >> direct] email: bob", "1.2.3.4", "bob"},
		{"2026/10/23 18:00:00 [2001:db8::1]:5678 accepted udp:x:53 [in >> direct] email: carol", "2001:db8::1", "carol"},
	}
	for _, c := range ok {
		ip, email, good := parseAccessLine(c.line)
		if !good || ip != c.ip || email != c.email {
			t.Errorf("parse %q = (%q,%q,%v), want (%q,%q)", c.line, ip, email, good, c.ip, c.email)
		}
	}
	bad := []string{
		"2026/10/23 18:00:00 1.2.3.4:5678 accepted tcp:example.com:443 [in-443 >> direct]",
		"2026/10/23 18:00:00 1.2.3.4:5678 rejected tcp:x:443 email: dave",
		"garbage",
		"",
	}
	for _, l := range bad {
		if _, _, good := parseAccessLine(l); good {
			t.Errorf("expected reject for %q", l)
		}
	}
}

func TestAdmitDeviceLimits(t *testing.T) {
	now := time.Now()
	c := &Client{Name: "a", HWIDLimit: 0}
	if _, err := admitDevice(c, "", now); err != nil {
		t.Fatalf("limit 0 must allow everything, got %v", err)
	}

	c = &Client{Name: "a", HWIDLimit: 2}
	if _, err := admitDevice(c, "", now); err != errHWIDRequired {
		t.Errorf("missing hwid: got %v", err)
	}
	if _, err := admitDevice(c, "bad hwid!!", now); err != errHWIDInvalid {
		t.Errorf("invalid hwid: got %v", err)
	}
	if ch, err := admitDevice(c, "device-one", now); err != nil || !ch {
		t.Fatalf("first device: changed=%v err=%v", ch, err)
	}
	if _, err := admitDevice(c, "device-two", now); err != nil {
		t.Fatalf("second device: %v", err)
	}
	if _, err := admitDevice(c, "device-three", now); err != errDeviceLimit {
		t.Errorf("third device should hit limit, got %v", err)
	}
	if _, err := admitDevice(c, "device-one", now.Add(time.Hour)); err != nil {
		t.Errorf("known device must stay allowed: %v", err)
	}
}

func TestIPTrackerWindowAndLoopback(t *testing.T) {
	tr := &ipTracker{seen: map[string]map[string]time.Time{}}
	now := time.Now()
	tr.observe("u", "127.0.0.1", now)
	tr.observe("u", "1.1.1.1", now)
	tr.observe("u", "2.2.2.2", now.Add(-time.Hour))
	tr.observe("u", "3.3.3.3", now.Add(-time.Minute))
	if n := tr.distinct("u", now); n != 2 {
		t.Errorf("distinct = %d, want 2", n)
	}
	tr.reset("u")
	if n := tr.distinct("u", now); n != 0 {
		t.Errorf("after reset = %d, want 0", n)
	}
}

func TestSubTokenUniqueAndURLSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		tok, err := newSubToken()
		if err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(tok, "+/=") || len(tok) < 30 {
			t.Errorf("token not URL-safe or too short: %q", tok)
		}
		if seen[tok] {
			t.Errorf("duplicate token %q", tok)
		}
		seen[tok] = true
	}
}

func TestFindClientByToken(t *testing.T) {
	st := &Store{Clients: []Client{{Name: "a", SubToken: "tok-a"}, {Name: "b", SubToken: "tok-b"}}}
	if c := findClientByToken(st, "tok-b"); c == nil || c.Name != "b" {
		t.Errorf("token lookup failed: %+v", c)
	}
	if findClientByToken(st, "") != nil || findClientByToken(st, "nope") != nil {
		t.Error("empty or unknown token must not match")
	}
}

func TestSubRouteUnknownToken(t *testing.T) {
	m := http.NewServeMux()
	registerXrayShareRoutes(m, func(h http.HandlerFunc) http.HandlerFunc { return h })
	req := httptest.NewRequest("GET", "/sub/unknown-token?server=1.2.3.4", nil)
	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatalf("unknown token must not return 200, got %d", rec.Code)
	}
	if _, err := base64.StdEncoding.DecodeString(rec.Body.String()); err == nil && rec.Body.Len() > 0 && rec.Code == 200 {
		t.Error("should not leak config")
	}
}
