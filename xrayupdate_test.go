package main

import (
	"net/http/httptest"
	"testing"
)

func TestParseDgstSHA(t *testing.T) {
	good := "SHA2-256= ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789\nSHA2-512= 00"
	h, ok := parseDgstSHA(good)
	if !ok || h != "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789" {
		t.Errorf("valid digest not parsed: %q %v", h, ok)
	}
	for _, bad := range []string{"", "SHA2-256= xyz", "SHA2-512= " + "a"} {
		if _, ok := parseDgstSHA(bad); ok {
			t.Errorf("invalid digest accepted: %q", bad)
		}
	}
}

func TestXrayTagValidation(t *testing.T) {
	for _, tag := range []string{"v25.1.1", "v1.8.24"} {
		if !reXrayTag.MatchString(tag) {
			t.Errorf("%q should be valid", tag)
		}
	}
	for _, tag := range []string{"25.1.1", "v25.1", "v25.1.1; rm -rf /", "../v1.0.0", "v25.1.1\n"} {
		if reXrayTag.MatchString(tag) {
			t.Errorf("%q should be rejected", tag)
		}
	}
}

func TestSellerCannotChangeXray(t *testing.T) {
	for _, c := range [][2]string{{"GET", "/api/xray/versions"}, {"POST", "/api/xray/version"}} {
		r := httptest.NewRequest(c[0], c[1], nil)
		if sellerAllowed(r) {
			t.Errorf("seller must not reach %s %s", c[0], c[1])
		}
	}
}

func TestSellerCannotUpdatePanel(t *testing.T) {
	for _, c := range [][2]string{{"GET", "/api/update"}, {"POST", "/api/update"}} {
		r := httptest.NewRequest(c[0], c[1], nil)
		if sellerAllowed(r) {
			t.Errorf("seller must not reach %s %s", c[0], c[1])
		}
	}
}

func TestSellerHomeScope(t *testing.T) {
	allowed := [][2]string{{"GET", "/api/system"}, {"GET", "/api/me"}}
	denied := [][2]string{{"GET", "/api/update"}, {"POST", "/api/update"}, {"GET", "/api/tunnels"}, {"GET", "/api/xray/status"}, {"GET", "/api/xray/versions"}, {"POST", "/api/xray/version"}}
	for _, c := range allowed {
		if !sellerAllowed(httptest.NewRequest(c[0], c[1], nil)) {
			t.Errorf("seller should reach %s %s", c[0], c[1])
		}
	}
	for _, c := range denied {
		if sellerAllowed(httptest.NewRequest(c[0], c[1], nil)) {
			t.Errorf("seller must not reach %s %s", c[0], c[1])
		}
	}
}
