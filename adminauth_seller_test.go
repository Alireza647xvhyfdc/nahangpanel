package main

import (
	"net/http/httptest"
	"testing"
)

func TestSellerAllowed(t *testing.T) {
	cases := []struct {
		method, path string
		want         bool
	}{
		{"GET", "/", true},
		{"GET", "/api/me", true},
		{"GET", "/api/xray/inbounds", true},
		{"GET", "/api/xray/clients", true},
		{"GET", "/api/xray/links", true},
		{"POST", "/api/xray/clients", true},
		{"PUT", "/api/xray/clients/a", true},
		{"POST", "/api/xray/clients/a/enable", true},
		{"POST", "/api/xray/clients/a/devices/reset", true},
		{"GET", "/api/tunnels", false},
		{"GET", "/api/admins", false},
		{"GET", "/api/backup", false},
		{"GET", "/api/settings", false},
		{"GET", "/api/xray/status", false},
		{"GET", "/api/xray/link", false},
		{"POST", "/api/xray/inbounds", false},
		{"POST", "/api/restore", false},
		{"POST", "/api/admins", false},
		{"DELETE", "/api/admins/x", false},
		{"PUT", "/api/xray/clients/a/enable", false},
		{"POST", "/api/xray/clients/", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(c.method, c.path, nil)
		if got := sellerAllowed(r); got != c.want {
			t.Errorf("%s %s: got %v, want %v", c.method, c.path, got, c.want)
		}
	}
}
