package main

import "testing"

// IP Limit و HWID Limit باید قبل از هر دسترسی به فایل رد شوند.
func TestAddClientRejectsOutOfRangeDeviceLimits(t *testing.T) {
	base := ClientReq{Name: "limit-test", Inbounds: []int{443}}
	cases := []ClientReq{
		{IPLimit: -1},
		{IPLimit: 10001},
		{HWIDLimit: -1},
		{HWIDLimit: 10001},
	}
	for i, c := range cases {
		req := base
		req.IPLimit, req.HWIDLimit = c.IPLimit, c.HWIDLimit
		if _, err := addClientFull(req); err == nil {
			t.Errorf("case %d: expected rejection for IPLimit=%d HWIDLimit=%d", i, req.IPLimit, req.HWIDLimit)
		}
	}
}
