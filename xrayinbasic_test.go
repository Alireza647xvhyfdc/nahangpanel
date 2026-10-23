package main

import (
	"testing"
	"time"
)

func TestBasicExtrasDefaultsAndLimits(t *testing.T) {
	in := &Inbound{}
	if e := validateBasicExtras(in); e != "" {
		t.Fatalf("empty basic extras should be valid, got %q", e)
	}
	if in.ShareStrategy != "inbound_listen" || in.TrafficReset != "never" {
		t.Fatalf("defaults not applied: %+v", in)
	}
	future := time.Now().Add(time.Hour).Unix()
	bad := []Inbound{
		{SortOrder: -1},
		{SortOrder: 10000},
		{TotalFlow: -5},
		{TrafficReset: "hourly"},
		{ShareStrategy: "bogus"},
		{Expires: -1},
		{Expires: time.Now().Add(-time.Hour).Unix()},
		{Expires: maxExpireAt + 1},
	}
	for i, b := range bad {
		if e := validateBasicExtras(&b); e == "" {
			t.Errorf("case %d should be rejected: %+v", i, b)
		}
	}
	ok := &Inbound{Expires: future, SortOrder: 3, TotalFlow: 1 << 30}
	if e := validateBasicExtras(ok); e != "" {
		t.Errorf("valid values rejected: %q", e)
	}
}

func TestDisableFlowClearsFlow(t *testing.T) {
	in := &Inbound{
		Protocol: "vless", Network: "tcp", Security: "tls",
		Flow: "xtls-rprx-vision", DisableFlow: true,
	}
	if e := validateAdvanced(in); e != "" {
		t.Fatalf("unexpected error: %q", e)
	}
	if in.Flow != "" {
		t.Errorf("flow should be cleared when disable_flow is set, got %q", in.Flow)
	}
}

func TestBindInboundOnlyForClient(t *testing.T) {
	tn := &Tunnel{Role: "server", Inbound: 8443}
	if e := bindInbound(tn); e == "" {
		t.Fatal("server role must not bind to an inbound")
	}
	if e := bindInbound(&Tunnel{Role: "client"}); e != "" {
		t.Fatalf("no inbound selected should be fine, got %q", e)
	}
}
