package main

import "testing"

func TestHostPortBracketsIPv6(t *testing.T) {
	cases := map[string]string{
		"1.2.3.4":        "1.2.3.4:443",
		"example.com":    "example.com:443",
		"2001:db8::1":    "[2001:db8::1]:443",
	}
	for host, want := range cases {
		if got := hostPort(host, 443); got != want {
			t.Errorf("hostPort(%q, 443) = %q, want %q", host, got, want)
		}
	}
}
