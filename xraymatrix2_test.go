package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInboundExtrasMatrix(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("XRAY_BIN تنظیم نشده")
	}
	dir := t.TempDir()
	cf, kf := writeSelfSigned(t, dir)
	priv, pub := realityKeys(t, bin)
	const uid = "11111111-2222-3333-4444-555555555555"
	lf := &LimitFallback{UploadAfter: 1000, UploadBps: 2000, UploadBurst: 3000, DownloadAfter: 1000, DownloadBps: 2000, DownloadBurst: 3000}
	tlsOf := func(extra func(*TLSSettings)) *TLSSettings {
		t := &TLSSettings{ServerName: "example.com", CertFile: cf, KeyFile: kf}
		if extra != nil {
			extra(t)
		}
		return t
	}
	realityOf := func(extra func(*RealitySettings)) *RealitySettings {
		r := &RealitySettings{Dest: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"},
			PrivateKey: priv, PublicKey: pub, ShortIDs: []string{"abcd"}}
		if extra != nil {
			extra(r)
		}
		return r
	}
	cases := []struct {
		name string
		in   Inbound
	}{
		{"vless-tls-alpn-versions", Inbound{Protocol: "vless", Network: "tcp", Security: "tls", Flow: "xtls-rprx-vision",
			TLS: tlsOf(func(t *TLSSettings) {
				t.ALPN = []string{"h2", "http/1.1"}
				t.MinVersion, t.MaxVersion = "1.2", "1.3"
				t.Curves = []string{"X25519"}
			})}},
		{"vless-tls-cipher-rejectsni", Inbound{Protocol: "vless", Network: "tcp", Security: "tls",
			TLS: tlsOf(func(t *TLSSettings) {
				t.CipherSuites = []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}
				t.RejectUnknownSNI = true
				t.DisableSystemRoot = true
				t.SessionResumption = true
			})}},
		{"vless-tls-limitfallback", Inbound{Protocol: "vless", Network: "tcp", Security: "tls",
			TLS: tlsOf(func(t *TLSSettings) { t.LimitFallback = lf })}},
		{"trojan-tls-alpn", Inbound{Protocol: "trojan", Network: "grpc", Security: "tls", ServiceName: "svc",
			TLS: tlsOf(func(t *TLSSettings) { t.ALPN = []string{"h2"} })}},
		{"vless-reality-show-timediff", Inbound{Protocol: "vless", Network: "tcp", Security: "reality",
			Reality: realityOf(func(r *RealitySettings) { r.Show = true; r.MaxTimeDiff = 60000; r.MinClientVer = "1.0.0" })}},
		{"vless-reality-limitfallback", Inbound{Protocol: "vless", Network: "tcp", Security: "reality", Flow: "xtls-rprx-vision",
			Reality: realityOf(func(r *RealitySettings) { r.LimitFallback = lf })}},
		{"vless-xhttp-reality-streamone", Inbound{Protocol: "vless", Network: "xhttp", Security: "reality", Path: "/x", Mode: "stream-one",
			Reality: realityOf(nil)}},
		{"vless-xhttp-tls-packetup", Inbound{Protocol: "vless", Network: "xhttp", Security: "tls", Path: "/x", Host: "example.com", Mode: "packet-up",
			TLS: tlsOf(nil)}},
		{"vless-tcp-sniff-listen", Inbound{Protocol: "vless", Network: "tcp", Security: "none", Sniffing: true,
			SniffDest: []string{"http", "tls"}, Listen: "0.0.0.0"}},
		{"vless-ws-tls-path-host", Inbound{Protocol: "vless", Network: "ws", Security: "tls", Path: "/ws", Host: "example.com",
			TLS: tlsOf(nil)}},
		{"vmess-kcp-none", Inbound{Protocol: "vmess", Network: "kcp", Security: "none"}},
		{"vless-httpupgrade-tls", Inbound{Protocol: "vless", Network: "httpupgrade", Security: "tls", Path: "/hu", Host: "example.com",
			TLS: tlsOf(nil)}},
	}

	var report []string
	var failures []string
	port := 3000
	for _, c := range cases {
		port++
		in := c.in
		in.Port, in.Remark = port, fmt.Sprintf("x%d", port)
		var e, step string
		for _, ch := range []struct {
			n string
			f func() string
		}{
			{"validateInbound", func() string { return validateInbound(in) }},
			{"validateSecurity", func() string { return validateSecurity(&in) }},
			{"validateProtocolSecurity", func() string { return validateProtocolSecurity(in) }},
			{"validateNetwork", func() string { return validateNetwork(&in) }},
			{"validateAdvanced", func() string { return validateAdvanced(&in) }},
		} {
			step = ch.n
			if e = ch.f(); e != "" {
				break
			}
		}
		if e != "" {
			report = append(report, fmt.Sprintf("REJECT  %-32s [%s] %s", c.name, step, e))
			continue
		}
		ensureKCPSeed(&in)
		st := &Store{Inbounds: []Inbound{in}}
		if in.Protocol != "shadowsocks" {
			st.Clients = []Client{{Name: "u1", ID: uid, Enabled: true, Inbounds: []int{in.Port}}}
		}
		b, err := buildXrayJSON(st)
		if err != nil {
			failures = append(failures, c.name+": buildXrayJSON: "+err.Error())
			continue
		}
		cfg := filepath.Join(dir, fmt.Sprintf("x-%d.json", port))
		os.WriteFile(cfg, b, 0o600)
		out, err := exec.Command(bin, "run", "-test", "-c", cfg).CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if i := strings.LastIndex(msg, "Failed to start"); i >= 0 {
				msg = msg[i:]
			}
			failures = append(failures, c.name+": xray -test: "+msg)
			report = append(report, "XRAYFAIL "+c.name)
			continue
		}
		report = append(report, "OK      "+c.name)
	}
	for _, r := range report {
		t.Log(r)
	}
	for _, f := range failures {
		t.Errorf("پذیرفته‌شده ولی Xray رد کرد: %s", f)
	}
}
