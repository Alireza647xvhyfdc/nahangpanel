package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKVLinesAndPick(t *testing.T) {
	out := "Seed:\n  abcSEED==\nVerify: verifyVAL==\nECH config list:\nQUJD\nECH server keys: keyVAL\n"
	m := kvLines(out)
	if got := pickKV(m, "seed"); got != "abcSEED==" {
		t.Fatalf("seed = %q", got)
	}
	if got := pickKV(m, "verify"); got != "verifyVAL==" {
		t.Fatalf("verify = %q", got)
	}
	if got := pickKV(m, "config"); got != "QUJD" {
		t.Fatalf("config = %q", got)
	}
	if got := pickKV(m, "key"); got != "keyVAL" {
		t.Fatalf("key = %q", got)
	}
}

func TestCertsOfLegacyAndList(t *testing.T) {
	legacy := &TLSSettings{CertFile: "/a.pem", KeyFile: "/a.key"}
	if c := certsOf(legacy); len(c) != 1 || c[0].CertFile != "/a.pem" {
		t.Fatalf("legacy certsOf = %+v", c)
	}
	multi := &TLSSettings{Certificates: []TLSCert{{CertFile: "/1.pem", KeyFile: "/1.key"}, {CertFile: "/2.pem", KeyFile: "/2.key"}}}
	if c := certsOf(multi); len(c) != 2 {
		t.Fatalf("multi certsOf len = %d", len(c))
	}
}

func TestStreamForTLSNewFields(t *testing.T) {
	in := Inbound{
		Security: "tls",
		Network:  "tcp",
		TLS: &TLSSettings{
			ServerName:    "example.com",
			Certificates:  []TLSCert{{CertFile: "/c1.pem", KeyFile: "/k1.key"}, {CertFile: "/c2.pem", KeyFile: "/k2.key"}},
			ECHSockopt:    true,
			ECHKey:        "ECHKEY",
			ECHConfig:     "ECHCFG",
			LimitFallback: &LimitFallback{UploadAfter: 10, UploadBps: 20, UploadBurst: 30, DownloadAfter: 1, DownloadBps: 2, DownloadBurst: 3},
		},
	}
	st := streamFor(in)
	b, _ := json.Marshal(st)
	js := string(b)
	for _, want := range []string{`"echSockopt":true`, `"echServerKeys":"ECHKEY"`, `"echConfigList":"ECHCFG"`, `"limitFallbackUpload"`, `"limitFallbackDownload"`, `/c2.pem`} {
		if !strings.Contains(js, want) {
			t.Fatalf("missing %s in %s", want, js)
		}
	}
	ts := st["tlsSettings"].(map[string]any)
	if n := len(ts["certificates"].([]map[string]any)); n != 2 {
		t.Fatalf("certificates count = %d", n)
	}
}

func TestStreamForRealityNewFields(t *testing.T) {
	in := Inbound{
		Security: "reality",
		Network:  "tcp",
		Reality: &RealitySettings{
			Dest: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"},
			PrivateKey: "priv", PublicKey: "pub", ShortIDs: []string{"ab"},
			MLDSA65Seed: "SEED", MLDSA65Verify: "VER", MasterKeyLog: "/tmp/k.log",
		},
	}
	rs := streamFor(in)["realitySettings"].(map[string]any)
	if rs["mldsa65Seed"] != "SEED" || rs["mldsa65Verify"] != "VER" || rs["masterKeyLog"] != "/tmp/k.log" {
		t.Fatalf("reality fields missing: %+v", rs)
	}
}

func TestRedactHidesSecrets(t *testing.T) {
	in := Inbound{
		Security: "reality",
		Reality:  &RealitySettings{PrivateKey: "p", MLDSA65Seed: "s"},
		TLS:      &TLSSettings{ECHKey: "k"},
	}
	out := redactInbound(in)
	if out.Reality.PrivateKey != "" || out.Reality.MLDSA65Seed != "" || out.TLS.ECHKey != "" {
		t.Fatalf("secrets not redacted: %+v %+v", out.Reality, out.TLS)
	}
	if in.Reality.MLDSA65Seed != "s" || in.TLS.ECHKey != "k" {
		t.Fatalf("redact must not mutate original")
	}
}

func TestValidateNewSecurityFields(t *testing.T) {
	tl := &TLSSettings{MinVersion: "1.2", MaxVersion: "1.3", Usage: "encipherment"}
	tl.ECHKey = "not base64!"
	if e := validateTLSExtra(tl); e == "" {
		t.Fatal("expected invalid ECH key error")
	}
	tl.ECHKey = "QUJD REFE"
	if e := validateTLSExtra(tl); e != "" || tl.ECHKey != "QUJDREFE" {
		t.Fatalf("expected whitespace-stripped ECH key, got %q err=%q", tl.ECHKey, e)
	}
	tl.LimitFallback = &LimitFallback{UploadBps: -1}
	if e := validateTLSExtra(tl); e == "" {
		t.Fatal("expected negative limit fallback error")
	}
	r := &RealitySettings{Xver: 0, SpiderX: "/", MLDSA65Seed: "bad seed!"}
	if e := validateRealityExtra(r); e == "" {
		t.Fatal("expected invalid mldsa seed error")
	}
}

func TestCertPinFromFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.pem")
	pemData := "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUZ0y2pI1xq8r3H1Vu3dU5dQe8VrYwCgYIKoZIzj0EAwIw\nRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu\ndGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yNDAxMDEwMDAwMDBaFw0yNTAxMDEw\nMDAwMDBaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYD\nVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwWTATBgcqhkjOPQIBBggqhkjO\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(p, []byte(pemData), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := certPinFromFile(p)
	if err != nil {
		t.Fatalf("certPinFromFile: %v", err)
	}
	if len(h) != 64 {
		t.Fatalf("pin length = %d", len(h))
	}
	if _, err := certPinFromFile("relative.pem"); err == nil {
		t.Fatal("relative path must be rejected")
	}
	if _, err := certPinFromFile(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("missing file must fail")
	}
}

func TestMaterializeCertsContentMode(t *testing.T) {
	old := tlsCertDir
	_ = old
	in := Inbound{
		Port:     2053,
		Security: "tls",
		TLS: &TLSSettings{ServerName: "example.com", Certificates: []TLSCert{
			{Mode: "content", CertContent: "x", KeyContent: "y"},
		}},
	}
	if err := materializeCerts(&in); err == nil {
		t.Fatal("invalid PEM content must be rejected")
	}
	in.TLS.Certificates[0].CertContent = "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----"
	in.TLS.Certificates[0].KeyContent = "-----BEGIN PRIVATE KEY-----\nBB\n-----END PRIVATE KEY-----"
	if err := materializeCerts(&in); err != nil {
		t.Skipf("cannot write to %s in this environment: %v", tlsCertDir, err)
	}
	c := in.TLS.Certificates[0]
	if c.CertContent != "" || c.KeyContent != "" {
		t.Fatal("PEM content must be cleared after writing")
	}
	os.Remove(c.CertFile)
	os.Remove(c.KeyFile)
}
