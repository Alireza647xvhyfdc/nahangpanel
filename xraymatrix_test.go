package main

// تست ماتریس: همهٔ ترکیب‌های protocol × network × security × flow را از همان زنجیرهٔ
// اعتبارسنجی addInbound رد می‌کند، کانفیگ می‌سازد و با `xray run -test` چک می‌کند.
// فقط وقتی اجرا می‌شود که XRAY_BIN به یک باینری Xray اشاره کند:
//   XRAY_BIN=/path/to/xray go test -run TestInboundMatrix -v ./...

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSelfSigned(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		DNSNames: []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	certFile = filepath.Join(dir, "c.pem")
	keyFile = filepath.Join(dir, "k.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
	return
}

func realityKeys(t *testing.T, bin string) (priv, pub string) {
	out, err := exec.Command(bin, "x25519").CombinedOutput()
	if err != nil {
		t.Fatalf("x25519: %v %s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch {
		case strings.HasPrefix(line, "PrivateKey:"):
			priv = f[len(f)-1]
		case strings.HasPrefix(line, "Password (PublicKey):"):
			pub = f[len(f)-1]
		}
	}
	return
}

func TestInboundMatrix(t *testing.T) {
	bin := os.Getenv("XRAY_BIN")
	if bin == "" {
		t.Skip("XRAY_BIN تنظیم نشده")
	}
	dir := t.TempDir()
	cf, kf := writeSelfSigned(t, dir)
	priv, pub := realityKeys(t, bin)

	protocols := []string{"vless", "vmess", "trojan", "shadowsocks"}
	networks := []string{"tcp", "kcp", "ws", "grpc", "httpupgrade", "xhttp"}
	securities := []string{"none", "tls", "reality"}
	flows := []string{"", "xtls-rprx-vision"}
	const uid = "11111111-2222-3333-4444-555555555555"

	port := 2000
	var failures []string
	var rows []string
	for _, p := range protocols {
		for _, n := range networks {
			for _, s := range securities {
				for _, fl := range flows {
					if fl != "" && (p != "vless" || s == "none") {
						continue // flow فقط برای vless با TLS یا Reality
					}
					port++
					name := fmt.Sprintf("%s/%s/%s/%s", p, n, s, fl)
					in := Inbound{Port: port, Protocol: p, Remark: "t" + fmt.Sprint(port), Security: s, Network: n, Flow: fl}
					if n == "ws" || n == "httpupgrade" || n == "xhttp" {
						in.Path, in.Host = "/p", "example.com"
					}
					if n == "grpc" {
						in.ServiceName = "svc"
					}
					if n == "xhttp" {
						in.Mode = "auto"
					}
					if s == "tls" {
						in.TLS = &TLSSettings{ServerName: "example.com", CertFile: cf, KeyFile: kf}
					}
					if s == "reality" {
						in.Reality = &RealitySettings{Dest: "www.microsoft.com:443", ServerNames: []string{"www.microsoft.com"},
							PrivateKey: priv, PublicKey: pub, ShortIDs: []string{"abcd"}}
					}

					// همان زنجیرهٔ addInbound (بدون قفل و نوشتن فایل)
					var e string
					step := ""
					checks := []struct {
						n string
						f func() string
					}{
						{"validateInbound", func() string { return validateInbound(in) }},
						{"validateSecurity", func() string { return validateSecurity(&in) }},
						{"validateProtocolSecurity", func() string { return validateProtocolSecurity(in) }},
						{"validateNetwork", func() string { return validateNetwork(&in) }},
						{"validateAdvanced", func() string { return validateAdvanced(&in) }},
					}
					for _, c := range checks {
						step = c.n
						if e = c.f(); e != "" {
							break
						}
					}
					if e != "" {
						rows = append(rows, fmt.Sprintf("REJECT  %-40s [%s] %s", name, step, e))
						continue
					}
					ensureKCPSeed(&in)
					ensureSSPassword(&in)

					st := &Store{Inbounds: []Inbound{in}}
					if p != "shadowsocks" {
						st.Clients = []Client{{Name: "u1", ID: uid, Enabled: true, Inbounds: []int{in.Port}}}
					}
					b, err := buildXrayJSON(st)
					if err != nil {
						failures = append(failures, name+": buildXrayJSON: "+err.Error())
						continue
					}
					cfg := filepath.Join(dir, fmt.Sprintf("cfg-%d.json", port))
					os.WriteFile(cfg, b, 0o600)
					out, err := exec.Command(bin, "run", "-test", "-c", cfg).CombinedOutput()
					if err != nil {
						msg := strings.TrimSpace(string(out))
						if len(msg) > 300 {
							msg = msg[len(msg)-300:]
						}
						failures = append(failures, name+": xray -test: "+msg)
						rows = append(rows, "XRAYFAIL "+name)
						continue
					}
					rows = append(rows, "OK      "+name)
				}
			}
		}
	}
	for _, r := range rows {
		t.Log(r)
	}
	for _, f := range failures {
		t.Errorf("پیکربندی پذیرفته‌شده ولی Xray رد کرد: %s", f)
	}
}
