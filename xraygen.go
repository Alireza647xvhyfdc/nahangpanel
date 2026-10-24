package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const tlsCertDir = "/etc/tunnelpanel/xcerts/"

func kvLines(out string) map[string]string {
	res := map[string]string{}
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		j := strings.Index(line, ":")
		if j < 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(line[:j]))
		v := strings.TrimSpace(line[j+1:])
		if v == "" && i+1 < len(lines) {
			v = strings.TrimSpace(lines[i+1])
		}
		if k == "" || v == "" {
			continue
		}
		if _, ok := res[k]; !ok {
			res[k] = v
		}
	}
	return res
}

func pickKV(m map[string]string, must ...string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		ok := true
		for _, sub := range must {
			if !strings.Contains(k, sub) {
				ok = false
				break
			}
		}
		if ok {
			return m[k]
		}
	}
	return ""
}

func runXray(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, xrayBin, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("اجرای xray ناموفق بود: %s", strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func genRealityKeys() (priv, pub string, err error) {
	out, err := runXray("x25519")
	if err != nil {
		return "", "", err
	}
	priv, pub = parseX25519(out)
	if priv == "" || pub == "" {
		return "", "", errors.New("خروجی xray x25519 قابل خواندن نیست")
	}
	return priv, pub, nil
}

func genMLDSA65() (seed, verify string, err error) {
	out, err := runXray("mldsa65")
	if err != nil {
		return "", "", err
	}
	m := kvLines(out)
	seed, verify = pickKV(m, "seed"), pickKV(m, "verify")
	if seed == "" || verify == "" {
		return "", "", errors.New("خروجی xray mldsa65 قابل خواندن نیست؛ نسخهٔ Xray را بررسی کن")
	}
	return seed, verify, nil
}

func genECH(serverName string) (config, key string, err error) {
	out, err := runXray("tls", "ech", "--serverName", serverName)
	if err != nil {
		return "", "", err
	}
	m := kvLines(out)
	config = cleanB64(pickKV(m, "config"))
	key = cleanB64(pickKV(m, "key"))
	if config == "" || key == "" {
		return "", "", errors.New("خروجی xray tls ech قابل خواندن نیست؛ نسخهٔ Xray را بررسی کن")
	}
	return config, key, nil
}

func materializeCerts(in *Inbound) error {
	if in.Security != "tls" || in.TLS == nil {
		return nil
	}
	for i := range in.TLS.Certificates {
		c := &in.TLS.Certificates[i]
		if c.Mode == "content" {
			if !strings.Contains(c.CertContent, "-----BEGIN") || !strings.Contains(c.KeyContent, "-----BEGIN") {
				return errors.New("محتوای PEM گواهی یا کلید معتبر نیست")
			}
			if err := os.MkdirAll(tlsCertDir, 0o700); err != nil {
				return err
			}
			base := filepath.Join(tlsCertDir, fmt.Sprintf("%d-%d", in.Port, i))
			c.CertFile, c.KeyFile = base+".crt", base+".key"
			if err := os.WriteFile(c.CertFile, []byte(strings.TrimSpace(c.CertContent)+"\n"), 0o644); err != nil {
				return err
			}
			if err := os.WriteFile(c.KeyFile, []byte(strings.TrimSpace(c.KeyContent)+"\n"), 0o600); err != nil {
				return err
			}
		}
		c.CertContent, c.KeyContent = "", ""
	}
	return nil
}

func scanTarget(target string) (ok bool, detail string) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || !reSNI.MatchString(host) {
		return false, "فرمت هدف نامعتبر است؛ مثل www.example.com:443"
	}
	if p, e := net.LookupPort("tcp", port); e != nil || p < 1 {
		return false, "پورت هدف نامعتبر است"
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", target, &tls.Config{
		ServerName: host,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		return false, "اتصال TLS ناموفق بود"
	}
	defer conn.Close()
	st := conn.ConnectionState()
	if st.Version != tls.VersionTLS13 {
		return false, "TLS 1.3 پشتیبانی نمی‌شود"
	}
	if st.NegotiatedProtocol != "h2" {
		return false, "HTTP/2 (h2) پشتیبانی نمی‌شود"
	}
	return true, "مناسب است"
}

var realityCandidates = []string{
	"www.microsoft.com:443", "www.apple.com:443", "www.cloudflare.com:443", "www.google.com:443",
	"www.amazon.com:443", "dl.google.com:443", "www.bing.com:443", "learn.microsoft.com:443",
	"www.nvidia.com:443", "www.intel.com:443", "www.samsung.com:443", "www.yahoo.com:443",
}

func findTargets() []string {
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		sem = make(chan struct{}, 6)
		ok  []string
	)
	for _, c := range realityCandidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			if good, _ := scanTarget(t); good {
				mu.Lock()
				ok = append(ok, t)
				mu.Unlock()
			}
		}(c)
	}
	wg.Wait()
	sort.Strings(ok)
	return ok
}

func certPinFromFile(path string) (string, error) {
	if !filepath.IsAbs(path) || strings.Contains(path, "..") {
		return "", errors.New("مسیر گواهی باید مطلق باشد")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", errors.New("فایل گواهی خوانده نشد")
	}
	for rest := data; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type == "CERTIFICATE" {
			sum := sha256.Sum256(blk.Bytes)
			return hex.EncodeToString(sum[:]), nil
		}
	}
	return "", errors.New("در فایل، گواهی PEM پیدا نشد")
}

func registerXraySecRoutes(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	jsonReply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	fail := func(w http.ResponseWriter, err error) {
		jsonReply(w, 500, map[string]string{"error": err.Error()})
	}
	readBody := func(w http.ResponseWriter, r *http.Request, v any) bool {
		return json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(v) == nil
	}

	m.HandleFunc("POST /api/xray/gen/reality", auth(func(w http.ResponseWriter, r *http.Request) {
		priv, pub, err := genRealityKeys()
		if err != nil {
			fail(w, err)
			return
		}
		jsonReply(w, 200, map[string]string{"private_key": priv, "public_key": pub})
	}))

	m.HandleFunc("POST /api/xray/gen/mldsa65", auth(func(w http.ResponseWriter, r *http.Request) {
		seed, verify, err := genMLDSA65()
		if err != nil {
			fail(w, err)
			return
		}
		jsonReply(w, 200, map[string]string{"seed": seed, "verify": verify})
	}))

	m.HandleFunc("POST /api/xray/gen/ech", auth(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ServerName string `json:"server_name"`
		}
		if !readBody(w, r, &in) || !reSNI.MatchString(in.ServerName) {
			jsonReply(w, 400, map[string]string{"error": "server_name برای ECH نامعتبر است"})
			return
		}
		cfg, key, err := genECH(in.ServerName)
		if err != nil {
			fail(w, err)
			return
		}
		jsonReply(w, 200, map[string]string{"config": cfg, "key": key})
	}))

	m.HandleFunc("POST /api/xray/scan-target", auth(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Target string `json:"target"`
		}
		if !readBody(w, r, &in) {
			jsonReply(w, 400, map[string]string{"error": "ورودی نامعتبر"})
			return
		}
		ok, detail := scanTarget(strings.TrimSpace(in.Target))
		jsonReply(w, 200, map[string]any{"ok": ok, "detail": detail})
	}))

	m.HandleFunc("GET /api/xray/find-targets", auth(func(w http.ResponseWriter, r *http.Request) {
		jsonReply(w, 200, map[string]any{"targets": findTargets()})
	}))

	m.HandleFunc("GET /api/xray/panel-cert", auth(func(w http.ResponseWriter, r *http.Request) {
		c, k := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
		if _, err1 := os.Stat(c); err1 != nil {
			jsonReply(w, 404, map[string]string{"error": "گواهی پنل پیدا نشد؛ پنل با -tls اجرا نشده است"})
			return
		}
		if _, err2 := os.Stat(k); err2 != nil {
			jsonReply(w, 404, map[string]string{"error": "کلید گواهی پنل پیدا نشد"})
			return
		}
		jsonReply(w, 200, map[string]string{"cert_file": c, "key_file": k})
	}))

	m.HandleFunc("POST /api/xray/cert-pin", auth(func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Path string `json:"path"`
		}
		if !readBody(w, r, &in) {
			jsonReply(w, 400, map[string]string{"error": "ورودی نامعتبر"})
			return
		}
		h, err := certPinFromFile(in.Path)
		if err != nil {
			jsonReply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		jsonReply(w, 200, map[string]string{"sha256": h})
	}))
}
