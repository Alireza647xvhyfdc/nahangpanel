package main

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	reXrayTag = regexp.MustCompile(`^v\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	reXrayCur = regexp.MustCompile(`Xray (\d{1,3}\.\d{1,3}\.\d{1,3})`)
	xrayOpMu  sync.Mutex
)

func xrayAssetName() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "Xray-linux-64.zip", nil
	case "arm64":
		return "Xray-linux-arm64-v8a.zip", nil
	}
	return "", fmt.Errorf("معماری %s برای Xray پشتیبانی نمی‌شود", runtime.GOARCH)
}

func parseDgstSHA(text string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "SHA2-256=") {
			continue
		}
		h := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "SHA2-256=")))
		if len(h) == 64 {
			if _, err := hex.DecodeString(h); err == nil {
				return h, true
			}
		}
	}
	return "", false
}

func currentXrayTag() string {
	m := reXrayCur.FindStringSubmatch(xrayVersion())
	if m == nil {
		return ""
	}
	return "v" + m[1]
}

func fetchXrayReleases() ([]map[string]any, error) {
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get("https://api.github.com/repos/XTLS/Xray-core/releases?per_page=20")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub returned HTTP %d", resp.StatusCode)
	}
	var rels []struct {
		TagName    string `json:"tag_name"`
		Prerelease bool   `json:"prerelease"`
		Published  string `json:"published_at"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&rels); err != nil {
		return nil, err
	}
	out := []map[string]any{}
	for _, r := range rels {
		if reXrayTag.MatchString(r.TagName) {
			out = append(out, map[string]any{"tag": r.TagName, "prerelease": r.Prerelease, "published": r.Published})
		}
	}
	return out, nil
}

func downloadFile(url, path string, limit int64) error {
	c := &http.Client{Timeout: 5 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("دانلود ناموفق بود (HTTP %d)", resp.StatusCode)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("فایل دانلودی بیش از حد بزرگ است")
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func extractXrayBinary(zipPath, dest string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.Name != "xray" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
		if err != nil {
			return err
		}
		n, err := io.Copy(out, io.LimitReader(rc, 200<<20))
		cerr := out.Close()
		if err != nil {
			return err
		}
		if cerr != nil {
			return cerr
		}
		if n == 0 {
			return fmt.Errorf("فایل xray در آرشیو خالی است")
		}
		return nil
	}
	return fmt.Errorf("فایل xray در آرشیو پیدا نشد")
}

func installXrayVersion(tag string) error {
	if !reXrayTag.MatchString(tag) {
		return fmt.Errorf("نام نسخه نامعتبر است")
	}
	asset, err := xrayAssetName()
	if err != nil {
		return err
	}
	xrayOpMu.Lock()
	defer xrayOpMu.Unlock()

	dir, err := os.MkdirTemp("", "xray-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	base := "https://github.com/XTLS/Xray-core/releases/download/" + tag + "/"
	zipPath := dir + "/xray.zip"
	dgstPath := dir + "/xray.dgst"
	if err := downloadFile(base+asset, zipPath, 100<<20); err != nil {
		return err
	}
	if err := downloadFile(base+asset+".dgst", dgstPath, 64<<10); err != nil {
		return err
	}
	dgst, err := os.ReadFile(dgstPath)
	if err != nil {
		return err
	}
	want, ok := parseDgstSHA(string(dgst))
	if !ok {
		return fmt.Errorf("فایل هش Xray معتبر نیست")
	}
	got, err := sha256File(zipPath)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("هش فایل Xray مطابقت ندارد؛ نصب متوقف شد")
	}

	newBin := dir + "/xray"
	if err := extractXrayBinary(zipPath, newBin); err != nil {
		return err
	}
	vout, err := exec.Command(newBin, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(vout), "Xray") {
		return fmt.Errorf("باینری Xray این نسخه اجرا نشد")
	}
	if _, err := os.Stat(xrayConfigPath); err == nil {
		if out, err := exec.Command(newBin, "run", "-test", "-c", xrayConfigPath).CombinedOutput(); err != nil {
			return fmt.Errorf("کانفیگ فعلی با این نسخه سازگار نیست: %s", strings.TrimSpace(string(out)))
		}
	}

	xrayMu.Lock()
	defer xrayMu.Unlock()
	bak := xrayBin + ".bak"
	staged := xrayBin + ".new"
	if err := copyXrayBinary(newBin, staged); err != nil {
		return err
	}
	hadOld := false
	if _, err := os.Stat(xrayBin); err == nil {
		hadOld = true
		os.Remove(bak)
		if err := os.Rename(xrayBin, bak); err != nil {
			os.Remove(staged)
			return err
		}
	}
	if err := os.Rename(staged, xrayBin); err != nil {
		if hadOld {
			os.Rename(bak, xrayBin)
		}
		return err
	}
	xrayVersionCache.mu.Lock()
	xrayVersionCache.val = ""
	xrayVersionCache.mu.Unlock()

	out, err := exec.Command("systemctl", "restart", "xray").CombinedOutput()
	active, _ := exec.Command("systemctl", "is-active", "xray").Output()
	if err != nil || strings.TrimSpace(string(active)) != "active" {
		if hadOld {
			os.Rename(bak, xrayBin)
			exec.Command("systemctl", "restart", "xray").Run()
		}
		xrayVersionCache.mu.Lock()
		xrayVersionCache.val = ""
		xrayVersionCache.mu.Unlock()
		return fmt.Errorf("Xray با نسخه‌ی جدید اجرا نشد و به نسخه‌ی قبلی برگشت: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func copyXrayBinary(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func registerXrayVersionRoutes(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	m.HandleFunc("GET /api/xray/versions", auth(func(w http.ResponseWriter, r *http.Request) {
		if !requireOwner(w, r) {
			return
		}
		rels, err := fetchXrayReleases()
		if err != nil {
			reply(w, 502, map[string]string{"error": "دریافت لیست نسخه‌ها ممکن نشد: " + err.Error()})
			return
		}
		reply(w, 200, map[string]any{"current": xrayVersion(), "current_tag": currentXrayTag(), "versions": rels})
	}))

	m.HandleFunc("POST /api/xray/version", auth(func(w http.ResponseWriter, r *http.Request) {
		if !requireOwner(w, r) {
			return
		}
		var in struct {
			Tag string `json:"tag"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&in) != nil {
			bad(w, "ورودی نامعتبر")
			return
		}
		if err := installXrayVersion(in.Tag); err != nil {
			bad(w, err.Error())
			return
		}
		reply(w, 200, map[string]any{"ok": true, "current_tag": currentXrayTag()})
	}))
}
