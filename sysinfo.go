package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var repo = "Alireza647xvhyfdc/nahangpanel"

func readFileTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

type cpuSample struct{ idle, total uint64 }

func readCPU() (cpuSample, bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, false
	}
	f := strings.Fields(strings.SplitN(string(b), "\n", 2)[0])
	if len(f) < 5 {
		return cpuSample{}, false
	}
	var s cpuSample
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		s.total += n
		if i == 3 || i == 4 {
			s.idle += n
		}
	}
	return s, true
}

func cpuPercent() float64 {
	a, ok1 := readCPU()
	time.Sleep(300 * time.Millisecond)
	b, ok2 := readCPU()
	if !ok1 || !ok2 || b.total <= a.total {
		return 0
	}
	return 100 * (1 - float64(b.idle-a.idle)/float64(b.total-a.total))
}

func memInfo() (total, avail, swapTotal, swapFree uint64) {
	b, _ := os.ReadFile("/proc/meminfo")
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		v *= 1024
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		case "SwapTotal:":
			swapTotal = v
		case "SwapFree:":
			swapFree = v
		}
	}
	return
}

func diskInfo(path string) (total, free uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	bs := uint64(st.Bsize)
	return st.Blocks * bs, st.Bavail * bs
}

func netTotals() (rx, tx uint64) {
	b, _ := os.ReadFile("/proc/net/dev")
	for _, l := range strings.Split(string(b), "\n") {
		i := strings.Index(l, ":")
		if i < 0 || strings.TrimSpace(l[:i]) == "lo" {
			continue
		}
		f := strings.Fields(l[i+1:])
		if len(f) < 9 {
			continue
		}
		r, _ := strconv.ParseUint(f[0], 10, 64)
		t, _ := strconv.ParseUint(f[8], 10, 64)
		rx += r
		tx += t
	}
	return
}

func osName() string {
	for _, l := range strings.Split(readFileTrim("/etc/os-release"), "\n") {
		if strings.HasPrefix(l, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(l, "PRETTY_NAME="), `"`)
		}
	}
	return runtime.GOOS
}

func systemInfo() map[string]any {
	host, _ := os.Hostname()
	uptime := 0.0
	if f := strings.Fields(readFileTrim("/proc/uptime")); len(f) > 0 {
		uptime, _ = strconv.ParseFloat(f[0], 64)
	}
	load := []float64{0, 0, 0}
	for i, v := range strings.Fields(readFileTrim("/proc/loadavg")) {
		if i >= 3 {
			break
		}
		load[i], _ = strconv.ParseFloat(v, 64)
	}
	memT, memA, swT, swF := memInfo()
	var memUsed uint64
	if memA <= memT {
		memUsed = memT - memA
	}
	diskT, diskF := diskInfo("/")
	rx, tx := netTotals()
	var swUsed uint64
	if swF <= swT {
		swUsed = swT - swF
	}
	return map[string]any{
		"hostname": host, "os": osName(), "kernel": readFileTrim("/proc/sys/kernel/osrelease"),
		"cpus": runtime.NumCPU(), "cpu_percent": cpuPercent(), "load": load, "uptime_sec": uptime,
		"mem_total": memT, "mem_used": memUsed,
		"swap_total": swT, "swap_used": swUsed,
		"disk_total": diskT, "disk_free": diskF,
		"net_rx": rx, "net_tx": tx,
	}
}

var updCache struct {
	sync.Mutex
	at  time.Time
	tag string
}

func latestTag() (string, error) {
	updCache.Lock()
	defer updCache.Unlock()
	if updCache.tag != "" && time.Since(updCache.at) < 10*time.Minute {
		return updCache.tag, nil
	}
	c := &http.Client{Timeout: 8 * time.Second}
	resp, err := c.Get("https://api.github.com/repos/" + repo + "/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub returned HTTP %d", resp.StatusCode)
	}
	var r struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&r); err != nil {
		return "", err
	}
	if r.TagName == "" {
		return "", fmt.Errorf("no release found")
	}
	updCache.tag, updCache.at = r.TagName, time.Now()
	return r.TagName, nil
}

func registerSys(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	m.HandleFunc("GET /api/system", auth(func(w http.ResponseWriter, r *http.Request) {
		if identOf(r).role == "seller" {
			b, _ := json.Marshal(systemInfo())
			var full map[string]any
			if err := json.Unmarshal(b, &full); err != nil {
				reply(w, 500, map[string]string{"error": "خطا در خواندن وضعیت سرور"})
				return
			}
			out := map[string]any{}
			for _, k := range []string{"cpu_percent", "cpus", "mem_total", "mem_used", "disk_total", "disk_free"} {
				if v, ok := full[k]; ok {
					out[k] = v
				}
			}
			reply(w, 200, out)
			return
		}
		reply(w, 200, systemInfo())
	}))
	m.HandleFunc("GET /api/update", auth(func(w http.ResponseWriter, r *http.Request) {
		if !requireOwner(w, r) {
			return
		}
		res := map[string]any{"current": version, "latest": "", "available": false}
		lat, err := latestTag()
		if err != nil {
			res["error"] = err.Error()
		} else {
			res["latest"] = lat
			res["available"] = lat != version
		}
		reply(w, 200, res)
	}))

	m.HandleFunc("POST /api/update", auth(func(w http.ResponseWriter, r *http.Request) {
		if !requireOwner(w, r) {
			return
		}
		cmd := "curl -fsSL https://raw.githubusercontent.com/" + repo + "/main/install.sh -o /tmp/nahang-install.sh && bash /tmp/nahang-install.sh --update"
		if _, err := sh("systemd-run", "--unit=nahang-selfupdate", "--collect", "/bin/bash", "-c", cmd); err != nil {
			bad(w, "نتوانستم به‌روزرسانی را شروع کنم: "+err.Error())
			return
		}
		reply(w, 200, map[string]bool{"ok": true})
	}))
}
