package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	xrayConfigPath = "/usr/local/etc/xray/config.json"
	xrayBin        = "/usr/local/bin/xray"
	xrayStore      = "/etc/tunnelpanel/xray-clients.json"
)

var xrayMu sync.Mutex

type Client struct {
	Name    string `json:"name"`
	ID      string `json:"id"`
	Enabled bool   `json:"enabled"`
	Expire  int64  `json:"expire,omitempty"`
	LimitGB int    `json:"limit_gb,omitempty"`
	Inbound int    `json:"inbound"`
	Inbounds           []int  `json:"inbounds,omitempty"`
	IPLimit            int    `json:"ip_limit,omitempty"`
	HWIDLimit          int    `json:"hwid_limit,omitempty"`
	TrafficReset       string `json:"traffic_reset,omitempty"`
	AutoRenew          bool   `json:"auto_renew,omitempty"`
	StartAfterFirstUse bool   `json:"start_after_first_use,omitempty"`
	Comment            string `json:"comment,omitempty"`
	Group              string `json:"group,omitempty"`
	Owner              string `json:"owner,omitempty"`
	SubToken       string   `json:"sub_token,omitempty"`
	Devices        []Device `json:"devices,omitempty"`
	DisabledReason string   `json:"disabled_reason,omitempty"`
	UsedBytes  int64 `json:"used_bytes,omitempty"`
	NextReset  int64 `json:"next_reset,omitempty"`
	FirstUseAt int64 `json:"first_use_at,omitempty"`
	Period     int64 `json:"period,omitempty"`
}

type Inbound struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Remark   string `json:"remark"`
	Security string           `json:"security"`
	TLS      *TLSSettings     `json:"tls,omitempty"`
	Reality  *RealitySettings `json:"reality,omitempty"`
	Password string           `json:"password,omitempty"`
	Network string `json:"network,omitempty"`
	Seed    string `json:"seed,omitempty"`
	Disabled    bool     `json:"disabled,omitempty"`
	Listen      string   `json:"listen,omitempty"`
	Sniffing    bool     `json:"sniffing,omitempty"`
	SniffDest   []string `json:"sniff_dest,omitempty"`
	Flow        string   `json:"flow,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Path        string   `json:"path,omitempty"`
	ServiceName string   `json:"service_name,omitempty"`
	Host        string   `json:"host,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	SortOrder      int    `json:"sort_order,omitempty"`
	ExcludeSub     bool   `json:"exclude_sub,omitempty"`
	DisableFlow    bool   `json:"disable_flow,omitempty"`
	ShareStrategy  string `json:"share_strategy,omitempty"`
	TotalFlow      int64  `json:"total_flow,omitempty"`
	TrafficReset   string `json:"traffic_reset,omitempty"`
	Expires        int64  `json:"expires,omitempty"`
	UsedBytes      int64  `json:"used_bytes,omitempty"`
	NextReset      int64  `json:"next_reset,omitempty"`
	DisabledReason string `json:"disabled_reason,omitempty"`
}

type Store struct {
	Inbounds []Inbound `json:"inbounds"`
	Clients  []Client  `json:"clients"`
}

var reRemark = regexp.MustCompile(`^[A-Za-z0-9_\-]{1,32}$`)

var reservedPorts = map[int]bool{22: true, 3080: true, 28254: true, xrayAPIPort: true}

const (
	maxLimitGB  = 100000
	maxExpireAt = 4102444800
)

func validateClientInput(expire int64, limitGB int) string {
	if expire < 0 || expire > maxExpireAt {
		return "تاریخ انقضا نامعتبر است"
	}
	if limitGB < 0 || limitGB > maxLimitGB {
		return "حجم نامعتبر است"
	}
	return ""
}

var reHost = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,253}$`)

func validServerAddr(a string) bool {
	if net.ParseIP(a) != nil {
		return true
	}
	return reHost.MatchString(a)
}

func loadStore() (*Store, error) {
	st := &Store{}
	b, err := os.ReadFile(xrayStore)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("xray-clients.json خراب است: %w", err)
	}
	return st, nil
}

func saveStore(st *Store) error {
	if err := os.MkdirAll(filepath.Dir(xrayStore), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := xrayStore + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, xrayStore)
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func validateInbound(in Inbound) string {
	if in.Port < 1024 || in.Port > 65535 {
		return "پورت باید بین ۱۰۲۴ و ۶۵۵۳۵ باشد (پورت‌های زیر ۱۰۲۴ رزرو هستند)"
	}
	if reservedPorts[in.Port] {
		return "این پورت برای سرویس دیگری رزرو است"
	}
	if !protocols[in.Protocol] {
		return "پروتکل باید vless، vmess، trojan یا shadowsocks باشد"
	}
	if in.Remark != "" && !reRemark.MatchString(in.Remark) {
		return "نام inbound فقط حروف انگلیسی، عدد، _ و - باشد"
	}
	return ""
}

func buildXrayJSON(st *Store) ([]byte, error) {
	type inboundJSON struct {
		Tag      string         `json:"tag"`
		Port     int            `json:"port"`
		Listen   string         `json:"listen,omitempty"`
		Protocol string         `json:"protocol"`
		Settings map[string]any `json:"settings"`
		Stream   map[string]any `json:"streamSettings"`
		Sniff    map[string]any `json:"sniffing,omitempty"`
	}

	var inbounds []any
	for _, in := range st.Inbounds {
		if in.Disabled {
			continue
		}
		settings := inboundSettings(in, st.Clients, time.Now())
		inbounds = append(inbounds, inboundJSON{
			Tag:      "in-" + strconv.Itoa(in.Port),
			Port:     in.Port,
			Protocol: in.Protocol,
			Settings: settings,
			Stream:   streamFor(in),
			Listen:   in.Listen,
			Sniff:    sniffFor(in),
		})
	}

	inbounds = append(inbounds, map[string]any{
		"tag": "api", "listen": "127.0.0.1", "port": xrayAPIPort, "protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1"},
	})
	cfg := map[string]any{
		"log":   map[string]any{"loglevel": "warning", "access": accessLogPath},
		"api":   map[string]any{"tag": "api", "services": []string{"StatsService"}},
		"stats": map[string]any{},
		"policy": map[string]any{
			"levels": map[string]any{"0": map[string]any{"statsUserUplink": true, "statsUserDownlink": true}},
			"system": map[string]any{"statsInboundUplink": true, "statsInboundDownlink": true},
		},
		"routing": map[string]any{"rules": []map[string]any{
			{"type": "field", "inboundTag": []string{"api"}, "outboundTag": "api"},
		}},
		"inbounds":  inbounds,
		"outbounds": []map[string]any{{"protocol": "freedom", "tag": "direct"}},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func clientUsable(c Client, now time.Time) bool {
	if !c.Enabled {
		return false
	}
	if c.Expire > 0 && now.Unix() > c.Expire {
		return false
	}
	return true
}

func writeXrayConfig(st *Store) error {
	b, err := buildXrayJSON(st)
	if err != nil {
		return err
	}
	tmp := filepath.Join(os.TempDir(), "xray-check.json")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)

	if out, err := exec.Command(xrayBin, "run", "-test", "-c", tmp).CombinedOutput(); err != nil {
		return fmt.Errorf("کانفیگ Xray نامعتبر است: %s", strings.TrimSpace(string(out)))
	}
	if err := os.MkdirAll(filepath.Dir(xrayConfigPath), 0o755); err != nil {
		return err
	}
	if err := ensureAccessLogDir(); err != nil {
		return err
	}
	if err := os.WriteFile(xrayConfigPath, b, 0o600); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "restart", "xray").CombinedOutput(); err != nil {
		return fmt.Errorf("ریستارت xray ناموفق بود: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

func addInbound(in Inbound) error {
	if e := validateInbound(in); e != "" {
		return errors.New(e)
	}
	if err := materializeCerts(&in); err != nil {
		return err
	}
	if e := validateSecurity(&in); e != "" {
		return errors.New(e)
	}
	in.NextReset = nextResetAfter(time.Now(), in.TrafficReset)
	if e := validateProtocolSecurity(in); e != "" {
		return errors.New(e)
	}
	if e := validateNetwork(&in); e != "" {
		return errors.New(e)
	}
	if e := validateAdvanced(&in); e != "" {
		return errors.New(e)
	}
	if err := ensureKCPSeed(&in); err != nil {
		return err
	}
	if err := ensureSSPassword(&in); err != nil {
		return err
	}
	if err := ensureRealityKeys(&in); err != nil {
		return err
	}
	xrayMu.Lock()
	defer xrayMu.Unlock()
	st, err := loadStore()
	if err != nil {
		return err
	}
	for _, x := range st.Inbounds {
		if x.Port == in.Port {
			return errors.New("این پورت قبلاً inbound دارد")
		}
	}
	st.Inbounds = append(st.Inbounds, in)
	if err := writeXrayConfig(st); err != nil {
		return err
	}
	return saveStore(st)
}
