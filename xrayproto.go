package main

// xrayproto.go: پروتکل‌ها (vless، vmess، trojan، shadowsocks)، settings کانفیگ و لینک هر کدام.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// protocols پروتکل‌های پشتیبانی‌شده را نگه می‌دارد.
var protocols = map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true}

// ssMethod روش رمزنگاری shadowsocks. aes-256-gcm در همهٔ نسخه‌های Xray پشتیبانی می‌شود.
const ssMethod = "aes-256-gcm"

// validateProtocolSecurity قوانین امنیتی مخصوص هر پروتکل را بررسی می‌کند.
// باید بعد از validateSecurity صدا زده شود، چون مقدار خالی security را none می‌کند.
func validateProtocolSecurity(in Inbound) string {
	switch in.Protocol {
	case "vmess":
		if in.Security == "reality" {
			return "vmess با Reality پشتیبانی نمی‌شود؛ از none یا tls استفاده کن"
		}
	case "trojan":
		if in.Security == "none" {
			return "trojan بدون TLS یا Reality امن نیست؛ یکی از tls یا reality را انتخاب کن"
		}
	case "shadowsocks":
		if in.Security != "none" {
			return "shadowsocks به TLS یا Reality نیاز ندارد؛ security را none بگذار"
		}
	}
	return ""
}

// validateNetwork شبکهٔ inbound را بررسی و پیش‌فرض tcp را می‌گذارد.
// mKCP یک transport روی UDP است و از تانل TCP عبور نمی‌کند؛ کلاینت باید مستقیم به سرور خارج وصل شود.
func validateNetwork(in *Inbound) string {
	if in.Network == "" {
		in.Network = "tcp"
	}
	if in.Protocol == "shadowsocks" && in.Network != "tcp" {
		return "shadowsocks فقط روی tcp ساخته می‌شود"
	}
	switch in.Network {
	case "tcp", "ws", "grpc", "httpupgrade", "xhttp":
		return ""
	case "kcp":
		if in.Security == "reality" {
			return "mKCP با Reality سازگار نیست؛ از none یا tls استفاده کن"
		}
		return ""
	}
	return "network باید tcp، kcp، ws، grpc، httpupgrade یا xhttp باشد"
}

// ensureKCPSeed برای mKCP یک seed تصادفی می‌سازد اگر خالی باشد.
func ensureKCPSeed(in *Inbound) error {
	if in.Network != "kcp" || in.Seed != "" {
		return nil
	}
	s, err := randHex(8)
	if err != nil {
		return err
	}
	in.Seed = s
	return nil
}

// ensureSSPassword برای shadowsocks رمز تصادفی می‌سازد اگر خالی باشد.
func ensureSSPassword(in *Inbound) error {
	if in.Protocol != "shadowsocks" || in.Password != "" {
		return nil
	}
	p, err := randHex(16)
	if err != nil {
		return err
	}
	in.Password = p
	return nil
}

// inboundSettings بخش settings کانفیگ Xray را بر اساس پروتکل می‌سازد.
// کلاینت‌های غیرفعال یا منقضی‌شده وارد کانفیگ نمی‌شوند.
func inboundSettings(in Inbound, clients []Client, now time.Time) map[string]any {
	switch in.Protocol {
	case "shadowsocks":
		// shadowsocks یک رمز برای کل inbound دارد و کلاینت جدا ندارد.
		return map[string]any{"method": ssMethod, "password": in.Password, "network": "tcp,udp"}

	case "trojan":
		cl := []map[string]any{}
		for _, c := range clients {
			if c.attachedTo(in.Port) && clientUsable(c, now) {
				cl = append(cl, map[string]any{"password": c.ID, "email": c.Name})
			}
		}
		return map[string]any{"clients": cl}

	case "vmess":
		cl := []map[string]any{}
		for _, c := range clients {
			if c.attachedTo(in.Port) && clientUsable(c, now) {
				cl = append(cl, map[string]any{"id": c.ID, "alterId": 0, "email": c.Name})
			}
		}
		return map[string]any{"clients": cl}

	default: // vless
		cl := []map[string]any{}
		for _, c := range clients {
			if c.attachedTo(in.Port) && clientUsable(c, now) {
				entry := map[string]any{"id": c.ID, "email": c.Name}
				if in.Flow != "" {
					entry["flow"] = in.Flow
				}
				cl = append(cl, entry)
			}
		}
		return map[string]any{"decryption": "none", "clients": cl}
	}
}

// securityParams پارامترهای امنیتی مشترک لینک vless و trojan را می‌سازد.
func securityParams(in Inbound) url.Values {
	q := url.Values{}
	switch in.Network {
	case "kcp":
		q.Set("type", "kcp")
		q.Set("headerType", "none")
		q.Set("seed", in.Seed)
	case "ws":
		q.Set("type", "ws")
		q.Set("path", pathOf(in))
		if in.Host != "" {
			q.Set("host", in.Host)
		}
	case "grpc":
		q.Set("type", "grpc")
		q.Set("serviceName", svcOf(in))
	case "httpupgrade":
		q.Set("type", "httpupgrade")
		q.Set("path", pathOf(in))
		if in.Host != "" {
			q.Set("host", in.Host)
		}
	case "xhttp":
		q.Set("type", "xhttp")
		q.Set("path", pathOf(in))
		if in.Host != "" {
			q.Set("host", in.Host)
		}
		q.Set("mode", modeOf(in))
	default:
		q.Set("type", "tcp")
	}
	switch in.Security {
	case "tls":
		q.Set("security", "tls")
		q.Set("sni", in.TLS.ServerName)
		if len(in.TLS.ALPN) > 0 {
			q.Set("alpn", strings.Join(in.TLS.ALPN, ","))
		}
		if in.TLS.ECHConfig != "" {
			q.Set("ech", in.TLS.ECHConfig)
		}
		q.Set("fp", fpOf(in))
	case "reality":
		r := in.Reality
		q.Set("security", "reality")
		if len(r.ServerNames) > 0 {
			q.Set("sni", r.ServerNames[0])
		}
		q.Set("pbk", r.PublicKey)
		if r.MLDSA65Verify != "" {
			q.Set("pqv", r.MLDSA65Verify)
		}
		q.Set("spx", spiderOf(r))
		if len(r.ShortIDs) > 0 {
			q.Set("sid", r.ShortIDs[0])
		}
		q.Set("fp", fpOf(in))
	default:
		q.Set("security", "none")
	}
	if in.Flow != "" {
		q.Set("flow", in.Flow)
	}
	return q
}

// buildLink لینک اشتراک یک inbound یا کلاینت را می‌سازد.
// برای shadowsocks، c می‌تواند nil باشد و لینک از خود inbound ساخته می‌شود.
// server باید IP سرور ایران باشد، چون کاربر به آن وصل می‌شود.
func buildLink(c *Client, in Inbound, server string) string {
	if !validServerAddr(server) {
		return ""
	}
	switch in.Protocol {
	case "shadowsocks":
		userinfo := base64.RawURLEncoding.EncodeToString([]byte(ssMethod + ":" + in.Password))
		name := in.Remark
		if name == "" {
			name = "ss"
		}
		return fmt.Sprintf("ss://%s@%s:%d#%s", userinfo, server, in.Port, url.QueryEscape(name))

	case "vmess":
		if c == nil {
			return ""
		}
		tls, sni := "", ""
		if in.Security == "tls" {
			tls, sni = "tls", in.TLS.ServerName
		}
		obj := map[string]any{
			"v": "2", "ps": c.Name, "add": server, "port": strconv.Itoa(in.Port),
			"id": c.ID, "aid": "0", "scy": "auto", "net": "tcp", "type": "none",
			"host": sni, "path": "", "tls": tls, "sni": sni,
		}
		switch in.Network {
		case "kcp":
			obj["net"] = "kcp"
			obj["path"] = in.Seed
		case "ws":
			obj["net"] = "ws"
			obj["path"] = pathOf(in)
		case "grpc":
			obj["net"] = "grpc"
			obj["path"] = svcOf(in)
		case "httpupgrade":
			obj["net"] = "httpupgrade"
			obj["path"] = pathOf(in)
		case "xhttp":
			obj["net"] = "xhttp"
			obj["path"] = pathOf(in)
		}
		if in.Host != "" {
			obj["host"] = in.Host
		}
		b, err := json.Marshal(obj)
		if err != nil {
			return ""
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(b)

	case "trojan":
		if c == nil {
			return ""
		}
		return fmt.Sprintf("trojan://%s@%s:%d?%s#%s", c.ID, server, in.Port, securityParams(in).Encode(), url.QueryEscape(c.Name))

	default: // vless
		if c == nil {
			return ""
		}
		return fmt.Sprintf("vless://%s@%s:%d?%s#%s", c.ID, server, in.Port, securityParams(in).Encode(), url.QueryEscape(c.Name))
	}
}

// pathOf مسیر ws را برمی‌گرداند (پیش‌فرض /).
func pathOf(in Inbound) string {
	if in.Path == "" {
		return "/"
	}
	return in.Path
}

// svcOf نام سرویس grpc را برمی‌گرداند (پیش‌فرض grpc).
func svcOf(in Inbound) string {
	if in.ServiceName == "" {
		return "grpc"
	}
	return in.ServiceName
}

// fpOf fingerprint کلاینت را برمی‌گرداند (پیش‌فرض chrome).
func fpOf(in Inbound) string {
	if in.Fingerprint == "" {
		return "chrome"
	}
	return in.Fingerprint
}

// sniffFor تنظیمات sniffing را برای کانفیگ Xray می‌سازد؛ nil یعنی غیرفعال.
func sniffFor(in Inbound) map[string]any {
	if !in.Sniffing {
		return nil
	}
	dest := in.SniffDest
	if len(dest) == 0 {
		dest = []string{"http", "tls"}
	}
	return map[string]any{"enabled": true, "destOverride": dest}
}

// modeOf حالت xhttp را برمی‌گرداند (پیش‌فرض auto).
func modeOf(in Inbound) string {
	if in.Mode == "" {
		return "auto"
	}
	return in.Mode
}
