package main

// xraysec.go: امنیت inbound (none، tls، reality) و ساخت لینک کلاینت.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// TLSSettings برای حالت tls: گواهی و کلید روی سرور خارج باید از قبل وجود داشته باشند.
type TLSSettings struct {
	ServerName        string   `json:"server_name"`
	CertFile          string   `json:"cert_file"`
	KeyFile           string   `json:"key_file"`
	ALPN              []string `json:"alpn,omitempty"`
	MinVersion        string   `json:"min_version,omitempty"`
	MaxVersion        string   `json:"max_version,omitempty"`
	CipherSuites      []string `json:"cipher_suites,omitempty"`
	Curves            []string `json:"curves,omitempty"`
	RejectUnknownSNI  bool     `json:"reject_unknown_sni,omitempty"`
	DisableSystemRoot bool     `json:"disable_system_root,omitempty"`
	SessionResumption bool     `json:"session_resumption,omitempty"`
	OCSPStapling      int      `json:"ocsp_stapling,omitempty"`
	OneTimeLoading    bool     `json:"one_time_loading,omitempty"`
	Usage             string   `json:"usage,omitempty"`
	PinnedSHA256      []string `json:"pinned_sha256,omitempty"`
	VerifyPeerName    []string `json:"verify_peer_name,omitempty"`
	MasterKeyLog      string   `json:"master_key_log,omitempty"`
	// Certificates لیست گواهی‌ها (حداکثر ۴). اگر خالی باشد، CertFile/KeyFile استفاده می‌شود.
	Certificates []TLSCert `json:"certificates,omitempty"`
	// ECH (Encrypted Client Hello)
	ECHSockopt bool   `json:"ech_sockopt,omitempty"`
	ECHKey     string `json:"ech_key,omitempty"` // کلید خصوصی سرور؛ هرگز به API برنمی‌گردد
	ECHConfig  string `json:"ech_config,omitempty"`
	// LimitFallback محدودیت سرعت fallback
	LimitFallback *LimitFallback `json:"limit_fallback,omitempty"`
}

// TLSCert یک گواهی TLS به‌صورت مسیر فایل یا محتوای PEM.
// محتوای PEM فقط هنگام ساخت استفاده می‌شود و داخل فایل‌های سرور ذخیره می‌شود؛ در store نمی‌ماند.
type TLSCert struct {
	Mode        string `json:"mode,omitempty"` // file | content
	CertFile    string `json:"cert_file,omitempty"`
	KeyFile     string `json:"key_file,omitempty"`
	CertContent string `json:"cert_content,omitempty"`
	KeyContent  string `json:"key_content,omitempty"`
}

// LimitFallback محدودیت سرعت fallback برای آپلود و دانلود.
type LimitFallback struct {
	UploadAfter   int64 `json:"upload_after,omitempty"`
	UploadBps     int64 `json:"upload_bps,omitempty"`
	UploadBurst   int64 `json:"upload_burst,omitempty"`
	DownloadAfter int64 `json:"download_after,omitempty"`
	DownloadBps   int64 `json:"download_bps,omitempty"`
	DownloadBurst int64 `json:"download_burst,omitempty"`
}

// RealitySettings برای حالت reality.
// PrivateKey فقط داخل فایل‌های سرور می‌ماند و هرگز به API برنمی‌گردد.
type RealitySettings struct {
	Dest         string   `json:"dest"`
	ServerNames  []string `json:"server_names"`
	PrivateKey   string   `json:"private_key"`
	PublicKey    string   `json:"public_key"`
	ShortIDs     []string `json:"short_ids"`
	Show         bool     `json:"show,omitempty"`
	Xver         int      `json:"xver,omitempty"`
	MaxTimeDiff  int      `json:"max_time_diff,omitempty"`
	MinClientVer string   `json:"min_client_ver,omitempty"`
	MaxClientVer string   `json:"max_client_ver,omitempty"`
	SpiderX      string   `json:"spider_x,omitempty"`
	// ML-DSA-65 (پس‌کوانتومی). Seed خصوصی است و هرگز به API برنمی‌گردد.
	MLDSA65Seed   string         `json:"mldsa65_seed,omitempty"`
	MLDSA65Verify string         `json:"mldsa65_verify,omitempty"`
	MasterKeyLog  string         `json:"master_key_log,omitempty"`
	LimitFallback *LimitFallback `json:"limit_fallback,omitempty"`
}

var (
	reSNI     = regexp.MustCompile(`^[A-Za-z0-9.\-]{1,253}$`)
	reShortID = regexp.MustCompile(`^[0-9a-f]{2,16}$`)
)

// validateSecurity امنیت inbound را بررسی می‌کند و تنظیمات غیرمرتبط را پاک می‌کند.
func validateSecurity(in *Inbound) string {
	switch in.Security {
	case "", "none":
		in.Security = "none"
		in.TLS = nil
		in.Reality = nil
		return ""

	case "tls":
		t := in.TLS
		if t == nil {
			return "تنظیمات TLS خالی است"
		}
		if !reSNI.MatchString(t.ServerName) {
			return "server_name برای TLS نامعتبر است"
		}
		if len(t.Certificates) > 4 {
			return "حداکثر ۴ گواهی مجاز است"
		}
		for _, c := range certsOf(t) {
			if _, err := os.Stat(c.CertFile); err != nil {
				return "فایل گواهی روی سرور پیدا نشد"
			}
			if _, err := os.Stat(c.KeyFile); err != nil {
				return "فایل کلید TLS روی سرور پیدا نشد"
			}
		}
		if e := validateTLSExtra(t); e != "" {
			return e
		}
		in.Reality = nil
		return ""

	case "reality":
		r := in.Reality
		if r == nil {
			return "تنظیمات Reality خالی است"
		}
		host, port, err := net.SplitHostPort(r.Dest)
		if err != nil || host == "" {
			return "dest باید به شکل host:port باشد، مثلاً www.microsoft.com:443"
		}
		if p, e := strconv.Atoi(port); e != nil || p < 1 || p > 65535 {
			return "پورت dest نامعتبر است"
		}
		if len(r.ServerNames) == 0 || len(r.ServerNames) > 8 {
			return "server_names باید بین ۱ تا ۸ مورد باشد"
		}
		for _, sn := range r.ServerNames {
			if !reSNI.MatchString(sn) {
				return "یکی از server_names نامعتبر است"
			}
		}
		if len(r.ShortIDs) > 16 {
			return "تعداد shortIds زیاد است"
		}
		for _, sid := range r.ShortIDs {
			if !reShortID.MatchString(sid) || len(sid)%2 != 0 {
				return "shortId باید hex با طول زوج و حداکثر ۱۶ کاراکتر باشد"
			}
		}
		if e := validateRealityExtra(r); e != "" {
			return e
		}
		in.TLS = nil
		return ""
	}
	return "security باید none، tls یا reality باشد"
}

// ensureRealityKeys اگر کلید نبود، با xray x25519 می‌سازد و یک shortId تصادفی می‌گذارد.
func ensureRealityKeys(in *Inbound) error {
	if in.Security != "reality" || in.Reality == nil {
		return nil
	}
	r := in.Reality
	if r.PrivateKey == "" || r.PublicKey == "" {
		out, err := exec.Command(xrayBin, "x25519").CombinedOutput()
		if err != nil {
			return fmt.Errorf("ساخت کلید Reality ناموفق بود: %s", strings.TrimSpace(string(out)))
		}
		priv, pub := parseX25519(string(out))
		if priv == "" || pub == "" {
			return errors.New("خروجی xray x25519 قابل خواندن نیست؛ نسخهٔ Xray را بررسی کن")
		}
		r.PrivateKey, r.PublicKey = priv, pub
	}
	if len(r.ShortIDs) == 0 {
		sid, err := randHex(8)
		if err != nil {
			return err
		}
		r.ShortIDs = []string{sid}
	}
	return nil
}

// parseX25519 خروجی xray x25519 را می‌خواند. نسخه‌های مختلف برچسب‌های متفاوت می‌دهند.
func parseX25519(out string) (priv, pub string) {
	for _, line := range strings.Split(out, "\n") {
		i := strings.Index(line, ":")
		if i < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:i]))
		val := strings.TrimSpace(line[i+1:])
		switch {
		case strings.Contains(key, "private"):
			priv = val
		case strings.Contains(key, "public"), strings.Contains(key, "password"):
			pub = val
		}
	}
	return priv, pub
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// streamFor تنظیمات streamSettings کانفیگ Xray را برای یک inbound می‌سازد.
func streamFor(in Inbound) map[string]any {
	network := in.Network
	if network == "" {
		network = "tcp"
	}
	sec := in.Security
	if sec == "" {
		sec = "none"
	}
	st := map[string]any{"network": network, "security": sec}

	switch sec {
	case "tls":
		t := in.TLS
		if t == nil {
			t = &TLSSettings{}
		}
		usage := t.Usage
		if usage == "" {
			usage = "encipherment"
		}
		certs := make([]map[string]any, 0, 4)
		for _, c := range certsOf(t) {
			cert := map[string]any{"certificateFile": c.CertFile, "keyFile": c.KeyFile, "usage": usage}
			if t.OCSPStapling > 0 {
				cert["ocspStapling"] = t.OCSPStapling
			}
			if t.OneTimeLoading {
				cert["oneTimeLoading"] = true
			}
			certs = append(certs, cert)
		}
		ts := map[string]any{"serverName": t.ServerName, "certificates": certs}
		if len(t.ALPN) > 0 {
			ts["alpn"] = t.ALPN
		}
		if t.MinVersion != "" {
			ts["minVersion"] = t.MinVersion
		}
		if t.MaxVersion != "" {
			ts["maxVersion"] = t.MaxVersion
		}
		if len(t.CipherSuites) > 0 {
			ts["cipherSuites"] = strings.Join(t.CipherSuites, ":")
		}
		if len(t.Curves) > 0 {
			ts["curvePreferences"] = t.Curves
		}
		if t.RejectUnknownSNI {
			ts["rejectUnknownSni"] = true
		}
		if t.DisableSystemRoot {
			ts["disableSystemRoot"] = true
		}
		if t.SessionResumption {
			ts["enableSessionResumption"] = true
		}
		if len(t.PinnedSHA256) > 0 {
			pins := make([]string, 0, len(t.PinnedSHA256))
			for _, h := range t.PinnedSHA256 {
				pins = append(pins, hexToB64(h))
			}
			ts["pinnedPeerCertificateChainSha256"] = pins
		}
		if len(t.VerifyPeerName) > 0 {
			ts["verifyPeerCertByName"] = t.VerifyPeerName
		}
		if t.MasterKeyLog != "" {
			ts["masterKeyLog"] = t.MasterKeyLog
		}
		if t.ECHSockopt {
			ts["echSockopt"] = true
		}
		if t.ECHKey != "" {
			ts["echServerKeys"] = t.ECHKey
		}
		if t.ECHConfig != "" {
			ts["echConfigList"] = t.ECHConfig
		}
		applyLimitFallback(ts, t.LimitFallback)
		st["tlsSettings"] = ts

	case "reality":
		r := in.Reality
		if r == nil {
			r = &RealitySettings{}
		}
		rs := map[string]any{
			"show":        r.Show,
			"dest":        r.Dest,
			"xver":        r.Xver,
			"serverNames": r.ServerNames,
			"privateKey":  r.PrivateKey,
			"shortIds":    r.ShortIDs,
		}
		if r.MaxTimeDiff > 0 {
			rs["maxTimeDiff"] = r.MaxTimeDiff
		}
		if r.MinClientVer != "" {
			rs["minClientVer"] = r.MinClientVer
		}
		if r.MaxClientVer != "" {
			rs["maxClientVer"] = r.MaxClientVer
		}
		if r.MLDSA65Seed != "" {
			rs["mldsa65Seed"] = r.MLDSA65Seed
		}
		if r.MLDSA65Verify != "" {
			rs["mldsa65Verify"] = r.MLDSA65Verify
		}
		if r.MasterKeyLog != "" {
			rs["masterKeyLog"] = r.MasterKeyLog
		}
		applyLimitFallback(rs, r.LimitFallback)
		st["realitySettings"] = rs
	}

	if network == "kcp" {
		st["kcpSettings"] = map[string]any{
			"mtu":              1350,
			"tti":              50,
			"uplinkCapacity":   5,
			"downlinkCapacity": 20,
			"congestion":       false,
			"readBufferSize":   2,
			"writeBufferSize":  2,
			"header":           map[string]any{"type": "none"},
			"seed":             in.Seed,
		}
	}
	if network == "ws" {
		headers := map[string]string{}
		if in.Host != "" {
			headers["Host"] = in.Host
		}
		st["wsSettings"] = map[string]any{"path": pathOf(in), "headers": headers}
	}
	if network == "grpc" {
		st["grpcSettings"] = map[string]any{"serviceName": svcOf(in)}
	}
	if network == "httpupgrade" {
		st["httpupgradeSettings"] = map[string]any{"path": pathOf(in), "host": in.Host}
	}
	if network == "xhttp" {
		st["xhttpSettings"] = map[string]any{"path": pathOf(in), "host": in.Host, "mode": modeOf(in)}
	}
	return st
}

// redactInbound نسخهٔ امن یک inbound برای پاسخ API می‌سازد (بدون کلید خصوصی).
func redactInbound(in Inbound) Inbound {
	out := in
	out.Password = "" // رمز shadowsocks هم محرمانه است
	if in.Reality != nil {
		r := *in.Reality
		r.PrivateKey = ""
		r.MLDSA65Seed = ""
		out.Reality = &r
	}
	if in.TLS != nil {
		t := *in.TLS
		t.ECHKey = ""
		out.TLS = &t
	}
	return out
}

var (
	reSvc        = regexp.MustCompile(`^[A-Za-z0-9_.\-]{1,64}$`)
	fpAllowed    = map[string]bool{"chrome": true, "firefox": true, "safari": true, "ios": true, "android": true, "edge": true, "random": true}
	sniffAllowed = map[string]bool{"http": true, "tls": true, "quic": true, "fakedns": true}
	xhttpModes   = map[string]bool{"auto": true, "packet-up": true, "stream-up": true, "stream-one": true}
)

// validateAdvanced تنظیمات تکمیلی inbound را بررسی و مقدارهای پیش‌فرض را تعیین می‌کند.
func validateAdvanced(in *Inbound) string {
	if in.Listen != "" && net.ParseIP(in.Listen) == nil {
		return "Listen باید یک IP معتبر باشد یا خالی بماند"
	}
	if in.Sniffing {
		if len(in.SniffDest) == 0 {
			in.SniffDest = []string{"http", "tls"}
		}
		for _, d := range in.SniffDest {
			if !sniffAllowed[d] {
				return "مقصد sniffing نامعتبر است: " + d
			}
		}
	} else {
		in.SniffDest = nil
	}
	switch in.Network {
	case "ws", "httpupgrade", "xhttp":
		if in.Path == "" {
			in.Path = "/"
		}
		if !strings.HasPrefix(in.Path, "/") || len(in.Path) > 200 || strings.ContainsAny(in.Path, " \t\r\n") {
			return "مسیر ws باید با / شروع شود و فاصله نداشته باشد"
		}
	case "grpc":
		if in.ServiceName == "" {
			in.ServiceName = "grpc"
		}
		if !reSvc.MatchString(in.ServiceName) {
			return "service name نامعتبر است (فقط حروف انگلیسی، عدد، نقطه، _ یا -)"
		}
	}
	if in.Host != "" && !reSNI.MatchString(in.Host) {
		return "host نامعتبر است"
	}
	if in.Network == "xhttp" {
		if in.Mode == "" {
			in.Mode = "auto"
		}
		if !xhttpModes[in.Mode] {
			return "mode باید auto، packet-up، stream-up یا stream-one باشد"
		}
	} else {
		in.Mode = ""
	}
	if in.Fingerprint == "" {
		in.Fingerprint = "chrome"
	}
	if !fpAllowed[in.Fingerprint] {
		return "fingerprint نامعتبر است"
	}
	if in.DisableFlow {
		in.Flow = ""
	}
	if e := validateBasicExtras(in); e != "" {
		return e
	}
	if in.Flow != "" {
		if in.Flow != "xtls-rprx-vision" {
			return "flow فقط xtls-rprx-vision است یا خالی"
		}
		if in.Protocol != "vless" || in.Network != "tcp" || (in.Security != "tls" && in.Security != "reality") {
			return "xtls-rprx-vision فقط برای vless روی tcp با tls یا reality است"
		}
	}
	return ""
}

var (
	reVer     = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){0,2}$`)
	reALPN    = regexp.MustCompile(`^[A-Za-z0-9./_\-]{1,32}$`)
	reCipher  = regexp.MustCompile(`^[A-Za-z0-9_]{3,64}$`)
	reSHA256  = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	reSpiderX = regexp.MustCompile(`^/[A-Za-z0-9._~/%?&=+\-]{0,200}$`)
	reKeyLog  = regexp.MustCompile(`^/[A-Za-z0-9._/\-]{1,200}$`)
	tlsVer    = map[string]bool{"1.0": true, "1.1": true, "1.2": true, "1.3": true}
	tlsCurve  = map[string]bool{"X25519": true, "P-256": true, "P-384": true, "P-521": true}
	tlsUsage  = map[string]bool{"encipherment": true, "verify": true, "issue": true}
)

// validateTLSExtra تنظیمات تکمیلی TLS را بررسی می‌کند.
func validateTLSExtra(t *TLSSettings) string {
	if len(t.ALPN) > 8 {
		return "تعداد ALPN زیاد است"
	}
	for _, a := range t.ALPN {
		if !reALPN.MatchString(a) {
			return "ALPN نامعتبر است: " + a
		}
	}
	if t.MinVersion != "" && !tlsVer[t.MinVersion] {
		return "حداقل نسخهٔ TLS نامعتبر است"
	}
	if t.MaxVersion != "" && !tlsVer[t.MaxVersion] {
		return "حداکثر نسخهٔ TLS نامعتبر است"
	}
	if t.MinVersion != "" && t.MaxVersion != "" && t.MinVersion > t.MaxVersion {
		return "حداقل نسخهٔ TLS نباید از حداکثر بیشتر باشد"
	}
	if len(t.CipherSuites) > 32 {
		return "تعداد cipher suite زیاد است"
	}
	for _, c := range t.CipherSuites {
		if !reCipher.MatchString(c) {
			return "cipher suite نامعتبر است: " + c
		}
	}
	for _, c := range t.Curves {
		if !tlsCurve[c] {
			return "curve نامعتبر است: " + c
		}
	}
	if t.OCSPStapling < 0 || t.OCSPStapling > 86400 {
		return "OCSP Stapling باید بین ۰ تا ۸۶۴۰۰ ثانیه باشد"
	}
	if t.Usage == "" {
		t.Usage = "encipherment"
	}
	if !tlsUsage[t.Usage] {
		return "usage باید encipherment، verify یا issue باشد"
	}
	if len(t.PinnedSHA256) > 8 {
		return "تعداد Pinned SHA-256 زیاد است"
	}
	for i, h := range t.PinnedSHA256 {
		if !reSHA256.MatchString(h) {
			return "Pinned SHA-256 باید ۶۴ کاراکتر هگز باشد"
		}
		t.PinnedSHA256[i] = strings.ToLower(h)
	}
	if len(t.VerifyPeerName) > 8 {
		return "تعداد Verify Peer Cert By Name زیاد است"
	}
	for _, n := range t.VerifyPeerName {
		if !reSNI.MatchString(n) {
			return "Verify Peer Cert By Name نامعتبر است: " + n
		}
	}
	if t.MasterKeyLog != "" && !reKeyLog.MatchString(t.MasterKeyLog) {
		return "مسیر Master Key Log باید مسیر مطلق و بدون فاصله باشد"
	}
	if t.ECHKey != "" {
		t.ECHKey = cleanB64(t.ECHKey)
		if !validB64(t.ECHKey) {
			return "ECH key نامعتبر است"
		}
	}
	if t.ECHConfig != "" {
		t.ECHConfig = cleanB64(t.ECHConfig)
		if !validB64(t.ECHConfig) {
			return "ECH config نامعتبر است"
		}
	}
	if e := validateLimitFallback(t.LimitFallback); e != "" {
		return e
	}
	return ""
}

// validateRealityExtra تنظیمات تکمیلی Reality را بررسی و SpiderX را پیش‌فرض می‌کند.
func validateRealityExtra(r *RealitySettings) string {
	if r.Xver < 0 || r.Xver > 2 {
		return "xver باید بین ۰ تا ۲ باشد"
	}
	if r.MaxTimeDiff < 0 || r.MaxTimeDiff > 86400000 {
		return "Max Time Diff نامعتبر است"
	}
	if r.MinClientVer != "" && !reVer.MatchString(r.MinClientVer) {
		return "Min Client Ver باید به شکل x.y.z باشد"
	}
	if r.MaxClientVer != "" && !reVer.MatchString(r.MaxClientVer) {
		return "Max Client Ver باید به شکل x.y.z باشد"
	}
	if r.MinClientVer != "" && r.MaxClientVer != "" && verCmp(r.MinClientVer, r.MaxClientVer) > 0 {
		return "Min Client Ver نباید از Max Client Ver بزرگ‌تر باشد"
	}
	if r.SpiderX == "" {
		r.SpiderX = "/"
	}
	if !reSpiderX.MatchString(r.SpiderX) {
		return "SpiderX باید با / شروع شود و فاصله نداشته باشد"
	}
	if r.MLDSA65Seed != "" {
		r.MLDSA65Seed = cleanB64(r.MLDSA65Seed)
		if !validB64(r.MLDSA65Seed) {
			return "ML-DSA-65 seed نامعتبر است"
		}
	}
	if r.MLDSA65Verify != "" {
		r.MLDSA65Verify = cleanB64(r.MLDSA65Verify)
		if !validB64(r.MLDSA65Verify) {
			return "ML-DSA-65 verify نامعتبر است"
		}
	}
	if r.MasterKeyLog != "" && !reKeyLog.MatchString(r.MasterKeyLog) {
		return "مسیر Master Key Log باید مسیر مطلق و بدون فاصله باشد"
	}
	if e := validateLimitFallback(r.LimitFallback); e != "" {
		return e
	}
	return ""
}

// spiderOf مسیر SpiderX را برای لینک کلاینت برمی‌گرداند.
func spiderOf(r *RealitySettings) string {
	if r == nil || r.SpiderX == "" {
		return "/"
	}
	return r.SpiderX
}

// hexToB64 هش هگز را به base64 تبدیل می‌کند (فرمت مورد انتظار Xray).
func hexToB64(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil {
		return h
	}
	return base64.StdEncoding.EncodeToString(b)
}

// verCmp دو نسخه‌ی x.y.z را مقایسه می‌کند (-1، 0 یا 1).
func verCmp(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < 3; i++ {
		x, y := verPart(pa, i), verPart(pb, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func verPart(p []string, i int) int {
	if i >= len(p) {
		return 0
	}
	n, _ := strconv.Atoi(p[i])
	return n
}

var reB64Blob = regexp.MustCompile(`^[A-Za-z0-9+/=_\-]+$`)

// validB64 مقدار base64 را با سقف طول ۸۱۹۲ بررسی می‌کند.
func validB64(s string) bool {
	return len(s) > 0 && len(s) <= 8192 && reB64Blob.MatchString(s)
}

// cleanB64 فاصله و خط جدید را از یک مقدار base64 حذف می‌کند.
func cleanB64(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// certsOf فهرست گواهی‌های TLS را برمی‌گرداند. اگر لیست خالی باشد، گواهی تکی قدیمی را برمی‌گرداند.
func certsOf(t *TLSSettings) []TLSCert {
	if t == nil {
		return nil
	}
	if len(t.Certificates) > 0 {
		return t.Certificates
	}
	return []TLSCert{{CertFile: t.CertFile, KeyFile: t.KeyFile}}
}

// validateLimitFallback مقدارهای منفی را رد می‌کند.
func validateLimitFallback(lf *LimitFallback) string {
	if lf == nil {
		return ""
	}
	for _, v := range []int64{lf.UploadAfter, lf.UploadBps, lf.UploadBurst, lf.DownloadAfter, lf.DownloadBps, lf.DownloadBurst} {
		if v < 0 {
			return "مقدارهای Limit Fallback نمی‌توانند منفی باشند"
		}
	}
	return ""
}

// applyLimitFallback مقدارهای Limit Fallback را داخل تنظیمات امنیت می‌گذارد.
func applyLimitFallback(m map[string]any, lf *LimitFallback) {
	if lf == nil {
		return
	}
	m["limitFallbackUpload"] = map[string]any{"afterBytes": lf.UploadAfter, "bytesPerSec": lf.UploadBps, "burstBytesPerSec": lf.UploadBurst}
	m["limitFallbackDownload"] = map[string]any{"afterBytes": lf.DownloadAfter, "bytesPerSec": lf.DownloadBps, "burstBytesPerSec": lf.DownloadBurst}
}
