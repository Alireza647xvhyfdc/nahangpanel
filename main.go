package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// version با -ldflags "-X main.version=vX.Y.Z" در build تنظیم می‌شود
var version = "dev"

//go:embed index.html login.html
var ui embed.FS

const dir = "/etc/tunnelpanel/"

type Tunnel struct {
	Name      string   `json:"name"`
	Role      string   `json:"role"` // server (ایران) | client (خارج)
	Transport string   `json:"transport"`
	Addr      string   `json:"addr"` // server: bind addr, client: remote addr
	Token     string   `json:"token,omitempty"`
	Ports     []string `json:"ports"`
	Allow     string   `json:"allow,omitempty"`   // فقط این IP به پورت تانل (سرور ایران) دسترسی دارد
	Stopped   bool     `json:"stopped,omitempty"` // توقف دستی؛ نگهبان ری‌استارت نمی‌کند
	Inbound   int      `json:"inbound,omitempty"` // پورت inbound این سرور که تانل به آن وصل است (فقط سرور خارج)
}

type Settings struct {
	TgToken string `json:"tg_token"`
	TgChat  string `json:"tg_chat"`
}

type failInfo struct {
	n     int
	until time.Time
}

var (
	set     Settings
	setMu   sync.Mutex
	fails   = map[string]*failInfo{}
	failMu  sync.Mutex
	mu      sync.Mutex
	tunnels = map[string]Tunnel{}
	reName  = regexp.MustCompile(`^[a-z0-9-]{1,20}$`)
	reTok   = regexp.MustCompile(`^[A-Za-z0-9]{8,64}$`)
	rePlain = regexp.MustCompile(`^[0-9]{1,5}$`)
	rePort  = regexp.MustCompile(`^[0-9a-z.:=\-]{1,60}$`)
	reTg    = regexp.MustCompile(`^[0-9]{5,12}:[A-Za-z0-9_-]{30,50}$`)
	reChat  = regexp.MustCompile(`^-?[0-9]{3,20}$`)
	okTrans = map[string]bool{"nahang": true, "nahangx": true, "tcp": true, "tcpmux": true, "ws": true, "wsmux": true, "wss": true, "wssmux": true}
)

func sh(a ...string) (string, error) {
	o, err := exec.Command(a[0], a[1:]...).CombinedOutput()
	return strings.TrimSpace(string(o)), err
}

func save() { b, _ := json.MarshalIndent(tunnels, "", " "); os.WriteFile(dir+"tunnels.json", b, 0600) }

func load() {
	os.MkdirAll(dir, 0700)
	if b, err := os.ReadFile(dir + "tunnels.json"); err == nil {
		json.Unmarshal(b, &tunnels)
	}
}

func units(t Tunnel) []string {
	return []string{"tp-" + t.Name}
}

func remove(t Tunnel) {
	for _, u := range units(t) {
		sh("systemctl", "disable", "--now", u)
		os.Remove("/etc/systemd/system/" + u + ".service")
		os.Remove(dir + u + ".toml")
		os.Remove(dir + u + ".json")
	}
	os.Remove(dir + t.Name + ".toml")
	sh("systemctl", "daemon-reload")
}

func apply(t Tunnel) error {
	if !okTrans[t.Transport] {
		return fmt.Errorf("transport %q is no longer supported; delete this tunnel and create it again", t.Transport)
	}
	for _, u := range units(t) {
		addr := t.Addr
		if t.Transport == "nahang" || t.Transport == "nahangx" {
			cfg := dir + u + ".json"
			b, _ := json.Marshal(nCfg{Role: t.Role, Addr: addr, Token: t.Token, Ports: t.Ports,
				TLS: t.Transport == "nahangx", Fast: t.Transport == "nahangx"})
			if err := os.WriteFile(cfg, b, 0600); err != nil {
				return err
			}
			exe, _ := os.Executable()
			unit := fmt.Sprintf("[Unit]\nDescription=Tunnel %s\nAfter=network.target\n\n[Service]\nExecStart=%s -nahang %s\nRestart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n", u, exe, cfg)
			if err := os.WriteFile("/etc/systemd/system/"+u+".service", []byte(unit), 0644); err != nil {
				return err
			}
			sh("systemctl", "daemon-reload")
			if _, err := sh("systemctl", "enable", "--now", u); err != nil {
				return err
			}
			continue
		}
		var c strings.Builder
		if t.Role == "server" {
			fmt.Fprintf(&c, "[server]\nbind_addr = %q\ntransport = %q\ntoken = %q\nnodelay = true\nkeepalive_period = 75\n", addr, t.Transport, t.Token)
			if strings.HasPrefix(t.Transport, "wss") {
				fmt.Fprintf(&c, "tls_cert = %q\ntls_key = %q\n", dir+"cert.pem", dir+"key.pem")
			}
			q := make([]string, len(t.Ports))
			for j, p := range t.Ports {
				q[j] = fmt.Sprintf("%q", p)
			}
			fmt.Fprintf(&c, "ports = [%s]\n", strings.Join(q, ", "))
		} else {
			fmt.Fprintf(&c, "[client]\nremote_addr = %q\ntransport = %q\ntoken = %q\nnodelay = true\nkeepalive_period = 75\nretry_interval = 3\n", addr, t.Transport, t.Token)
		}
		cfg := dir + u + ".toml"
		if err := os.WriteFile(cfg, []byte(c.String()), 0600); err != nil {
			return err
		}
		unit := fmt.Sprintf("[Unit]\nDescription=Tunnel %s\nAfter=network.target\n\n[Service]\nExecStart=/usr/local/bin/backhaul -c %s\nRestart=always\nRestartSec=3\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n", u, cfg)
		if err := os.WriteFile("/etc/systemd/system/"+u+".service", []byte(unit), 0644); err != nil {
			return err
		}
		sh("systemctl", "daemon-reload")
		if _, err := sh("systemctl", "enable", "--now", u); err != nil {
			return err
		}
	}
	return nil
}

// فایروال: پورت‌ها فقط برای IP مجاز باز می‌مانند (ایران: پورت تانل | خارج: پورت‌های قفل‌شونده)
func fw(t Tunnel, add bool) {
	if t.Allow == "" {
		return
	}
	var ports []string
	if t.Role == "server" {
		if _, p, err := net.SplitHostPort(t.Addr); err == nil {
			ports = []string{p}
		}
	} else {
		for _, p := range t.Ports {
			if rePlain.MatchString(p) && p != "22" {
				ports = append(ports, p)
			}
		}
	}
	ch := "tp-" + t.Name
	if add {
		sh("iptables", "-N", ch)
		sh("iptables", "-F", ch)
		sh("iptables", "-A", ch, "-i", "lo", "-j", "ACCEPT")
		sh("iptables", "-A", ch, "-s", t.Allow, "-j", "ACCEPT")
		sh("iptables", "-A", ch, "-j", "DROP")
		for _, p := range ports {
			if _, err := sh("iptables", "-C", "INPUT", "-p", "tcp", "--dport", p, "-j", ch); err != nil {
				sh("iptables", "-I", "INPUT", "-p", "tcp", "--dport", p, "-j", ch)
			}
			if _, err := sh("ip6tables", "-C", "INPUT", "-p", "tcp", "--dport", p, "!", "-i", "lo", "-j", "DROP"); err != nil {
				sh("ip6tables", "-I", "INPUT", "-p", "tcp", "--dport", p, "!", "-i", "lo", "-j", "DROP")
			}
		}
	} else {
		for _, p := range ports {
			sh("iptables", "-D", "INPUT", "-p", "tcp", "--dport", p, "-j", ch)
			sh("ip6tables", "-D", "INPUT", "-p", "tcp", "--dport", p, "!", "-i", "lo", "-j", "DROP")
		}
		sh("iptables", "-F", ch)
		sh("iptables", "-X", ch)
	}
}

func reply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func bad(w http.ResponseWriter, msg string) { reply(w, 400, map[string]string{"error": msg}) }

func loadSettings() {
	if b, err := os.ReadFile(dir + "settings.json"); err == nil {
		json.Unmarshal(b, &set)
	}
}

func saveSettings() { b, _ := json.Marshal(set); os.WriteFile(dir+"settings.json", b, 0600) }

// اعلان تلگرام (روی سرور خارج تنظیم شود؛ از ایران معمولاً در دسترس نیست)
func notify(msg string) error {
	setMu.Lock()
	s := set
	setMu.Unlock()
	if s.TgToken == "" || s.TgChat == "" {
		return fmt.Errorf("تلگرام تنظیم نشده است")
	}
	h, _ := os.Hostname()
	c := http.Client{Timeout: 10 * time.Second}
	r, err := c.PostForm("https://api.telegram.org/bot"+s.TgToken+"/sendMessage", url.Values{"chat_id": {s.TgChat}, "text": {msg + "\n(" + h + ")"}})
	if err != nil {
		return fmt.Errorf("ارسال نشد؛ دسترسی به تلگرام ممکن نیست")
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return fmt.Errorf("تلگرام خطا داد؛ توکن یا شناسه‌ی چت را بررسی کنید")
	}
	return nil
}

// اتصال‌های برقرارشده‌ی سیستم (یک بار برای همه‌ی تانل‌ها)
func conns() []string {
	o, _ := sh("ss", "-Htn", "state", "established")
	return strings.Split(o, "\n")
}

// تعداد اتصال واقعی تانل؛ -1 یعنی قابل تشخیص نیست
func linked(t Tunnel, lines []string) int {
	host, port, err := net.SplitHostPort(t.Addr)
	if err != nil || (t.Role == "client" && net.ParseIP(host) == nil) {
		return -1
	}
	n := 0
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		if (t.Role == "server" && strings.HasSuffix(f[2], ":"+port)) || (t.Role == "client" && f[3] == t.Addr) {
			n++
		}
	}
	return n
}

func validate(t *Tunnel) string {
	if e := bindInbound(t); e != "" {
		return e
	}
	if !reName.MatchString(t.Name) || !okTrans[t.Transport] || !reTok.MatchString(t.Token) || (t.Role != "server" && t.Role != "client") {
		return "ورودی نامعتبر"
	}
	host, _, err := net.SplitHostPort(t.Addr)
	if err != nil || (t.Role == "client" && host == "") {
		return "آدرس باید به شکل IP:PORT باشد"
	}
	for _, p := range t.Ports {
		if !rePort.MatchString(p) {
			return "پورت نامعتبر: " + p
		}
	}
	if t.Role == "server" && len(t.Ports) == 0 {
		return "حداقل یک پورت لازم است"
	}
	if t.Allow != "" && net.ParseIP(t.Allow) == nil {
		return "IP مجاز نامعتبر است"
	}
	if t.Role == "client" && len(t.Ports) > 0 {
		if t.Allow == "" {
			return "برای قفل پورت، IP سرور ایران لازم است"
		}
		for _, p := range t.Ports {
			if !rePlain.MatchString(p) || p == "22" {
				return "فقط شماره پورت (به‌جز ۲۲) مجاز است"
			}
		}
	}
	return ""
}

// ساخت یا جایگزینی تانل (mu باید قفل باشد)
func create(t Tunnel) error {
	if old, ok := tunnels[t.Name]; ok {
		fw(old, false)
		remove(old)
	}
	if err := apply(t); err != nil {
		return err
	}
	fw(t, true)
	t.Stopped = false
	tunnels[t.Name] = t
	save()
	return nil
}

func guardian() {
	badN := map[string]int{}
	sent := map[string]bool{}
	rs := map[string][]time.Time{}
	for range time.Tick(30 * time.Second) {
		lines := conns()
		mu.Lock()
		for n, t := range tunnels {
			if t.Stopped {
				continue
			}
			act := true
			for _, u := range units(t) {
				if s, _ := sh("systemctl", "is-active", u); s == "failed" || s == "inactive" {
					act = false
					sh("systemctl", "restart", u)
					now := time.Now()
					keep := []time.Time{}
					for _, x := range rs[n] {
						if now.Sub(x) < 10*time.Minute {
							keep = append(keep, x)
						}
					}
					rs[n] = append(keep, now)
					if len(rs[n]) >= 3 && !sent[n+"#r"] {
						sent[n+"#r"] = true
						go notify("⚠️ تانل " + n + " مدام از کار می‌افتد (۳ ری‌استارت در ۱۰ دقیقه)")
					}
				}
			}
			if act && linked(t, lines) != 0 {
				if sent[n] {
					go notify("✅ تانل " + n + " دوباره وصل شد")
				}
				badN[n], sent[n], sent[n+"#r"] = 0, false, false
			} else if badN[n]++; badN[n] == 2 {
				sent[n] = true
				go notify("🔴 تانل " + n + " قطع است (اتصالی برقرار نیست)")
			}
		}
		mu.Unlock()
	}
}

// نشست ورود: کوکی امضاشده با کلید تصادفی (با ری‌استارت سرویس همه دوباره وارد می‌شوند)
var sessKey = func() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}()

const (
	sessName = "tp_session"
	sessTTL  = 12 * time.Hour
	// همان سیاست امنیتی صفحه اصلی
	pageCSP = "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src data:; connect-src 'self'; frame-ancestors 'none'"
)

func sign(s string) string {
	m := hmac.New(sha256.New, sessKey)
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

func blocked(ip string) bool {
	failMu.Lock()
	defer failMu.Unlock()
	f := fails[ip]
	return f != nil && time.Now().Before(f.until)
}

func failed(ip string) {
	failMu.Lock()
	defer failMu.Unlock()
	if len(fails) > 1000 {
		fails = map[string]*failInfo{}
	}
	f := fails[ip]
	if f == nil {
		f = &failInfo{}
		fails[ip] = f
	}
	if f.n++; f.n >= 5 {
		f.n, f.until = 0, time.Now().Add(5*time.Minute)
	}
}

func clearFails(ip string) {
	failMu.Lock()
	defer failMu.Unlock()
	delete(fails, ip)
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "-nahang" {
		runNahan(os.Args[2])
		return
	}
	port := flag.String("port", "8443", "پورت پنل")
	user := flag.String("user", "admin", "نام کاربری")
	pass := flag.String("pass", "", "رمز عبور (یا TP_PASS یا فایل "+dir+"pass)")
	listen := flag.String("listen", "127.0.0.1", "آدرس گوش‌دادن پنل (پیش‌فرض: فقط محلی)")
	flag.String("allow", "", "منسوخ: نادیده گرفته می‌شود (برای سازگاری با سرویس‌های قدیمی)")
	useTLS := flag.Bool("tls", false, "HTTPS با گواهی "+dir+"cert.pem")
	showVer := flag.Bool("version", false, "نمایش نسخه و خروج")
	flag.Parse()
	if *showVer {
		fmt.Println(version)
		return
	}
	pw := *pass
	if pw == "" {
		pw = os.Getenv("TP_PASS")
	}
	if pw == "" {
		if b, err := os.ReadFile(dir + "pass"); err == nil {
			pw = strings.TrimSpace(string(b))
		}
	}
	if len(pw) < 8 {
		fmt.Println("رمز عبور باید حداقل ۸ کاراکتر باشد")
		os.Exit(1)
	}
	load()
	loadSettings()
	setOwner(*user, pw)
	for _, t := range tunnels {
		fw(t, true)
	}
	go guardian()
	startXrayMonitor()

	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			ip, _, _ := net.SplitHostPort(r.RemoteAddr)
			if blocked(ip) {
				http.Error(w, "تلاش‌های ناموفق زیاد؛ چند دقیقه بعد دوباره امتحان کنید", 429)
				return
			}
			user, role := identify(r, ip)
			if role == "" {
				if r.Header.Get("Authorization") != "" {
					failed(ip)
				}
				if r.Method == "GET" && r.URL.Path == "/" {
					http.Redirect(w, r, "/login", http.StatusFound)
					return
				}
				reply(w, 401, map[string]string{"error": "unauthorized"})
				return
			}
			// viewer فقط می‌تواند بخواند؛ هر تغییری فقط برای owner است
			if r.Method != "GET" && role != "owner" {
				reply(w, 403, map[string]string{"error": "فقط مدیر اصلی می‌تواند تغییر دهد"})
				return
			}
			// جلوگیری از CSRF: درخواست‌های تغییردهنده باید هدر سفارشی و Origin هم‌میزبان داشته باشند
			if r.Method != "GET" {
				if r.Header.Get("X-Requested-With") != "tunnelpanel" {
					http.Error(w, "forbidden", 403)
					return
				}
				if o := r.Header.Get("Origin"); o != "" {
					if ou, err := url.Parse(o); err != nil || ou.Host != r.Host {
						http.Error(w, "forbidden", 403)
						return
					}
				}
			}
			h(w, withIdent(r, user, role))
		}
	}

	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", auth(func(w http.ResponseWriter, r *http.Request) {
		b, _ := ui.ReadFile("index.html")
		b = []byte(strings.ReplaceAll(string(b), "__VERSION__", version))
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", pageCSP)
		w.Write(b)
	}))
	m.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		if _, role := sessionIdent(r); role != "" {
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		b, _ := ui.ReadFile("login.html")
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", pageCSP)
		w.Write(b)
	})
	m.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if r.Header.Get("X-Requested-With") != "tunnelpanel" {
			http.Error(w, "forbidden", 403)
			return
		}
		if blocked(ip) {
			reply(w, 429, map[string]string{"error": "تلاش‌های ناموفق زیاد؛ چند دقیقه بعد دوباره امتحان کنید"})
			return
		}
		var in struct {
			User string `json:"user"`
			Pass string `json:"pass"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in) != nil {
			bad(w, "ورودی نامعتبر")
			return
		}
		user, role := loginRole(in.User, in.Pass)
		if role == "" {
			failed(ip)
			reply(w, 401, map[string]string{"error": "نام کاربری یا رمز عبور اشتباه است"})
			return
		}
		clearFails(ip)
		http.SetCookie(w, &http.Cookie{Name: sessName, Value: newSession(user, role), Path: "/", HttpOnly: true, Secure: *useTLS, SameSite: http.SameSiteStrictMode, MaxAge: int(sessTTL.Seconds())})
		reply(w, 200, map[string]bool{"ok": true})
	})
	m.HandleFunc("GET /api/tunnels", auth(func(w http.ResponseWriter, r *http.Request) {
		lines := conns()
		mu.Lock()
		defer mu.Unlock()
		out := []map[string]any{}
		remarks := inboundRemarks()
		for n, t := range tunnels {
			us := units(t)
			on := 0
			for _, u := range us {
				if s, _ := sh("systemctl", "is-active", u); s == "active" {
					on++
				}
			}
			out = append(out, map[string]any{"name": n, "role": t.Role, "transport": t.Transport, "addr": t.Addr, "ports": t.Ports, "allow": t.Allow, "stopped": t.Stopped, "on": on, "total": len(us), "conns": linked(t, lines), "inbound": t.Inbound, "inbound_name": remarks[t.Inbound]})
		}
		reply(w, 200, out)
	}))
	m.HandleFunc("GET /api/tunnels/{name}", auth(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		t, ok := tunnels[r.PathValue("name")]
		mu.Unlock()
		if !ok {
			reply(w, 404, map[string]string{"error": "پیدا نشد"})
			return
		}
		reply(w, 200, t)
	}))
	m.HandleFunc("POST /api/tunnels", auth(func(w http.ResponseWriter, r *http.Request) {
		var t Tunnel
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&t) != nil {
			bad(w, "ورودی نامعتبر")
			return
		}
		if e := validate(&t); e != "" {
			bad(w, e)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if err := create(t); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]string{"ok": "1"})
	}))
	m.HandleFunc("POST /api/tunnels/{name}/{act}", auth(func(w http.ResponseWriter, r *http.Request) {
		n, act := r.PathValue("name"), r.PathValue("act")
		mu.Lock()
		defer mu.Unlock()
		if _, ok := tunnels[n]; !ok {
			reply(w, 404, map[string]string{"error": "پیدا نشد"})
			return
		}
		switch act {
		case "start", "stop", "restart":
			t := tunnels[n]
			for _, u := range units(t) {
				sh("systemctl", act, u)
			}
			t.Stopped = act == "stop"
			tunnels[n] = t
			save()
		case "delete":
			fw(tunnels[n], false)
			remove(tunnels[n])
			delete(tunnels, n)
			save()
		default:
			bad(w, "عملیات نامعتبر")
			return
		}
		reply(w, 200, map[string]string{"ok": "1"})
	}))
	m.HandleFunc("GET /api/tunnels/{name}/logs", auth(func(w http.ResponseWriter, r *http.Request) {
		n := r.PathValue("name")
		if !reName.MatchString(n) {
			return
		}
		mu.Lock()
		t, ok := tunnels[n]
		mu.Unlock()
		if !ok {
			return
		}
		args := []string{"journalctl", "-n", "40", "--no-pager"}
		for _, u := range units(t) {
			args = append(args, "-u", u)
		}
		o, _ := sh(args...)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte(o))
	}))
	m.HandleFunc("GET /api/backup", auth(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tn := make(map[string]Tunnel, len(tunnels))
		for k, v := range tunnels {
			tn[k] = v
		}
		mu.Unlock()
		xs, err := loadStore() // تانل‌ها و کلاینت/اینباند Xray هر دو داخل پشتیبان می‌روند
		if err != nil {
			bad(w, "خواندن اطلاعات Xray ناموفق بود: "+err.Error())
			return
		}
		b, _ := json.MarshalIndent(backupFile{Format: "tunnelpanel-backup", Version: 2, Tunnels: tn, Xray: xs}, "", " ")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="tunnels-backup.json"`)
		w.Write(b)
	}))
	m.HandleFunc("POST /api/restore", auth(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<20))
		if err != nil {
			bad(w, "فایل پشتیبان نامعتبر است")
			return
		}
		var bf backupFile
		tunnelsIn := map[string]Tunnel{}
		if json.Unmarshal(body, &bf) == nil && bf.Format == "tunnelpanel-backup" {
			tunnelsIn = bf.Tunnels
		} else if json.Unmarshal(body, &tunnelsIn) != nil { // فرمت قدیمی: فقط نقشهٔ تانل‌ها
			bad(w, "فایل پشتیبان نامعتبر است")
			return
		}
		mu.Lock()
		defer mu.Unlock()
		okN, errs := 0, []string{}
		for n, t := range tunnelsIn {
			t.Name = n
			if e := validate(&t); e != "" {
				errs = append(errs, n+": "+e)
			} else if err := create(t); err != nil {
				errs = append(errs, n+": "+err.Error())
			} else {
				okN++
			}
		}
		xrayN := 0
		if bf.Xray != nil {
			n, e := restoreXrayStore(bf.Xray)
			xrayN = n
			if e != nil {
				errs = append(errs, "Xray: "+e.Error())
			}
		}
		reply(w, 200, map[string]any{"ok": okN, "xray_clients": xrayN, "errors": errs})
	}))
	registerSys(m, auth)
	m.HandleFunc("GET /api/settings", auth(func(w http.ResponseWriter, r *http.Request) {
		setMu.Lock()
		defer setMu.Unlock()
		reply(w, 200, map[string]any{"tg": set.TgToken != "", "chat": set.TgChat})
	}))
	m.HandleFunc("POST /api/settings", auth(func(w http.ResponseWriter, r *http.Request) {
		var b Settings
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&b) != nil {
			bad(w, "ورودی نامعتبر")
			return
		}
		setMu.Lock()
		defer setMu.Unlock()
		if b.TgToken == "" && b.TgChat != "" {
			b.TgToken = set.TgToken
		}
		if b.TgToken != "" || b.TgChat != "" {
			if !reTg.MatchString(b.TgToken) || !reChat.MatchString(b.TgChat) {
				bad(w, "توکن ربات یا شناسه‌ی چت نامعتبر است")
				return
			}
		}
		set = b
		saveSettings()
		reply(w, 200, map[string]string{"ok": "1"})
	}))
	m.HandleFunc("POST /api/settings/test", auth(func(w http.ResponseWriter, r *http.Request) {
		if err := notify("✅ پیام آزمایشی Nahang"); err != nil {
			bad(w, err.Error())
			return
		}
		reply(w, 200, map[string]string{"ok": "1"})
	}))

	registerXrayRoutes(m, auth)
	registerTunnelBindRoute(m, auth)
	registerAdminRoutes(m, auth)
	fmt.Println("پنل روی پورت", *port, "اجرا شد")
	srv := &http.Server{Addr: *listen + ":" + *port, Handler: m, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
	var err error
	if *useTLS {
		err = srv.ListenAndServeTLS(dir+"cert.pem", dir+"key.pem")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
