package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	adminsFile  = "/etc/tunnelpanel/admins.json"
	pbkdfIter   = 210000
	pbkdfKeyLen = 32
)

var (
	ownerUser   string
	ownerPass   string
	adminMu     sync.Mutex
	reAdminName = regexp.MustCompile(`^[A-Za-z0-9_\-]{3,32}$`)
	dummySalt   = make([]byte, 16)
)

type adminRec struct {
	Username   string `json:"username"`
	Role       string `json:"role"`
	Iter       int    `json:"iter"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	MaxClients int    `json:"max_clients,omitempty"`
	Expire     int64  `json:"expire,omitempty"`
	TotalGB    int    `json:"total_gb,omitempty"`
}

type identKey struct{}

type ident struct{ user, role string }

func setOwner(u, p string) {
	ownerUser, ownerPass = u, p
}

func pbkdf2(pw, salt []byte, iter, keyLen int) []byte {
	hLen := sha256.Size
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	for b := 1; b <= blocks; b++ {
		m := hmac.New(sha256.New, pw)
		m.Write(salt)
		m.Write([]byte{byte(b >> 24), byte(b >> 16), byte(b >> 8), byte(b)})
		u := m.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			m = hmac.New(sha256.New, pw)
			m.Write(u)
			u = m.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

func hashPassword(pw string) (salt, hash string, err error) {
	sb := make([]byte, 16)
	if _, err := rand.Read(sb); err != nil {
		return "", "", err
	}
	h := pbkdf2([]byte(pw), sb, pbkdfIter, pbkdfKeyLen)
	return hex.EncodeToString(sb), hex.EncodeToString(h), nil
}

func verifyPassword(a adminRec, pw string) bool {
	salt, err := hex.DecodeString(a.Salt)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(a.Hash)
	if err != nil || a.Iter <= 0 {
		return false
	}
	got := pbkdf2([]byte(pw), salt, a.Iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func loadAdmins() ([]adminRec, error) {
	b, err := os.ReadFile(adminsFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var list []adminRec
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, fmt.Errorf("admins.json خراب است: %w", err)
	}
	return list, nil
}

func saveAdmins(list []adminRec) error {
	if err := os.MkdirAll("/etc/tunnelpanel", 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(list, "", "  ")
	tmp := adminsFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, adminsFile)
}

func findAdmin(u string) (adminRec, bool) {
	list, err := loadAdmins()
	if err != nil {
		return adminRec{}, false
	}
	for _, a := range list {
		if a.Username == u {
			return a, true
		}
	}
	return adminRec{}, false
}

func currentRole(u string) string {
	if ownerUser != "" && u == ownerUser {
		return "owner"
	}
	if a, ok := findAdmin(u); ok {
		if sellerExpired(a, time.Now()) {
			return ""
		}
		return a.Role
	}
	return ""
}

func loginRole(u, p string) (string, string) {
	if ownerUser != "" &&
		subtle.ConstantTimeCompare([]byte(u), []byte(ownerUser)) == 1 &&
		subtle.ConstantTimeCompare([]byte(p), []byte(ownerPass)) == 1 {
		return ownerUser, "owner"
	}
	a, ok := findAdmin(u)
	if !ok {
		pbkdf2([]byte(p), dummySalt, pbkdfIter, pbkdfKeyLen)
		return "", ""
	}
	if !verifyPassword(a, p) {
		return "", ""
	}
	if sellerExpired(a, time.Now()) {
		return "", ""
	}
	return a.Username, a.Role
}

func newSession(user, role string) string {
	exp := strconv.FormatInt(time.Now().Add(sessTTL).Unix(), 10)
	payload := exp + "|" + user + "|" + role
	return payload + "." + sign(payload)
}

func sessionIdent(r *http.Request) (string, string) {
	c, err := r.Cookie(sessName)
	if err != nil {
		return "", ""
	}
	i := strings.LastIndex(c.Value, ".")
	if i < 0 {
		return "", ""
	}
	payload, sig := c.Value[:i], c.Value[i+1:]
	if !hmac.Equal([]byte(sig), []byte(sign(payload))) {
		return "", ""
	}
	parts := strings.Split(payload, "|")
	if len(parts) != 3 {
		return "", ""
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", ""
	}
	role := currentRole(parts[1])
	if role == "" {
		return "", ""
	}
	return parts[1], role
}

func identify(r *http.Request, ip string) (string, string) {
	if u, role := sessionIdent(r); role != "" {
		return u, role
	}
	bu, bp, ok := r.BasicAuth()
	if !ok {
		return "", ""
	}
	u, role := loginRole(bu, bp)
	if role != "" {
		clearFails(ip)
	}
	return u, role
}

func withIdent(r *http.Request, user, role string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), identKey{}, ident{user, role}))
}

func identOf(r *http.Request) ident {
	v, _ := r.Context().Value(identKey{}).(ident)
	return v
}

func requireOwner(w http.ResponseWriter, r *http.Request) bool {
	if identOf(r).role != "owner" {
		reply(w, 403, map[string]string{"error": "فقط مدیر اصلی دسترسی دارد"})
		return false
	}
	return true
}

func validAdminInput(u, p, role string) string {
	if !reAdminName.MatchString(u) {
		return "نام کاربری باید ۳ تا ۳۲ کاراکتر انگلیسی، عدد، _ یا - باشد"
	}
	if len(p) < 8 || len(p) > 256 {
		return "رمز باید بین ۸ تا ۲۵۶ کاراکتر باشد"
	}
	if role != "owner" && role != "viewer" && role != "seller" {
		return "نقش باید owner، viewer یا seller باشد"
	}
	return ""
}

func registerAdminRoutes(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	m.HandleFunc("GET /api/me", auth(func(w http.ResponseWriter, r *http.Request) {
		id := identOf(r)
		out := map[string]any{"user": id.user, "role": id.role}
		if id.role == "seller" {
			if a, ok := findAdmin(id.user); ok {
				out["expire"] = a.Expire
				out["total_gb"] = a.TotalGB
				if st, err := loadStore(); err == nil {
					out["used_gb"] = float64(sellerUsedBytes(st, a.Username)) / float64(bytesPerGB)
					out["over_quota"] = sellerOverQuota(a, st)
				}
			}
		}
		reply(w, 200, out)
	}))

	m.HandleFunc("GET /api/admins", auth(func(w http.ResponseWriter, r *http.Request) {
		if !requireOwner(w, r) {
			return
		}
		list, err := loadAdmins()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		owned := map[string]int{}
		var stored *Store
		if st, err := loadStore(); err == nil {
			stored = st
			for _, c := range st.Clients {
				if c.Owner != "" {
					owned[c.Owner]++
				}
			}
		}
		out := []map[string]any{{"username": ownerUser, "role": "owner", "primary": true}}
		for _, a := range list {
			item := map[string]any{"username": a.Username, "role": a.Role, "max_clients": a.MaxClients, "clients": owned[a.Username], "expire": a.Expire, "total_gb": a.TotalGB, "used_gb": 0.0, "blocked": false}
			if stored != nil && a.Role == "seller" {
				item["used_gb"] = float64(sellerUsedBytes(stored, a.Username)) / float64(bytesPerGB)
				item["blocked"] = sellerExpired(a, time.Now()) || sellerOverQuota(a, stored)
			}
			out = append(out, item)
		}
		reply(w, 200, out)
	}))

	m.HandleFunc("POST /api/admins", auth(func(w http.ResponseWriter, r *http.Request) {
		if !requireOwner(w, r) {
			return
		}
		var in struct {
			Username   string `json:"username"`
			Password   string `json:"password"`
			Role       string `json:"role"`
			MaxClients int    `json:"max_clients"`
			Expire     int64  `json:"expire"`
			TotalGB    int    `json:"total_gb"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in) != nil {
			reply(w, 400, map[string]string{"error": "ورودی نامعتبر"})
			return
		}
		if e := validAdminInput(in.Username, in.Password, in.Role); e != "" {
			reply(w, 400, map[string]string{"error": e})
			return
		}
		if in.MaxClients < 0 || in.MaxClients > 1000000 {
			reply(w, 400, map[string]string{"error": "سقف تعداد کلاینت نامعتبر است"})
			return
		}
		maxClients := 0
		var sellerExp int64
		sellerTGB := 0
		if in.Role == "seller" {
			maxClients = in.MaxClients
			if e := validSellerLimits(in.Expire, in.TotalGB); e != "" {
				reply(w, 400, map[string]string{"error": e})
				return
			}
			sellerExp, sellerTGB = in.Expire, in.TotalGB
		}
		adminMu.Lock()
		defer adminMu.Unlock()
		list, err := loadAdmins()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if in.Username == ownerUser {
			reply(w, 400, map[string]string{"error": "این نام کاربری رزرو شده است"})
			return
		}
		for _, a := range list {
			if a.Username == in.Username {
				reply(w, 400, map[string]string{"error": "این نام کاربری قبلاً ساخته شده"})
				return
			}
		}
		salt, hash, err := hashPassword(in.Password)
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		list = append(list, adminRec{Username: in.Username, Role: in.Role, Iter: pbkdfIter, Salt: salt, Hash: hash, MaxClients: maxClients, Expire: sellerExp, TotalGB: sellerTGB})
		if err := saveAdmins(list); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]string{"ok": "1"})
	}))

	m.HandleFunc("POST /api/admins/{name}", auth(func(w http.ResponseWriter, r *http.Request) {
		if !requireOwner(w, r) {
			return
		}
		name := r.PathValue("name")
		if name == ownerUser {
			reply(w, 400, map[string]string{"error": "مدیر اصلی از این بخش قابل تغییر نیست"})
			return
		}
		var in struct {
			Role       string `json:"role"`
			Password   string `json:"password"`
			MaxClients *int   `json:"max_clients"`
			Expire     *int64 `json:"expire"`
			TotalGB    *int   `json:"total_gb"`
		}
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in) != nil {
			reply(w, 400, map[string]string{"error": "ورودی نامعتبر"})
			return
		}
		adminMu.Lock()
		defer adminMu.Unlock()
		list, err := loadAdmins()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		idx := -1
		for i, a := range list {
			if a.Username == name {
				idx = i
			}
		}
		if idx < 0 {
			reply(w, 404, map[string]string{"error": "ادمین پیدا نشد"})
			return
		}
		if in.Role != "" {
			if in.Role != "owner" && in.Role != "viewer" && in.Role != "seller" {
				reply(w, 400, map[string]string{"error": "نقش باید owner، viewer یا seller باشد"})
				return
			}
			list[idx].Role = in.Role
		}
		if in.MaxClients != nil {
			if *in.MaxClients < 0 || *in.MaxClients > 1000000 {
				reply(w, 400, map[string]string{"error": "سقف تعداد کلاینت نامعتبر است"})
				return
			}
			list[idx].MaxClients = *in.MaxClients
		}
		if in.Expire != nil || in.TotalGB != nil {
			exp, tgb := list[idx].Expire, list[idx].TotalGB
			if in.Expire != nil {
				exp = *in.Expire
			}
			if in.TotalGB != nil {
				tgb = *in.TotalGB
			}
			if e := validSellerLimits(exp, tgb); e != "" {
				reply(w, 400, map[string]string{"error": e})
				return
			}
			list[idx].Expire, list[idx].TotalGB = exp, tgb
		}
		if in.Password != "" {
			if len(in.Password) < 8 || len(in.Password) > 256 {
				reply(w, 400, map[string]string{"error": "رمز باید بین ۸ تا ۲۵۶ کاراکتر باشد"})
				return
			}
			salt, hash, err := hashPassword(in.Password)
			if err != nil {
				reply(w, 500, map[string]string{"error": err.Error()})
				return
			}
			list[idx].Salt, list[idx].Hash, list[idx].Iter = salt, hash, pbkdfIter
		}
		if err := saveAdmins(list); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]string{"ok": "1"})
	}))

	m.HandleFunc("DELETE /api/admins/{name}", auth(func(w http.ResponseWriter, r *http.Request) {
		if !requireOwner(w, r) {
			return
		}
		name := r.PathValue("name")
		if name == ownerUser {
			reply(w, 400, map[string]string{"error": "مدیر اصلی حذف نمی‌شود"})
			return
		}
		adminMu.Lock()
		defer adminMu.Unlock()
		list, err := loadAdmins()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		out := make([]adminRec, 0, len(list))
		removed := false
		for _, a := range list {
			if a.Username == name {
				removed = true
				continue
			}
			out = append(out, a)
		}
		if !removed {
			reply(w, 404, map[string]string{"error": "ادمین پیدا نشد"})
			return
		}
		if err := releaseSellerClients(name); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		if err := saveAdmins(out); err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, map[string]string{"ok": "1"})
	}))
}

func releaseSellerClients(name string) error {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	st, err := loadStore()
	if err != nil {
		return err
	}
	kept := st.Clients[:0]
	removed := false
	for _, c := range st.Clients {
		if c.Owner == name {
			removed = true
			continue
		}
		kept = append(kept, c)
	}
	if !removed {
		return nil
	}
	st.Clients = kept
	if err := writeXrayConfig(st); err != nil {
		return err
	}
	return saveStore(st)
}

func sellerAllowed(r *http.Request) bool {
	p := r.URL.Path
	const pre = "/api/xray/clients/"
	switch r.Method {
	case "GET":
		switch p {
		case "/", "/api/me", "/api/system", "/api/xray/inbounds", "/api/xray/clients", "/api/xray/links":
			return true
		}
	case "POST":
		if p == "/api/xray/clients" {
			return true
		}
		if strings.HasPrefix(p, pre) {
			rest := p[len(pre):]
			return strings.HasSuffix(rest, "/enable") || strings.HasSuffix(rest, "/devices/reset")
		}
	case "PUT":
		if strings.HasPrefix(p, pre) {
			rest := p[len(pre):]
			return rest != "" && !strings.Contains(rest, "/")
		}
	}
	return false
}
