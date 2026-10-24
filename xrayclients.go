package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type ClientReq struct {
	Name               string `json:"name"`
	ID                 string `json:"id"`
	Enabled            *bool  `json:"enabled"`
	Inbounds           []int  `json:"inbounds"`
	Expire             int64  `json:"expire"`
	LimitGB            int    `json:"limit_gb"`
	IPLimit            int    `json:"ip_limit"`
	HWIDLimit          int    `json:"hwid_limit"`
	TrafficReset       string `json:"traffic_reset"`
	AutoRenew          bool   `json:"auto_renew"`
	StartAfterFirstUse bool   `json:"start_after_first_use"`
	Comment            string `json:"comment"`
	Group              string `json:"group"`
	KeepPeriod         bool   `json:"keep_period"`
	Owner              string `json:"-"`
}

var (
	reUUID        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	reGroup       = regexp.MustCompile(`^[A-Za-z0-9_\-]{0,32}$`)
	trafficResets = map[string]bool{"": true, "never": true, "daily": true, "weekly": true, "monthly": true}
)

func (c Client) attachedTo(port int) bool {
	if c.Inbound == port {
		return true
	}
	for _, p := range c.Inbounds {
		if p == port {
			return true
		}
	}
	return false
}

func addClientFull(req ClientReq) (Client, error) {
	if !reRemark.MatchString(req.Name) {
		return Client{}, errors.New("نام کلاینت فقط حروف انگلیسی، عدد، _ و - باشد")
	}
	if e := validateClientInput(req.Expire, req.LimitGB); e != "" {
		return Client{}, errors.New(e)
	}
	if req.IPLimit < 0 || req.IPLimit > 10000 || req.HWIDLimit < 0 || req.HWIDLimit > 10000 {
		return Client{}, errors.New("IP Limit یا HWID Limit باید بین ۰ و ۱۰۰۰۰ باشد")
	}
	if !trafficResets[req.TrafficReset] {
		return Client{}, errors.New("Traffic Reset نامعتبر است")
	}
	now := time.Now()
	var period int64
	if req.Expire > 0 {
		period = req.Expire - now.Unix()
	}
	if (req.AutoRenew || req.StartAfterFirstUse) && period <= 0 {
		return Client{}, errors.New("برای Auto renewal و Start after first use تاریخ انقضا (به‌عنوان دوره) باید در آینده باشد")
	}
	if len(req.Comment) > 200 {
		return Client{}, errors.New("توضیح بیش از ۲۰۰ کاراکتر است")
	}
	if !reGroup.MatchString(req.Group) {
		return Client{}, errors.New("گروه فقط حروف انگلیسی، عدد، _ و - باشد (حداکثر ۳۲)")
	}
	if len(req.Inbounds) == 0 {
		return Client{}, errors.New("حداقل یک inbound انتخاب کن")
	}

	id := strings.TrimSpace(req.ID)
	if id == "" {
		gen, err := newUUID()
		if err != nil {
			return Client{}, err
		}
		id = gen
	} else if !reUUID.MatchString(id) {
		return Client{}, errors.New("UUID نامعتبر است")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	xrayMu.Lock()
	defer xrayMu.Unlock()
	st, err := loadStore()
	if err != nil {
		return Client{}, err
	}

	if req.Owner != "" {
		if a, ok := findAdmin(req.Owner); ok && (sellerExpired(a, now) || sellerOverQuota(a, st)) {
			return Client{}, errSellerLimited
		}
		if a, ok := findAdmin(req.Owner); ok && a.MaxClients > 0 {
			n := 0
			for _, o := range st.Clients {
				if o.Owner == req.Owner {
					n++
				}
			}
			if n >= a.MaxClients {
				return Client{}, errors.New("به سقف تعداد کلاینت‌های مجاز خودت رسیدی")
			}
		}
	}

	seen := map[int]bool{}
	attach := []int{}
	for _, p := range req.Inbounds {
		if seen[p] {
			continue
		}
		seen[p] = true
		found := false
		for _, in := range st.Inbounds {
			if in.Port != p {
				continue
			}
			if in.Protocol == "shadowsocks" {
				return Client{}, errors.New("shadowsocks کلاینت جدا ندارد؛ از لینک خود inbound استفاده کن")
			}
			found = true
		}
		if !found {
			return Client{}, fmt.Errorf("inbound با پورت %d وجود ندارد", p)
		}
		attach = append(attach, p)
	}

	for _, c := range st.Clients {
		if c.Name == req.Name {
			return Client{}, errors.New("نام کلاینت تکراری است")
		}
		if c.ID == id {
			return Client{}, errors.New("این UUID قبلاً استفاده شده؛ UUID دیگری بگذار")
		}
	}

	subToken, err := newSubToken()
	if err != nil {
		return Client{}, err
	}
	c := Client{
		SubToken: subToken,
		Name:     req.Name, ID: id, Enabled: enabled, Expire: req.Expire, LimitGB: req.LimitGB,
		Inbounds: attach, IPLimit: req.IPLimit, HWIDLimit: req.HWIDLimit, TrafficReset: req.TrafficReset,
		AutoRenew: req.AutoRenew, StartAfterFirstUse: req.StartAfterFirstUse,
		Comment: req.Comment, Group: req.Group, Owner: req.Owner,
		NextReset: nextResetAfter(now, req.TrafficReset),
	}
	if req.StartAfterFirstUse {
		c.Expire = 0
		c.Period = period
	} else if req.AutoRenew {
		c.Period = period
	}
	st.Clients = append(st.Clients, c)
	if err := writeXrayConfig(st); err != nil {
		return Client{}, err
	}
	return c, saveStore(st)
}

func sellerOf(r *http.Request) string {
	if id := identOf(r); id.role == "seller" {
		return id.user
	}
	return ""
}

func ownsClient(r *http.Request, c *Client) bool {
	if s := sellerOf(r); s != "" {
		return c.Owner == s
	}
	return true
}

var errClientNotFound = errors.New("کلاینت پیدا نشد")

func editClient(oldName string, req ClientReq) (Client, error) {
	if req.Name == "" {
		req.Name = oldName
	}
	if !reRemark.MatchString(req.Name) {
		return Client{}, errors.New("نام کلاینت فقط حروف انگلیسی، عدد، _ و - باشد")
	}
	if e := validateClientInput(req.Expire, req.LimitGB); e != "" {
		return Client{}, errors.New(e)
	}
	if req.IPLimit < 0 || req.IPLimit > 10000 || req.HWIDLimit < 0 || req.HWIDLimit > 10000 {
		return Client{}, errors.New("IP Limit یا HWID Limit باید بین ۰ و ۱۰۰۰۰ باشد")
	}
	if !trafficResets[req.TrafficReset] {
		return Client{}, errors.New("Traffic Reset نامعتبر است")
	}
	if len(req.Comment) > 200 {
		return Client{}, errors.New("توضیح بیش از ۲۰۰ کاراکتر است")
	}
	if !reGroup.MatchString(req.Group) {
		return Client{}, errors.New("گروه فقط حروف انگلیسی، عدد، _ و - باشد (حداکثر ۳۲)")
	}
	if len(req.Inbounds) == 0 {
		return Client{}, errors.New("حداقل یک inbound انتخاب کن")
	}
	id := strings.TrimSpace(req.ID)
	if id != "" && !reUUID.MatchString(id) {
		return Client{}, errors.New("UUID نامعتبر است")
	}

	now := time.Now()
	var period int64
	if req.Expire > 0 {
		period = req.Expire - now.Unix()
	}

	xrayMu.Lock()
	defer xrayMu.Unlock()
	st, err := loadStore()
	if err != nil {
		return Client{}, err
	}
	idx := -1
	for i := range st.Clients {
		if st.Clients[i].Name == oldName {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Client{}, errClientNotFound
	}
	c := &st.Clients[idx]
	if req.Owner != "" && c.Owner != req.Owner {
		return Client{}, errClientNotFound
	}
	if id == "" {
		id = c.ID
	}

	keep := req.KeepPeriod && c.Period > 0
	if (req.AutoRenew || req.StartAfterFirstUse) && period <= 0 && !keep {
		return Client{}, errors.New("برای Auto renewal و Start after first use تاریخ انقضا (به‌عنوان دوره) باید در آینده باشد")
	}

	seen := map[int]bool{}
	attach := []int{}
	for _, p := range req.Inbounds {
		if seen[p] {
			continue
		}
		seen[p] = true
		found := false
		for _, in := range st.Inbounds {
			if in.Port != p {
				continue
			}
			if in.Protocol == "shadowsocks" {
				return Client{}, errors.New("shadowsocks کلاینت جدا ندارد؛ از لینک خود inbound استفاده کن")
			}
			found = true
		}
		if !found {
			return Client{}, fmt.Errorf("inbound با پورت %d وجود ندارد", p)
		}
		attach = append(attach, p)
	}

	for i, o := range st.Clients {
		if i == idx {
			continue
		}
		if o.Name == req.Name {
			return Client{}, errors.New("نام کلاینت تکراری است")
		}
		if o.ID == id {
			return Client{}, errors.New("این UUID قبلاً استفاده شده؛ UUID دیگری بگذار")
		}
	}

	if req.Name != oldName {
		ipMon.reset(oldName)
	}
	c.Name = req.Name
	c.ID = id
	c.Inbound = 0
	c.Inbounds = attach
	c.LimitGB = req.LimitGB
	c.IPLimit = req.IPLimit
	c.HWIDLimit = req.HWIDLimit
	c.Comment = req.Comment
	c.Group = req.Group
	c.AutoRenew = req.AutoRenew
	c.StartAfterFirstUse = req.StartAfterFirstUse
	if req.TrafficReset != c.TrafficReset {
		c.TrafficReset = req.TrafficReset
		c.NextReset = nextResetAfter(now, req.TrafficReset)
	}
	if req.Enabled != nil && *req.Enabled && c.DisabledReason == sellerLimitReason {
		return Client{}, errSellerLimited
	}
	if req.Enabled != nil && *req.Enabled != c.Enabled {
		c.Enabled = *req.Enabled
		c.DisabledReason = ""
		if c.Enabled {
			ipMon.reset(c.Name)
		}
	}

	switch {
	case req.StartAfterFirstUse && c.FirstUseAt == 0:
		c.Expire = 0
		if !keep {
			c.Period = period
		}
	case req.StartAfterFirstUse:
		c.Expire = req.Expire
		if c.Period <= 0 {
			c.Period = period
		}
	case req.AutoRenew:
		c.Expire = req.Expire
		if !keep {
			c.Period = period
		}
	default:
		c.Expire = req.Expire
		c.Period = 0
	}

	res := *c
	if err := writeXrayConfig(st); err != nil {
		return Client{}, err
	}
	return res, saveStore(st)
}

func registerXrayClientRoutes(m *http.ServeMux, auth func(http.HandlerFunc) http.HandlerFunc) {
	m.HandleFunc("POST /api/xray/clients", auth(func(w http.ResponseWriter, r *http.Request) {
		var req ClientReq
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req) != nil {
			reply(w, 400, map[string]string{"error": "ورودی نامعتبر"})
			return
		}
		req.Owner = sellerOf(r)
		c, err := addClientFull(req)
		if err != nil {
			reply(w, 400, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, c)
	}))

	m.HandleFunc("PUT /api/xray/clients/{name}", auth(func(w http.ResponseWriter, r *http.Request) {
		var req ClientReq
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req) != nil {
			reply(w, 400, map[string]string{"error": "ورودی نامعتبر"})
			return
		}
		req.Owner = sellerOf(r)
		c, err := editClient(r.PathValue("name"), req)
		if err != nil {
			code := 400
			if errors.Is(err, errClientNotFound) {
				code = 404
			}
			reply(w, code, map[string]string{"error": err.Error()})
			return
		}
		reply(w, 200, c)
	}))

	m.HandleFunc("GET /api/xray/links", auth(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		server, name := q.Get("server"), q.Get("name")
		if server == "" {
			server = irServerAddr()
		}
		if !validServerAddr(server) {
			reply(w, 400, map[string]string{"error": "server باید IP یا نام میزبان معتبر باشد"})
			return
		}
		st, err := loadStore()
		if err != nil {
			reply(w, 500, map[string]string{"error": err.Error()})
			return
		}
		var c *Client
		for i := range st.Clients {
			if st.Clients[i].Name == name {
				c = &st.Clients[i]
				break
			}
		}
		if c == nil || !ownsClient(r, c) {
			reply(w, 404, map[string]string{"error": "کلاینت پیدا نشد"})
			return
		}
		type item struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Link     string `json:"link"`
			Note     string `json:"note,omitempty"`
		}
		out := []item{}
		for _, in := range st.Inbounds {
			if !c.attachedTo(in.Port) || in.ExcludeSub || in.Disabled {
				continue
			}
			link := buildLink(c, in, server)
			it := item{Port: in.Port, Protocol: in.Protocol, Link: link}
			if link == "" {
				it.Note = "لینک برای این پروتکل ساخته نشد"
			} else if in.Network == "kcp" {
				it.Note = "mKCP روی UDP است؛ IP سرور خارج را بگذار و پورت UDP را باز کن"
			}
			out = append(out, it)
		}
		reply(w, 200, out)
	}))
}
