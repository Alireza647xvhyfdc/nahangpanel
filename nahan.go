package main

// روش تانل «نهنگ» (nahang)
// تانل معکوس: سرور خارج چند اتصال آماده (pool) به سرور ایران می‌زند؛ هر کاربر یکی از آن‌ها را می‌گیرد.
// دست‌دادن: X25519 + احراز هویت با HMAC از توکن؛ بایت‌های اول کاملاً تصادفی و بدون امضای ثابت.
// داده: AES-256-GCM، طول فریم رمز می‌شود و هر فریم پدینگ تصادفی دارد؛ ضربان تصادفی در حالت بیکاری.
// پروب بدون توکن هیچ پاسخی نمی‌گیرد (tarpit).

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type nCfg struct {
	Role  string   `json:"role"`
	Addr  string   `json:"addr"`
	Token string   `json:"token"`
	Ports []string `json:"ports"`
	TLS   bool     `json:"tls"`
	Pool  int      `json:"pool"`
	Fast  bool     `json:"fast"` // nahangx: پروتکل نسخه‌ی ۲ (سریع + ضد replay + کلید چرخشی)
}

var errAuth = errors.New("auth")

func ri(max int) int {
	var b [4]byte
	rand.Read(b[:])
	return int(binary.BigEndian.Uint32(b[:]) % uint32(max))
}

func rb(n int) []byte { b := make([]byte, n); rand.Read(b); return b }

func hsum(parts ...[]byte) []byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

func hmac16(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)[:16]
}

func xor32(a, b []byte) []byte {
	o := make([]byte, 32)
	for i := range o {
		o[i] = a[i] ^ b[i]
	}
	return o
}

func cat(parts ...[]byte) []byte {
	var o []byte
	for _, p := range parts {
		o = append(o, p...)
	}
	return o
}

type sess struct {
	c      net.Conn
	wa, ra cipher.AEAD
	wk, rk []byte
	wc, rc uint64
	wmu    sync.Mutex
	fast   bool // nahangx: ارسال/دریافت در nahangx.go
}

func newSess(c net.Conn, master, shared, C, S []byte, client bool) (*sess, error) {
	wk := hsum(master, shared, C, S, []byte("c2s"))
	rk := hsum(master, shared, C, S, []byte("s2c"))
	if !client {
		wk, rk = rk, wk
	}
	mk := func(k []byte) (cipher.AEAD, error) {
		b, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	}
	wa, err := mk(wk)
	if err != nil {
		return nil, err
	}
	ra, err := mk(rk)
	if err != nil {
		return nil, err
	}
	return &sess{c: c, wa: wa, ra: ra, wk: wk, rk: rk}, nil
}

func ctr(n uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, n); return b }

func nonce(n uint64) []byte { b := make([]byte, 12); binary.BigEndian.PutUint64(b[4:], n); return b }

// فریم: [طول رمزشده ۲ بایت][AES-GCM(نوع ۱ | طول داده ۲ | داده | پدینگ تصادفی)]
func (s *sess) send(typ byte, data []byte) error {
	if s.fast {
		return s.sendX(typ, data)
	}
	pad := ri(32)
	if len(data) < 200 {
		pad = ri(160)
	}
	pt := make([]byte, 3+len(data)+pad)
	pt[0] = typ
	binary.BigEndian.PutUint16(pt[1:], uint16(len(data)))
	copy(pt[3:], data)
	rand.Read(pt[3+len(data):])
	s.wmu.Lock()
	defer s.wmu.Unlock()
	ct := s.wa.Seal(nil, nonce(s.wc), pt, nil)
	h := make([]byte, 2)
	binary.BigEndian.PutUint16(h, uint16(len(ct)))
	m := hsum([]byte("len"), s.wk, ctr(s.wc))
	h[0] ^= m[0]
	h[1] ^= m[1]
	s.wc++
	_, err := s.c.Write(append(h, ct...))
	return err
}

func (s *sess) recv() (byte, []byte, error) {
	if s.fast {
		return s.recvX()
	}
	var h [2]byte
	if _, err := io.ReadFull(s.c, h[:]); err != nil {
		return 0, nil, err
	}
	m := hsum([]byte("len"), s.rk, ctr(s.rc))
	h[0] ^= m[0]
	h[1] ^= m[1]
	n := int(binary.BigEndian.Uint16(h[:]))
	if n < 19 {
		return 0, nil, errors.New("bad frame")
	}
	ct := make([]byte, n)
	if _, err := io.ReadFull(s.c, ct); err != nil {
		return 0, nil, err
	}
	pt, err := s.ra.Open(nil, nonce(s.rc), ct, nil)
	if err != nil {
		return 0, nil, err
	}
	s.rc++
	l := int(binary.BigEndian.Uint16(pt[1:3]))
	if 3+l > len(pt) {
		return 0, nil, errors.New("bad frame")
	}
	return pt[0], pt[3 : 3+l], nil
}

func hsClient(c net.Conn, master []byte) (*sess, error) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	C := priv.PublicKey().Bytes()
	n := rb(16)
	pm := xor32(C, hsum(master, []byte("c"), n))
	if _, err := c.Write(cat(n, pm, hmac16(master, n, pm), rb(int(n[0])))); err != nil {
		return nil, err
	}
	hd := make([]byte, 64)
	if _, err := io.ReadFull(c, hd); err != nil {
		return nil, err
	}
	rn, sm, st := hd[:16], hd[16:48], hd[48:64]
	if !hmac.Equal(st, hmac16(master, rn, sm, C)) {
		return nil, errAuth
	}
	if _, err := io.CopyN(io.Discard, c, int64(rn[0])); err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(xor32(sm, hsum(master, []byte("s"), rn)))
	if err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	return newSess(c, master, shared, C, pub.Bytes(), true)
}

func hsServer(c net.Conn, master []byte) (*sess, error) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	hd := make([]byte, 64)
	if _, err := io.ReadFull(c, hd); err != nil {
		return nil, err
	}
	n, pm, tg := hd[:16], hd[16:48], hd[48:64]
	if !hmac.Equal(tg, hmac16(master, n, pm)) {
		return nil, errAuth
	}
	if _, err := io.CopyN(io.Discard, c, int64(n[0])); err != nil {
		return nil, err
	}
	C := xor32(pm, hsum(master, []byte("c"), n))
	cp, err := ecdh.X25519().NewPublicKey(C)
	if err != nil {
		return nil, errAuth
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	S := priv.PublicKey().Bytes()
	rn := rb(16)
	sm := xor32(S, hsum(master, []byte("s"), rn))
	if _, err := c.Write(cat(rn, sm, hmac16(master, rn, sm, C), rb(int(rn[0])))); err != nil {
		return nil, err
	}
	shared, err := priv.ECDH(cp)
	if err != nil {
		return nil, err
	}
	return newSess(c, master, shared, C, S, false)
}

func tune(c net.Conn) {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if t, ok := c.(*net.TCPConn); ok {
		t.SetNoDelay(true)
		t.SetKeepAlive(true)
		t.SetKeepAlivePeriod(30 * time.Second)
	}
}

// پروب‌های بدون توکن: هیچ پاسخی نمی‌گیرند و چند ثانیه سرگردان می‌مانند
func tarpit(c net.Conn) {
	c.SetDeadline(time.Now().Add(time.Duration(8+ri(25)) * time.Second))
	io.Copy(io.Discard, c)
	c.Close()
}

func pipe(u net.Conn, s *sess) {
	var once sync.Once
	closeAll := func() { once.Do(func() { u.Close(); s.c.Close() }) }
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		bs := 16000
		if s.fast {
			bs = 32000
		}
		buf := make([]byte, bs)
		for {
			n, err := u.Read(buf)
			if n > 0 && s.send(0, buf[:n]) != nil {
				closeAll()
				return
			}
			if err != nil {
				if err == io.EOF {
					s.send(3, nil)
				} else {
					closeAll()
				}
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			t, d, err := s.recv()
			if err != nil {
				closeAll()
				return
			}
			switch t {
			case 0:
				if _, err := u.Write(d); err != nil {
					closeAll()
					return
				}
			case 3:
				if tc, ok := u.(*net.TCPConn); ok {
					tc.CloseWrite()
				} else {
					closeAll()
				}
				return
			}
		}
	}()
	wg.Wait()
	closeAll()
}

func openOn(s *sess, port int) bool {
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(port))
	if s.send(2, p[:]) != nil {
		return false
	}
	s.c.SetReadDeadline(time.Now().Add(4 * time.Second))
	defer s.c.SetReadDeadline(time.Time{})
	for {
		t, _, err := s.recv()
		if err != nil || t == 3 {
			return false
		}
		if t == 4 {
			return true
		}
	}
}

func parsePorts(ps []string) map[int]int {
	m := map[int]int{}
	for _, p := range ps {
		l, t, eq := strings.Cut(p, "=")
		if a, b, rg := strings.Cut(l, "-"); rg && !eq {
			x, e1 := strconv.Atoi(a)
			y, e2 := strconv.Atoi(b)
			if e1 == nil && e2 == nil && x > 0 && y >= x && y-x <= 1000 && y < 65536 {
				for i := x; i <= y; i++ {
					m[i] = i
				}
			}
			continue
		}
		x, e1 := strconv.Atoi(l)
		y := x
		if eq {
			var e2 error
			if y, e2 = strconv.Atoi(t); e2 != nil {
				continue
			}
		}
		if e1 == nil && x > 0 && x < 65536 && y > 0 && y < 65536 {
			m[x] = y
		}
	}
	return m
}

func forward(l, t int, idle chan *sess) {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(l))
	if err != nil {
		log.Println("listen", l, err)
		return
	}
	for {
		u, err := ln.Accept()
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		go func(u net.Conn) {
			tune(u)
			for i := 0; i < 8; i++ {
				select {
				case s := <-idle:
					if openOn(s, t) {
						pipe(u, s)
						return
					}
					s.c.Close()
				case <-time.After(5 * time.Second):
					u.Close()
					return
				}
			}
			u.Close()
		}(u)
	}
}

func runServer(cfg nCfg, master []byte) {
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		log.Fatal(err)
	}
	if cfg.TLS {
		cert, err := tls.LoadX509KeyPair(dir+"cert.pem", dir+"key.pem")
		if err != nil {
			log.Fatal(err)
		}
		tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if cfg.Fast {
			tc.MinVersion = tls.VersionTLS13
		}
		ln = tls.NewListener(ln, tc)
	}
	hs := hsServer
	if cfg.Fast {
		hs = hsServerX
	}
	idle := make(chan *sess, 256)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				time.Sleep(time.Second)
				continue
			}
			go func(c net.Conn) {
				tune(c)
				s, err := hs(c, master)
				if err != nil {
					if err == errAuth {
						if cfg.Fast {
							decoy(c)
						} else {
							tarpit(c)
						}
					} else {
						c.Close()
					}
					return
				}
				for {
					select {
					case idle <- s:
						return
					default:
						select {
						case old := <-idle:
							old.c.Close()
						default:
						}
					}
				}
			}(c)
		}
	}()
	for l, t := range parsePorts(cfg.Ports) {
		go forward(l, t, idle)
	}
	select {}
}

func heartbeat(s *sess, stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-time.After(time.Duration(15+ri(20)) * time.Second):
			if s.send(1, rb(ri(40))) != nil {
				return
			}
		}
	}
}

// هر worker یک اتصال آماده نگه می‌دارد؛ هنگام استفاده، جانشینش بلافاصله ساخته می‌شود
func worker(cfg nCfg, master []byte) {
	hs := hsClient
	if cfg.Fast {
		hs = hsClientX
	}
	for {
		var c net.Conn
		var err error
		if cfg.TLS {
			// اعتبار با HMAC توکن داخل تانل تأیید می‌شود، نه با گواهی
			tc := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
			if cfg.Fast {
				tc.MinVersion = tls.VersionTLS13
			}
			c, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", cfg.Addr, tc)
		} else {
			c, err = net.DialTimeout("tcp", cfg.Addr, 10*time.Second)
		}
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		tune(c)
		s, err := hs(c, master)
		if err != nil {
			c.Close()
			time.Sleep(3 * time.Second)
			continue
		}
		stop := make(chan struct{})
		go heartbeat(s, stop)
		used := false
		for {
			t, d, err := s.recv()
			if err != nil {
				break
			}
			if t != 2 || len(d) != 2 {
				continue
			}
			used = true
			go worker(cfg, master)
			u, e := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(int(binary.BigEndian.Uint16(d))), 5*time.Second)
			if e != nil {
				s.send(3, nil)
				break
			}
			s.send(4, nil)
			pipe(u, s)
			break
		}
		close(stop)
		c.Close()
		if used {
			return
		}
		time.Sleep(time.Second)
	}
}

func runNahan(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	var cfg nCfg
	if json.Unmarshal(b, &cfg) != nil {
		log.Fatal("پیکربندی نامعتبر")
	}
	label := "nahan1|"
	if cfg.Fast {
		cfg.TLS = true // nahangx همیشه داخل TLS ۱.۳ است
		label = "nahanx2|"
	}
	master := hsum([]byte(label), []byte(cfg.Token))
	if cfg.Role == "server" {
		runServer(cfg, master)
		return
	}
	if cfg.Pool <= 0 || cfg.Pool > 64 {
		cfg.Pool = 6
	}
	for i := 0; i < cfg.Pool; i++ {
		go worker(cfg, master)
		time.Sleep(150 * time.Millisecond)
	}
	select {}
}
