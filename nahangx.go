package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	xRekey   = 1 << 18
	xMaxData = 32768
	xSkew    = 120
	xMaxSeen = 200000
)

var xPool = sync.Pool{New: func() any {
	b := make([]byte, 2+3+xMaxData+15+16+64)
	return &b
}}

func aeadOf(k []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func (s *sess) rekeyW() {
	s.wk = hsum(s.wk, []byte("rekey"))
	s.wa, _ = aeadOf(s.wk)
}

func (s *sess) rekeyR() {
	s.rk = hsum(s.rk, []byte("rekey"))
	s.ra, _ = aeadOf(s.rk)
}

func newSessX(c net.Conn, master, shared, C, S []byte, client bool) (*sess, error) {
	s, err := newSess(c, master, shared, C, S, client)
	if err != nil {
		return nil, err
	}
	s.fast = true
	return s, nil
}

func (s *sess) sendX(typ byte, data []byte) error {
	if len(data) > xMaxData {
		return errors.New("frame too large")
	}
	pad := ri(16)
	if len(data) < 256 {
		pad = ri(200)
	}
	pl := 3 + len(data) + pad

	bp := xPool.Get().(*[]byte)
	defer xPool.Put(bp)
	if cap(*bp) < 2+pl+16 {
		nb := make([]byte, 2+pl+16)
		bp = &nb
	}
	b := (*bp)[:2+pl+16]
	pt := b[2 : 2+pl]
	pt[0] = typ
	binary.BigEndian.PutUint16(pt[1:], uint16(len(data)))
	copy(pt[3:], data)
	if _, err := rand.Read(pt[3+len(data):]); err != nil {
		return err
	}

	s.wmu.Lock()
	defer s.wmu.Unlock()
	ct := s.wa.Seal(pt[:0], nonce(s.wc), pt, nil)
	m := hsum([]byte("len"), s.wk, ctr(s.wc))
	binary.BigEndian.PutUint16(b[0:2], uint16(len(ct)))
	b[0] ^= m[0]
	b[1] ^= m[1]
	s.wc++
	if s.wc%xRekey == 0 {
		s.rekeyW()
	}
	_, err := s.c.Write(b[:2+len(ct)])
	return err
}

func (s *sess) recvX() (byte, []byte, error) {
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
	pt, err := s.ra.Open(ct[:0], nonce(s.rc), ct, nil)
	if err != nil {
		return 0, nil, err
	}
	s.rc++
	if s.rc%xRekey == 0 {
		s.rekeyR()
	}
	l := int(binary.BigEndian.Uint16(pt[1:3]))
	if 3+l > len(pt) {
		return 0, nil, errors.New("bad frame")
	}
	return pt[0], pt[3 : 3+l], nil
}

var xSeen = struct {
	sync.Mutex
	m    map[[16]byte]int64
	last int64
}{m: map[[16]byte]int64{}}

func xFresh(n []byte) bool {
	now := time.Now().Unix()
	ts := int64(binary.BigEndian.Uint64(n[8:16]))
	if d := now - ts; d > xSkew || d < -xSkew {
		return false
	}
	var k [16]byte
	copy(k[:], n)
	xSeen.Lock()
	defer xSeen.Unlock()
	if _, dup := xSeen.m[k]; dup {
		return false
	}
	if len(xSeen.m) >= xMaxSeen {
		if now != xSeen.last {
			xSeen.last = now
			for kk, t := range xSeen.m {
				if now-t > 2*xSkew {
					delete(xSeen.m, kk)
				}
			}
		}
		if len(xSeen.m) >= xMaxSeen {
			return false
		}
	}
	xSeen.m[k] = now
	return true
}

func hsClientX(c net.Conn, master []byte) (*sess, error) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	C := priv.PublicKey().Bytes()
	n := rb(16)
	binary.BigEndian.PutUint64(n[8:], uint64(time.Now().Unix()))
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
	return newSessX(c, master, shared, C, pub.Bytes(), true)
}

func hsServerX(c net.Conn, master []byte) (*sess, error) {
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	hd := make([]byte, 64)

	c.SetReadDeadline(time.Now().Add(6 * time.Second))
	if _, err := io.ReadFull(c, hd); err != nil {
		return nil, errAuth
	}
	c.SetReadDeadline(time.Now().Add(6 * time.Second))
	n, pm, tg := hd[:16], hd[16:48], hd[48:64]
	if !hmac.Equal(tg, hmac16(master, n, pm)) {
		return nil, errAuth
	}
	if !xFresh(n) {
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
	return newSessX(c, master, shared, C, S, false)
}

func decoy(c net.Conn) {
	c.SetDeadline(time.Now().Add(5 * time.Second))
	body := "<!DOCTYPE html>\n<html><head><title>404 Not Found</title></head>\n" +
		"<body><h1>404 Not Found</h1><p>The requested URL was not found on this server.</p></body></html>\n"
	resp := "HTTP/1.1 404 Not Found\r\n" +
		"Date: " + time.Now().UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT") + "\r\n" +
		"Content-Type: text/html; charset=utf-8\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"Connection: close\r\n\r\n" + body
	c.Write([]byte(resp))
	c.Close()
}
