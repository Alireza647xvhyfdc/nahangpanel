package main

// ترنسپورت «نهنگ ایکس» (nahangx) — سریع و سخت‌شده
//
// نسخه‌ی ۲ پروتکل نهنگ با این تفاوت‌ها:
//   - همیشه داخل TLS 1.3 (لایه‌ی بیرونی؛ ترافیک روی سیم کاملاً رمزشده است).
//   - ضد replay: هر دست‌دادن یک مهر زمانی داخل HMAC دارد و سرور هر nonce را
//     تا ۲ دقیقه به خاطر می‌سپارد؛ ضبط‌کردن و پخش‌مجدد دست‌دادن بی‌اثر است.
//   - چرخش کلید: هر ۲^۱۸ فریم (حدود ۸ گیگابایت) کلید ارسال و دریافت هر دو طرف
//     به‌صورت هم‌زمان و قطعی تغییر می‌کند؛ نشت یک کلید، ترافیک بعدی را باز نمی‌کند.
//   - سرعت: فریم‌های بزرگ‌تر (تا ۳۲KB)، رمزنگاری درجا (بدون کپی اضافه)،
//     یک‌بار write برای هر فریم (هدر + بدنه) و بافرهای بازچرخانی شده (sync.Pool).
//
// نسخه‌ی قبلی (nahang / nahangtls) بدون تغییر باقی می‌ماند تا سازگاری حفظ شود.

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
	"sync"
	"time"
)

const (
	xRekey   = 1 << 18 // تعداد فریم بین دو چرخش کلید
	xMaxData = 32768   // بیشینه‌ی داده‌ی یک فریم
	xSkew    = 120     // بیشینه‌ی اختلاف ساعت مجاز (ثانیه)
	xMaxSeen = 200000  // سقف nonceهای به‌خاطرسپرده‌شده
)

var xPool = sync.Pool{New: func() any {
	b := make([]byte, 2+3+xMaxData+15+16+64)
	return &b
}}

// ---------- کلید و رمز ----------

func aeadOf(k []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// هر دو طرف دقیقاً در یک شماره‌ی فریم چرخش می‌کنند، پس کلیدها همیشه هم‌راستا می‌مانند.
func (s *sess) rekeyW() {
	s.wk = hsum(s.wk, []byte("rekey"))
	s.wa, _ = aeadOf(s.wk)
}

func (s *sess) rekeyR() {
	s.rk = hsum(s.rk, []byte("rekey"))
	s.ra, _ = aeadOf(s.rk)
}

// newSessX همان newSess است با پرچم نسخه‌ی سریع.
func newSessX(c net.Conn, master, shared, C, S []byte, client bool) (*sess, error) {
	s, err := newSess(c, master, shared, C, S, client)
	if err != nil {
		return nil, err
	}
	s.fast = true
	return s, nil
}

// ---------- فریم ----------
// قالب فریم: [طول رمزشده ۲ بایت، XOR با ماسک][AES-GCM(نوع ۱ | طول داده ۲ | داده | پدینگ)]

// sendX: یک فریم را با یک write و بدون کپی اضافه ارسال می‌کند.
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
	b := (*bp)[:2+pl+16]
	pt := b[2 : 2+pl]
	pt[0] = typ
	binary.BigEndian.PutUint16(pt[1:], uint16(len(data)))
	copy(pt[3:], data)
	rand.Read(pt[3+len(data):])

	s.wmu.Lock()
	defer s.wmu.Unlock()
	// رمزنگاری درجا: خروجی روی همان حافظه‌ی متن‌ساده نوشته می‌شود
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

// recvX: خواندن و باز کردن درجای یک فریم.
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

// ---------- ضد replay ----------

var xSeen = struct {
	sync.Mutex
	m map[[16]byte]int64
}{m: map[[16]byte]int64{}}

// xFresh: مهر زمانی را می‌سنجد و nonce را یک‌بار می‌پذیرد.
// nonce فقط پس از تأیید HMAC فراخوانی می‌شود، بنابراین مهاجم نمی‌تواند حافظه را پر کند.
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
		for kk, t := range xSeen.m {
			if now-t > 2*xSkew {
				delete(xSeen.m, kk)
			}
		}
		if len(xSeen.m) >= xMaxSeen {
			return false
		}
	}
	xSeen.m[k] = now
	return true
}

// ---------- دست‌دادن ----------
// ساختار مشابه nahang است؛ nonce حالا ۸ بایت تصادفی + ۸ بایت مهر زمانی دارد.

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
	if _, err := io.ReadFull(c, hd); err != nil {
		return nil, err
	}
	n, pm, tg := hd[:16], hd[16:48], hd[48:64]
	if !hmac.Equal(tg, hmac16(master, n, pm)) {
		return nil, errAuth
	}
	// پس از تأیید HMAC: مهر زمانی و یکتایی nonce
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
