package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestNahangxHandshakeAndFrames(t *testing.T) {
	master := hsum([]byte("nahanx2|"), []byte("test-token"))
	a, b := net.Pipe()
	type result struct {
		s   *sess
		err error
	}
	ch := make(chan result, 1)
	go func() {
		s, err := hsServerX(b, master)
		ch <- result{s, err}
	}()
	cs, err := hsClientX(a, master)
	if err != nil {
		t.Fatal("client handshake:", err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal("server handshake:", r.err)
	}
	ss := r.s

	sizes := []int{0, 1, 255, 256, 16000, 32768}
	go func() {
		for _, n := range sizes {
			if err := cs.send(2, bytes.Repeat([]byte{byte(n)}, n)); err != nil {
				t.Error("send:", err)
				return
			}
		}
	}()
	for _, n := range sizes {
		typ, got, err := ss.recv()
		if err != nil {
			t.Fatal("recv:", err)
		}
		if typ != 2 || !bytes.Equal(got, bytes.Repeat([]byte{byte(n)}, n)) {
			t.Fatalf("frame mismatch for size %d", n)
		}
	}
}

func TestNahangxFreshness(t *testing.T) {
	n := rb(16)
	binary.BigEndian.PutUint64(n[8:], uint64(time.Now().Unix()))
	if !xFresh(n) {
		t.Fatal("first use of a fresh nonce must be accepted")
	}
	if xFresh(n) {
		t.Fatal("replayed nonce must be rejected")
	}
	old := rb(16)
	binary.BigEndian.PutUint64(old[8:], uint64(time.Now().Add(-10*time.Minute).Unix()))
	if xFresh(old) {
		t.Fatal("stale timestamp must be rejected")
	}
}
