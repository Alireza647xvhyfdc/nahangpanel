package main

import (
	"testing"
	"time"
)

func TestSellerExpiry(t *testing.T) {
	now := time.Now()
	past := adminRec{Role: "seller", Expire: now.Add(-time.Hour).Unix()}
	future := adminRec{Role: "seller", Expire: now.Add(time.Hour).Unix()}
	none := adminRec{Role: "seller"}
	owner := adminRec{Role: "owner", Expire: now.Add(-time.Hour).Unix()}
	if !sellerExpired(past, now) {
		t.Error("past expiry should be expired")
	}
	if sellerExpired(future, now) || sellerExpired(none, now) {
		t.Error("future or unset expiry should not be expired")
	}
	if sellerExpired(owner, now) {
		t.Error("non-seller must not be treated as expired seller")
	}
}

func TestSellerQuotaSumsOnlyOwnClients(t *testing.T) {
	st := &Store{Clients: []Client{
		{Name: "a", Owner: "s1", UsedBytes: 3 * bytesPerGB},
		{Name: "b", Owner: "s1", UsedBytes: 2 * bytesPerGB},
		{Name: "c", Owner: "s2", UsedBytes: 50 * bytesPerGB},
	}}
	if got := sellerUsedBytes(st, "s1"); got != 5*bytesPerGB {
		t.Errorf("used = %d, want %d", got, 5*bytesPerGB)
	}
	if !sellerOverQuota(adminRec{Username: "s1", Role: "seller", TotalGB: 5}, st) {
		t.Error("exactly at cap should count as over quota")
	}
	if sellerOverQuota(adminRec{Username: "s1", Role: "seller", TotalGB: 6}, st) {
		t.Error("below cap should not be over quota")
	}
	if sellerOverQuota(adminRec{Username: "s1", Role: "seller", TotalGB: 0}, st) {
		t.Error("zero cap means unlimited")
	}
}

func TestValidSellerLimits(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).Unix()
	if e := validSellerLimits(0, 0); e != "" {
		t.Errorf("unlimited should be valid: %s", e)
	}
	if e := validSellerLimits(future, 10); e != "" {
		t.Errorf("future expiry should be valid: %s", e)
	}
	if e := validSellerLimits(time.Now().Add(-time.Hour).Unix(), 0); e == "" {
		t.Error("past expiry must be rejected")
	}
	if e := validSellerLimits(0, -1); e == "" {
		t.Error("negative quota must be rejected")
	}
}
