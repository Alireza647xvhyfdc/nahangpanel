package main

import (
	"errors"
	"time"
)

const sellerLimitReason = "seller_limit"

func sellerExpired(a adminRec, now time.Time) bool {
	return a.Role == "seller" && a.Expire > 0 && now.Unix() > a.Expire
}

func sellerUsedBytes(st *Store, seller string) int64 {
	var total int64
	for _, c := range st.Clients {
		if c.Owner == seller {
			total += c.UsedBytes
		}
	}
	return total
}

func sellerOverQuota(a adminRec, st *Store) bool {
	return a.Role == "seller" && a.TotalGB > 0 && sellerUsedBytes(st, a.Username) >= int64(a.TotalGB)*bytesPerGB
}

func validSellerLimits(expire int64, totalGB int) string {
	if expire < 0 || expire > maxExpireAt {
		return "تاریخ انقضا نامعتبر است"
	}
	if expire > 0 && expire <= time.Now().Unix() {
		return "تاریخ انقضا باید در آینده باشد"
	}
	if totalGB < 0 || totalGB > maxLimitGB {
		return "سقف حجم نامعتبر است"
	}
	return ""
}

func enforceSellers(now time.Time) error {
	adminMu.Lock()
	admins, err := loadAdmins()
	adminMu.Unlock()
	if err != nil {
		return err
	}
	byName := map[string]adminRec{}
	for _, a := range admins {
		byName[a.Username] = a
	}

	xrayMu.Lock()
	defer xrayMu.Unlock()
	st, err := loadStore()
	if err != nil {
		return err
	}
	blocked := map[string]bool{}
	for name, a := range byName {
		if a.Role == "seller" {
			blocked[name] = sellerExpired(a, now) || sellerOverQuota(a, st)
		}
	}

	changed := false
	for i := range st.Clients {
		c := &st.Clients[i]
		off := c.Owner != "" && blocked[c.Owner]
		switch {
		case off && c.Enabled:
			c.Enabled = false
			c.DisabledReason = sellerLimitReason
			changed = true
		case !off && c.DisabledReason == sellerLimitReason:
			c.Enabled = true
			c.DisabledReason = ""
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if err := saveStore(st); err != nil {
		return err
	}
	return syncXrayConfig(st)
}

var errSellerLimited = errors.New("حساب فروشنده به سقف حجم یا زمان رسیده؛ کلاینت فعال نمی‌شود")
