package main

// xrayinbasic.go: اعتبارسنجی و پیش‌فرض‌های بخش «پایه» ساخت inbound
// (ترتیب اشتراک، حذف از اشتراک، Share address، سقف ترافیک، ریست ترافیک، زمان انقضا).

import (
	"net"
	"time"
)

var (
	basicShareStrategies = map[string]bool{"inbound_listen": true, "server_ip": true}
	basicTrafficResets   = map[string]bool{"never": true, "daily": true, "weekly": true, "monthly": true}
)

// validateBasicExtras مقدارهای بخش پایه را بررسی و پیش‌فرض‌ها را تعیین می‌کند.
func validateBasicExtras(in *Inbound) string {
	if in.SortOrder < 0 || in.SortOrder > 9999 {
		return "ترتیب اشتراک باید بین ۰ و ۹۹۹۹ باشد"
	}
	if in.ShareStrategy == "" {
		in.ShareStrategy = "inbound_listen"
	}
	if !basicShareStrategies[in.ShareStrategy] {
		return "Share address strategy نامعتبر است"
	}
	if in.TotalFlow < 0 {
		return "Total Flow نمی‌تواند منفی باشد"
	}
	if in.TrafficReset == "" {
		in.TrafficReset = "never"
	}
	if !basicTrafficResets[in.TrafficReset] {
		return "Traffic Reset نامعتبر است"
	}
	if in.Expires < 0 || in.Expires > maxExpireAt {
		return "زمان انقضا نامعتبر است"
	}
	if in.Expires > 0 && in.Expires <= time.Now().Unix() {
		return "زمان انقضا باید در آینده باشد"
	}
	return ""
}

// shareHost آدرس داخل لینک را انتخاب می‌کند.
// Server IP (و داده‌های قدیمی بدون استراتژی): همان IP سرور.
// Inbound listen: اگر inbound روی یک IP مشخص گوش می‌دهد (نه همه‌ی IPها یا loopback)، همان IP.
func shareHost(in Inbound, server string) string {
	if in.ShareStrategy != "inbound_listen" {
		return server
	}
	ip := net.ParseIP(in.Listen)
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() {
		return server
	}
	return in.Listen
}
