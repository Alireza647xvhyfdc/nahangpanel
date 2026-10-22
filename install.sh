#!/bin/bash
# نصب و به‌روزرسانی پنل تانل — روی هر دو سرور (ایران و خارج) اجرا شود
# نصب:          sudo bash install.sh [پورت پنل] [IP مجاز (اختیاری)]
# به‌روزرسانی:  sudo nahang   (گزینه‌ی ۶)   یا   sudo bash /usr/local/share/tunnelpanel/install.sh --update
set -e
[ "$EUID" -ne 0 ] && { echo "با root اجرا کنید"; exit 1; }

REPO="USER/REPO"   # <-- نام کاربری/نام مخزن گیت‌هاب را اینجا بگذار
SVC=/etc/systemd/system/tunnelpanel.service
MENU_SHARE=/usr/local/share/tunnelpanel

UPDATE=0
[ "$1" = "--update" ] && UPDATE=1

if [ "$UPDATE" = 1 ]; then
  [ -f "$SVC" ] || { echo "پنل هنوز نصب نشده؛ اول بدون --update نصب کن"; exit 1; }
  PORT=$(grep -oE -- '-port [0-9]+' "$SVC" | awk '{print $2}')
  ALLOW=$(grep -oE -- '-allow [0-9.]+' "$SVC" | awk '{print $2}')
else
  PORT=${1:-$((20000 + RANDOM % 30000))}
  ALLOW=${2:-}
fi
LISTEN=127.0.0.1
if [ -n "$ALLOW" ]; then LISTEN=0.0.0.0; fi

command -v curl >/dev/null || { apt-get update -y && apt-get install -y curl; }
command -v openssl >/dev/null || apt-get install -y openssl

mkdir -p /etc/tunnelpanel
# رمز: در به‌روزرسانی رمز قبلی نگه داشته می‌شود
if [ -s /etc/tunnelpanel/pass ]; then
  PASS=$(cat /etc/tunnelpanel/pass)
  PASS_NOTE="(رمز قبلی حفظ شد)"
else
  PASS=$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 14)
  PASS_NOTE=""
fi

A=$(uname -m); if [ "$A" = "x86_64" ]; then A=amd64; else A=arm64; fi

# هسته Backhaul (فقط برای ترنسپورت‌های tcp/ws و نسخه‌های mux)
if [ ! -x /usr/local/bin/backhaul ]; then
  curl -fL "https://github.com/Musixal/Backhaul/releases/latest/download/backhaul_linux_${A}.tar.gz" -o /tmp/bh.tgz
  echo "SHA256 هسته Backhaul: $(sha256sum /tmp/bh.tgz | cut -d' ' -f1)"
  if [ -n "$BH_SHA256" ]; then
    echo "$BH_SHA256  /tmp/bh.tgz" | sha256sum -c - || { echo "هش Backhaul نامطابق است"; exit 1; }
  fi
  tar -xzf /tmp/bh.tgz -C /usr/local/bin backhaul && chmod +x /usr/local/bin/backhaul
fi

# گواهی خودامضا برای ترنسپورت‌های wss و nahangtls/nahangx
[ -f /etc/tunnelpanel/cert.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout /etc/tunnelpanel/key.pem -out /etc/tunnelpanel/cert.pem -subj "/CN=www.example.com" 2>/dev/null

# دانلود و تأیید باینری قبل از توقف سرویس (اگر دانلود خراب باشد، پنل فعلی دست‌نخورده می‌ماند)
BASE="https://github.com/${REPO}/releases/latest/download"
curl -fL "$BASE/tunnelpanel-linux-$A" -o /tmp/tunnelpanel-linux-$A
curl -fL "$BASE/SHA256SUMS" -o /tmp/SHA256SUMS
(cd /tmp && grep " tunnelpanel-linux-$A\$" SHA256SUMS | sha256sum -c -) || { echo "هش باینری پنل نامطابق است؛ نصب متوقف شد"; exit 1; }

systemctl stop tunnelpanel 2>/dev/null || true
install -m 755 /tmp/tunnelpanel-linux-$A /usr/local/bin/tunnelpanel

umask 077; printf '%s' "$PASS" > /etc/tunnelpanel/pass; umask 022

cat > "$SVC" <<EOF
[Unit]
Description=Tunnel Panel
After=network.target
[Service]
ExecStart=/usr/local/bin/tunnelpanel -listen $LISTEN -port $PORT -user admin ${ALLOW:+-allow $ALLOW -tls}
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now tunnelpanel

# فایل مدیریت: نصب‌کننده‌ی محلی و دستور nahang
mkdir -p "$MENU_SHARE"
if [ -f "$0" ] && [ "$(readlink -f "$0")" != "$MENU_SHARE/install.sh" ]; then
  cp "$0" "$MENU_SHARE/install.sh"
fi

cat > /usr/local/bin/nahang <<'MENU'
#!/bin/bash
# منوی مدیریت پنل تانل — اجرا: sudo nahang
SVC=/etc/systemd/system/tunnelpanel.service
DIR=/etc/tunnelpanel
[ "$EUID" -ne 0 ] && { echo "با root اجرا کنید: sudo nahang"; exit 1; }

tunnels() { systemctl list-units 'tp-*' --all --no-legend --plain 2>/dev/null | awk '{print $1}' | sed 's/\.service$//'; }

status() {
  echo "پنل: $(systemctl is-active tunnelpanel 2>/dev/null)"
  local list; list=$(tunnels)
  if [ -z "$list" ]; then echo "  تانلی ساخته نشده است"; return; fi
  for u in $list; do printf '  %-16s %s\n' "${u#tp-}" "$(systemctl is-active "$u")"; done
}

pick() {
  local list=($(tunnels)); SEL=""
  if [ ${#list[@]} -eq 0 ]; then echo "تانلی وجود ندارد"; return 1; fi
  local i=1
  for u in "${list[@]}"; do echo "  $i) ${u#tp-}"; i=$((i+1)); done
  read -rp "شماره‌ی تانل: " n
  if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le ${#list[@]} ]; then
    SEL=${list[$((n-1))]}; return 0
  fi
  echo "شماره نامعتبر است"; return 1
}

show_addr() {
  local p ip a
  p=$(grep -oE -- '-port [0-9]+' "$SVC" | awk '{print $2}')
  ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  a=$(grep -oE -- '-allow [0-9.]+' "$SVC" | awk '{print $2}')
  if [ -n "$a" ]; then
    echo "آدرس پنل: https://$ip:$p  (فقط برای IP مجاز $a)"
  else
    echo "پنل فقط محلی است. از کامپیوتر خودت:"
    echo "  ssh -L 8443:127.0.0.1:$p root@$ip"
    echo "سپس در مرورگر باز کن: http://127.0.0.1:8443"
  fi
  echo "کاربر: admin"
  echo "رمز:   $(cat $DIR/pass 2>/dev/null)"
}

uninstall() {
  read -rp "پنل و همه‌ی تانل‌ها حذف شوند؟ برای تأیید YES بنویس: " c
  [ "$c" = "YES" ] || { echo "لغو شد"; return; }
  for u in $(tunnels); do
    systemctl disable --now "$u" 2>/dev/null
    rm -f "/etc/systemd/system/$u.service"
  done
  systemctl disable --now tunnelpanel 2>/dev/null
  rm -f "$SVC" /usr/local/bin/tunnelpanel
  iptables -S INPUT 2>/dev/null | grep -- '-j tp-' | sed 's/^-A/-D/' | while read -r r; do iptables $r; done
  for c in $(iptables -S 2>/dev/null | awk '/^-N tp-/{print $2}'); do iptables -F "$c"; iptables -X "$c"; done
  rm -rf "$DIR" /usr/local/share/tunnelpanel
  systemctl daemon-reload
  echo "پنل حذف شد. اگر قانون ip6tables دستی اضافه کرده‌ای، جدا پاکش کن."
  rm -f /usr/local/bin/nahang
  exit 0
}

while true; do
  clear
  echo "======================================"
  echo "        مدیریت پنل تانل (nahang)"
  echo "======================================"
  status
  echo "--------------------------------------"
  echo " 1) آدرس و رمز پنل"
  echo " 2) ری‌استارت پنل"
  echo " 3) ری‌استارت یک تانل"
  echo " 4) لاگ یک تانل"
  echo " 5) پشتیبان‌گیری از تانل‌ها"
  echo " 6) به‌روزرسانی پنل"
  echo " 7) حذف کامل"
  echo " 0) خروج"
  echo "--------------------------------------"
  read -rp "انتخاب: " c
  case "$c" in
    1) show_addr ;;
    2) systemctl restart tunnelpanel && echo "پنل ری‌استارت شد" ;;
    3) pick && systemctl restart "$SEL" && echo "$SEL ری‌استارت شد" ;;
    4) pick && journalctl -u "$SEL" -n 60 --no-pager ;;
    5) f=/root/tunnels-backup-$(date +%F-%H%M).json
       cp "$DIR/tunnels.json" "$f" && chmod 600 "$f" && echo "پشتیبان ذخیره شد: $f" ;;
    6) bash /usr/local/share/tunnelpanel/install.sh --update ;;
    7) uninstall ;;
    0) exit 0 ;;
    *) echo "گزینه‌ی نامعتبر" ;;
  esac
  echo
  read -rp "Enter برای ادامه..." _
done
MENU
chmod 755 /usr/local/bin/nahang

echo "================================"
if [ "$UPDATE" = 1 ]; then
  echo "پنل به‌روزرسانی شد. پورت و تنظیمات قبلی حفظ شدند."
else
  if [ -z "$ALLOW" ]; then
    echo "پنل فقط محلی است (از اینترنت دیده نمی‌شود). از کامپیوتر خودت اجرا کن:"
    echo "  ssh -L 8443:127.0.0.1:$PORT root@IP-سرور"
    echo "سپس در مرورگر باز کن: http://127.0.0.1:8443"
  else
    echo "آدرس پنل:  https://IP-سرور:$PORT  (فقط برای IP $ALLOW؛ گواهی خودامضاست)"
  fi
  echo "کاربر: admin"
  echo "رمز:   $PASS $PASS_NOTE"
fi
echo "مدیریت از خط فرمان: sudo nahang"
echo "================================"
