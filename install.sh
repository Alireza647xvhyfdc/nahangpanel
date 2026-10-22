#!/bin/bash
# Install / update the Nahang tunnel panel. Run on BOTH servers (Iran and foreign).
# Install:  sudo bash install.sh   (you will be asked for the panel port)
# Update:   sudo nahang   (option 7)   or   sudo bash /usr/local/share/tunnelpanel/install.sh --update
set -e
[ "$EUID" -ne 0 ] && { echo "Run as root"; exit 1; }

REPO="Alireza647xvhyfdc/nahangpanel"
SVC=/etc/systemd/system/tunnelpanel.service
MENU_SHARE=/usr/local/share/tunnelpanel

UPDATE=0
[ "$1" = "--update" ] && UPDATE=1

if [ "$UPDATE" = 1 ]; then
  [ -f "$SVC" ] || { echo "Panel is not installed yet. Run without --update first."; exit 1; }
  PORT=$(grep -oE -- '-port [0-9]+' "$SVC" | awk '{print $2}')
  ALLOW=$(grep -oE -- '-allow [0-9.]+' "$SVC" | awk '{print $2}')
else
  # Ask for the panel port (empty = random free port between 20000 and 49999)
  DEFAULT_PORT=$((20000 + RANDOM % 30000))
  while :; do
    PORT=""
    read -rp "Panel port [$DEFAULT_PORT]: " PORT </dev/tty 2>/dev/null || true
    PORT=${PORT:-$DEFAULT_PORT}
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
      echo "Invalid port. Enter a number between 1 and 65535."
      continue
    fi
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
      echo "Port $PORT is already in use. Choose another one."
      continue
    fi
    break
  done
  valid_ipv4() {
    local re='^([0-9]{1,3}\.){3}[0-9]{1,3}$' a b c d
    [[ "$1" =~ $re ]] || return 1
    IFS=. read -r a b c d <<<"$1"
    [ "$a" -le 255 ] && [ "$b" -le 255 ] && [ "$c" -le 255 ] && [ "$d" -le 255 ]
  }
  # Optional: your public IP, allowed to open the panel directly over HTTPS.
  # Empty = panel is local only and is reached through SSH.
  while :; do
    ALLOW=""
    read -rp "Your public IP for direct access (empty = SSH only): " ALLOW </dev/tty 2>/dev/null || true
    ALLOW=$(echo "$ALLOW" | tr -d ' ')
    if [ -z "$ALLOW" ] || valid_ipv4 "$ALLOW"; then break; fi
    echo "Invalid IPv4 address."
  done
fi
LISTEN=127.0.0.1
if [ -n "$ALLOW" ]; then LISTEN=0.0.0.0; fi

command -v curl >/dev/null || { apt-get update -y && apt-get install -y curl; }
command -v openssl >/dev/null || apt-get install -y openssl

mkdir -p /etc/tunnelpanel
# Password: kept on update
if [ -s /etc/tunnelpanel/pass ]; then
  PASS=$(cat /etc/tunnelpanel/pass)
  PASS_NOTE="(previous password kept)"
else
  PASS=$(head -c 12 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 14)
  PASS_NOTE=""
fi

A=$(uname -m); if [ "$A" = "x86_64" ]; then A=amd64; else A=arm64; fi

# Backhaul core (only for the tcp/ws and mux transports)
if [ ! -x /usr/local/bin/backhaul ]; then
  curl -fL "https://github.com/Musixal/Backhaul/releases/latest/download/backhaul_linux_${A}.tar.gz" -o /tmp/bh.tgz
  echo "Backhaul SHA256: $(sha256sum /tmp/bh.tgz | cut -d' ' -f1)"
  if [ -n "$BH_SHA256" ]; then
    echo "$BH_SHA256  /tmp/bh.tgz" | sha256sum -c - || { echo "Backhaul checksum mismatch"; exit 1; }
  fi
  tar -xzf /tmp/bh.tgz -C /usr/local/bin backhaul && chmod +x /usr/local/bin/backhaul
fi

# Self-signed certificate for the wss and nahangtls/nahangx transports
[ -f /etc/tunnelpanel/cert.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout /etc/tunnelpanel/key.pem -out /etc/tunnelpanel/cert.pem -subj "/CN=www.example.com" 2>/dev/null

# Download and verify the panel binary BEFORE stopping the service
# (if the download fails, the running panel is left untouched)
BASE="https://github.com/${REPO}/releases/latest/download"
curl -fL "$BASE/tunnelpanel-linux-$A" -o /tmp/tunnelpanel-linux-$A
curl -fL "$BASE/SHA256SUMS" -o /tmp/SHA256SUMS
(cd /tmp && grep " tunnelpanel-linux-$A\$" SHA256SUMS | sha256sum -c -) || { echo "Panel binary checksum mismatch; install aborted"; exit 1; }

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

# Local installer copy (used for updates) and the nahang command
mkdir -p "$MENU_SHARE"
echo "$REPO" > "$MENU_SHARE/repo"
if [ -f "$0" ] && [ "$(readlink -f "$0")" != "$MENU_SHARE/install.sh" ]; then
  cp "$0" "$MENU_SHARE/install.sh"
elif [ ! -f "$MENU_SHARE/install.sh" ]; then
  # Run through a pipe (curl | bash): fetch a copy for future updates
  curl -fsSL "https://raw.githubusercontent.com/$REPO/main/install.sh" -o "$MENU_SHARE/install.sh"
fi

cat > /usr/local/bin/nahang <<'MENU'
#!/bin/bash
# Nahang tunnel panel manager. Run: sudo nahang
SVC=/etc/systemd/system/tunnelpanel.service
DIR=/etc/tunnelpanel
SHARE=/usr/local/share/tunnelpanel
BIN=/usr/local/bin/tunnelpanel
REPO=$(cat "$SHARE/repo" 2>/dev/null)
[ "$EUID" -ne 0 ] && { echo "Run as root: sudo nahang"; exit 1; }

tunnels() { systemctl list-units 'tp-*' --all --no-legend --plain 2>/dev/null | awk '{print $1}' | sed 's/\.service$//'; }

status() {
  echo "Panel: $(systemctl is-active tunnelpanel 2>/dev/null)   Version: $(installed_version)"
  local list; list=$(tunnels)
  if [ -z "$list" ]; then echo "  No tunnels created yet"; return; fi
  for u in $list; do printf '  %-16s %s\n' "${u#tp-}" "$(systemctl is-active "$u")"; done
}

pick() {
  local list=($(tunnels)); SEL=""
  if [ ${#list[@]} -eq 0 ]; then echo "No tunnels exist"; return 1; fi
  local i=1
  for u in "${list[@]}"; do echo "  $i) ${u#tp-}"; i=$((i+1)); done
  read -rp "Tunnel number: " n
  if [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le ${#list[@]} ]; then
    SEL=${list[$((n-1))]}; return 0
  fi
  echo "Invalid number"; return 1
}

show_addr() {
  local p ip a
  p=$(grep -oE -- '-port [0-9]+' "$SVC" | awk '{print $2}')
  ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  a=$(grep -oE -- '-allow [0-9.]+' "$SVC" | awk '{print $2}')
  ip=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
  if [ -n "$a" ]; then
    echo "Panel address: https://$ip:$p  (only for allowed IP $a)"
  else
    echo "The panel is local only. From your local machine run:"
    echo "  ssh -L $p:127.0.0.1:$p root@$ip"
    echo "Then open in your browser: http://127.0.0.1:$p"
  fi
  echo "User:     admin"
  echo "Password: $(cat $DIR/pass 2>/dev/null)"
}

installed_version() { "$BIN" -version 2>/dev/null || echo "unknown"; }

latest_version() {
  curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null \
    | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

# returns 0 = up to date, 2 = update available, 1 = error
check_update() {
  if [ -z "$REPO" ]; then echo "Repository is not set. Reinstall the panel."; return 1; fi
  local cur lat
  cur=$(installed_version)
  lat=$(latest_version)
  echo "Installed version: $cur"
  if [ -z "$lat" ]; then echo "Could not reach GitHub. Check the server's internet access."; return 1; fi
  echo "Latest release:    $lat"
  if [ "$cur" = "$lat" ]; then echo "You are up to date."; return 0; fi
  echo "A new version is available."; return 2
}

update_panel() {
  check_update
  local rc=$?
  if [ $rc -ne 2 ]; then return; fi
  read -rp "Install the latest version now? [y/N]: " a
  if [[ ! "$a" =~ ^[Yy]$ ]]; then echo "Cancelled"; return; fi
  if ! curl -fsSL "https://raw.githubusercontent.com/$REPO/main/install.sh" -o /tmp/nahang-install.sh; then
    echo "Download of the installer failed"; return
  fi
  bash /tmp/nahang-install.sh --update
  rm -f /tmp/nahang-install.sh
}

uninstall() {
  read -rp "Remove the panel and ALL tunnels? Type YES to confirm: " c
  if [ "$c" != "YES" ]; then echo "Cancelled"; return; fi
  for u in $(tunnels); do
    systemctl disable --now "$u" 2>/dev/null
    rm -f "/etc/systemd/system/$u.service"
  done
  systemctl disable --now tunnelpanel 2>/dev/null
  rm -f "$SVC" "$BIN"
  iptables -S INPUT 2>/dev/null | grep -- '-j tp-' | sed 's/^-A/-D/' | while read -r r; do iptables $r; done
  for ch in $(iptables -S 2>/dev/null | awk '/^-N tp-/{print $2}'); do iptables -F "$ch"; iptables -X "$ch"; done
  rm -rf "$DIR" "$SHARE"
  systemctl daemon-reload
  echo "Panel removed. If you added ip6tables rules manually, remove them yourself."
  rm -f /usr/local/bin/nahang
  exit 0
}

while true; do
  clear
  echo "======================================"
  echo "       Nahang Tunnel Panel Manager"
  echo "======================================"
  status
  echo "--------------------------------------"
  echo " 1) Panel address and password"
  echo " 2) Restart panel"
  echo " 3) Restart a tunnel"
  echo " 4) Show tunnel logs"
  echo " 5) Back up tunnels"
  echo " 6) Check for updates"
  echo " 7) Update panel"
  echo " 8) Uninstall completely"
  echo " 0) Exit"
  echo "--------------------------------------"
  read -rp "Choice: " c
  case "$c" in
    1) show_addr ;;
    2) systemctl restart tunnelpanel && echo "Panel restarted" ;;
    3) pick && systemctl restart "$SEL" && echo "$SEL restarted" ;;
    4) pick && journalctl -u "$SEL" -n 60 --no-pager ;;
    5) f=/root/tunnels-backup-$(date +%F-%H%M).json
       cp "$DIR/tunnels.json" "$f" && chmod 600 "$f" && echo "Backup saved: $f" ;;
    6) check_update ;;
    7) update_panel ;;
    8) uninstall ;;
    0) exit 0 ;;
    *) echo "Invalid choice" ;;
  esac
  echo
  read -rp "Press Enter to continue..." _
done
MENU
chmod 755 /usr/local/bin/nahang

echo "================================"
if [ "$UPDATE" = 1 ]; then
  echo "Panel updated. Previous port and settings were kept."
else
  SERVER_IP=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
  if [ -n "$ALLOW" ]; then
    echo "Panel URL: https://$SERVER_IP:$PORT  (only for IP $ALLOW; self-signed certificate, accept the browser warning)"
  else
    echo "The panel listens locally only (not reachable from the internet). From your local machine run:"
    echo "  ssh -L $PORT:127.0.0.1:$PORT root@$SERVER_IP"
    echo "Then open in your browser: http://127.0.0.1:$PORT"
  fi
  echo "User:     admin"
  echo "Password: $PASS $PASS_NOTE"
fi
echo "Manage from the command line: sudo nahang"
echo "================================"
