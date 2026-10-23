#!/bin/bash
# Install / update / uninstall the Nahang tunnel panel. Run on BOTH servers (Iran and foreign).
#   Install:    sudo bash install.sh                 (asks for the port and your IP)
#   Update:     sudo bash install.sh --update        (or: sudo nahang, option 7)
#   Uninstall:  sudo bash install.sh --uninstall     (or: sudo nahang, option 8)
set -e
[ "$EUID" -ne 0 ] && { echo "Run as root"; exit 1; }

REPO="Alireza647xvhyfdc/nahangpanel"
SVC=/etc/systemd/system/tunnelpanel.service
MENU_SHARE=/usr/local/share/tunnelpanel

TTY=${TP_TTY:-/dev/tty}   # TP_TTY is only for testing

# Prompts go straight to the terminal so they appear on the same line as the input
has_tty() { [ -r "$TTY" ] && (: >"$TTY") 2>/dev/null; }
ask() {
  local answer=""
  printf '%s' "$1" >"$TTY" 2>/dev/null || true
  IFS= read -r answer <"$TTY" 2>/dev/null || answer=""
  printf '%s' "${answer:-$2}"
}
confirm() {
  local answer=""
  printf '%s' "$1" >"$TTY" 2>/dev/null || true
  IFS= read -r answer <"$TTY" 2>/dev/null || answer=""
  [ "$answer" = "$2" ]
}

step() { echo ">>> $*"; }
trap 'rc=$?; [ "$rc" -ne 0 ] && echo "!!! Install failed (exit code $rc) at line $LINENO. Fix the problem above and run the installer again." >&2' EXIT
# download with timeouts and retries; prints a clear error instead of dying silently
dl() {  # dl URL OUTPUT
  curl -fL --connect-timeout 15 --max-time 300 --retry 3 --retry-delay 2 "$1" -o "$2" \
    || { echo "!!! Download failed: $1" >&2; echo "    (check that this server can reach github.com, and that the release exists)" >&2; exit 1; }
}

uninstall_panel() {
  for u in $(systemctl list-units 'tp-*' --all --no-legend --plain 2>/dev/null | awk '{print $1}' | sed 's/\.service$//'); do
    systemctl disable --now "$u" 2>/dev/null || true
    rm -f "/etc/systemd/system/$u.service"
  done
  systemctl disable --now tunnelpanel 2>/dev/null || true
  rm -f "$SVC" /usr/local/bin/tunnelpanel /usr/local/bin/nahang
  iptables -S INPUT 2>/dev/null | grep -- '-j tp-' | sed 's/^-A/-D/' | while read -r r; do iptables $r || true; done
  for ch in $(iptables -S 2>/dev/null | awk '/^-N tp-/{print $2}'); do iptables -F "$ch" || true; iptables -X "$ch" || true; done
  if [ -s /etc/tunnelpanel/host ] && [ -x /root/.acme.sh/acme.sh ]; then
    /root/.acme.sh/acme.sh --remove -d "$(cat /etc/tunnelpanel/host)" >/dev/null 2>&1 || true
  fi
  rm -rf /etc/tunnelpanel "$MENU_SHARE"
  systemctl daemon-reload || true
  echo "The panel has been removed."
}

# Mode: install (default), update, or uninstall
MODE=install
case "${1:-}" in
  --update)    MODE=update ;;
  --uninstall) MODE=uninstall ;;
esac

# Panel already installed and we have a terminal: ask what to do
if [ "$MODE" = install ] && [ -f "$SVC" ] && has_tty; then
  echo "The panel is already installed."
  echo " 1) Reinstall (choose the port again)"
  echo " 2) Update to the latest version"
  echo " 3) Uninstall the panel"
  echo " 0) Exit"
  case "$(ask 'Choice [0]: ' 0)" in
    1) MODE=install ;;
    2) MODE=update ;;
    3) MODE=uninstall ;;
    *) echo "Nothing changed."; exit 0 ;;
  esac
fi

if [ "$MODE" = uninstall ]; then
  if confirm "Remove the panel and ALL tunnels? Type YES to confirm: " YES; then
    uninstall_panel
  else
    echo "Cancelled."
  fi
  exit 0
fi

UPDATE=0
if [ "$MODE" = update ]; then
  [ -f "$SVC" ] || { echo "The panel is not installed yet. Run the installer without options first."; exit 1; }
  UPDATE=1
  PORT=$(grep -oE -- '-port [0-9]+' "$SVC" | awk '{print $2}')
  PUBLIC=0; grep -q -- '-listen 0.0.0.0' "$SVC" && PUBLIC=1
else
  # Panel port. Enter = random free port between 20000 and 49999
  DEFAULT_PORT=$((20000 + RANDOM % 30000))
  while :; do
    PORT=$(ask "Panel port [$DEFAULT_PORT]: " "$DEFAULT_PORT")
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
  # Direct access on the server IP over HTTPS, protected by the panel password (default)
  PUBLIC=1
fi
LISTEN=127.0.0.1
if [ "$PUBLIC" = 1 ]; then LISTEN=0.0.0.0; fi

step "Checking requirements (curl, openssl)..."
command -v curl >/dev/null || { apt-get update -y && apt-get install -y curl; }
command -v openssl >/dev/null || { apt-get update -y; apt-get install -y openssl; }

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
  step "Downloading Backhaul core..."
  dl "https://github.com/Musixal/Backhaul/releases/latest/download/backhaul_linux_${A}.tar.gz" /tmp/bh.tgz
  echo "Backhaul SHA256: $(sha256sum /tmp/bh.tgz | cut -d' ' -f1)"
  if [ -n "$BH_SHA256" ]; then
    echo "$BH_SHA256  /tmp/bh.tgz" | sha256sum -c - || { echo "Backhaul checksum mismatch"; exit 1; }
  fi
  tar -xzf /tmp/bh.tgz -C /usr/local/bin backhaul && chmod +x /usr/local/bin/backhaul
fi

# Xray core (inbounds and clients on the foreign server). Skipped when it is already installed.
# The panel writes /usr/local/etc/xray/config.json and manages the "xray" service (see below).
if [ ! -x /usr/local/bin/xray ]; then
  case "$(uname -m)" in
    x86_64|amd64)  XA=Xray-linux-64.zip ;;
    aarch64|arm64) XA=Xray-linux-arm64-v8a.zip ;;
    *) XA="" ;;
  esac
  if [ -z "$XA" ]; then
    echo "!!! Xray has no release for $(uname -m); install it manually at /usr/local/bin/xray" >&2
  else
    step "Downloading Xray core..."
    XBASE="https://github.com/XTLS/Xray-core/releases/latest/download"
    rm -rf /tmp/xray-dl && mkdir -p /tmp/xray-dl
    dl "$XBASE/$XA" /tmp/xray-dl/xray.zip
    dl "$XBASE/$XA.dgst" /tmp/xray-dl/xray.dgst
    WANT=$(grep -m1 '^SHA2-256=' /tmp/xray-dl/xray.dgst | sed 's/^SHA2-256= *//' | tr -d '[:space:]')
    GOT=$(sha256sum /tmp/xray-dl/xray.zip | cut -d' ' -f1)
    [ -n "$WANT" ] && [ "$WANT" = "$GOT" ] || { echo "Xray checksum mismatch; install aborted"; exit 1; }
    command -v unzip >/dev/null || { apt-get update -y >/dev/null && apt-get install -y unzip; }
    unzip -o -q /tmp/xray-dl/xray.zip xray -d /tmp/xray-dl
    install -m 755 /tmp/xray-dl/xray /usr/local/bin/xray
    rm -rf /tmp/xray-dl
    echo "Xray installed: $(/usr/local/bin/xray version | head -1)"
  fi
fi

# ---------------------------------------------------------------------------
# Certificate for the panel (HTTPS). Asked only on a fresh install / reinstall.
#   1) Domain  -> trusted Let's Encrypt certificate for your domain
#   2) IP      -> trusted Let's Encrypt certificate for the server IP (short-lived, auto-renewed)
#   3) Self-signed (browser warning)
# On update the existing certificate is kept untouched.
# ---------------------------------------------------------------------------
CERT_MODE=keep
CERT_DOMAIN=""
if [ "$UPDATE" != 1 ]; then
  CERT_MODE=ip
  if has_tty; then
    echo
    echo "How should the HTTPS certificate be issued?"
    echo " 1) Domain  (Let's Encrypt, the domain must point to this server)"
    echo " 2) IP      (Let's Encrypt, for the server IP address)"
    echo " 3) Self-signed (no real certificate, browser shows a warning)"
    case "$(ask 'Choice [2]: ' 2)" in
      1) CERT_MODE=domain ;;
      3) CERT_MODE=self ;;
      *) CERT_MODE=ip ;;
    esac
  fi
fi

SERVER_IP=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

if [ "$CERT_MODE" = domain ]; then
  while :; do
    CERT_DOMAIN=$(ask "Domain name (e.g. panel.example.com): " "")
    CERT_DOMAIN=$(echo "$CERT_DOMAIN" | tr 'A-Z' 'a-z' | tr -d ' ')
    if [[ "$CERT_DOMAIN" =~ ^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$ ]]; then break; fi
    echo "Invalid domain. Try again (example: panel.example.com)."
  done
  RESOLVED=$(getent ahostsv4 "$CERT_DOMAIN" 2>/dev/null | awk '{print $1; exit}')
  if [ "$RESOLVED" != "$SERVER_IP" ]; then
    echo "Warning: $CERT_DOMAIN resolves to '${RESOLVED:-nothing}', but this server's IP is $SERVER_IP."
    if ! confirm "Continue anyway? [y/N]: " y; then
      echo "Fix the DNS record and run the installer again."; exit 1
    fi
  fi
fi

issue_acme_cert() {  # issue_acme_cert MODE(domain|ip) VALUE ; returns non-zero on failure
  local mode=$1 value=$2 AH=/root/.acme.sh
  # port 80 must be free for the HTTP-01 challenge
  if (exec 3<>"/dev/tcp/127.0.0.1/80") 2>/dev/null; then
    echo "Port 80 is in use by another program; it is required to validate the certificate."
    return 1
  fi
  command -v socat >/dev/null || { apt-get update -y >/dev/null 2>&1; apt-get install -y socat >/dev/null 2>&1; } || true
  if [ ! -x "$AH/acme.sh" ]; then
    step "Installing acme.sh..."
    rm -rf /tmp/acme-src && mkdir -p /tmp/acme-src
    curl -fL --connect-timeout 15 --max-time 120 --retry 3 \
      "https://github.com/acmesh-official/acme.sh/archive/refs/heads/master.tar.gz" -o /tmp/acme-src.tgz || return 1
    tar -xzf /tmp/acme-src.tgz -C /tmp/acme-src --strip-components=1 || return 1
    (cd /tmp/acme-src && ./acme.sh --install --home "$AH" --accountemail "admin@${value//[^a-zA-Z0-9.-]/}.invalid" >/dev/null 2>&1) || true
    rm -rf /tmp/acme-src /tmp/acme-src.tgz
    [ -x "$AH/acme.sh" ] || return 1
  fi
  "$AH/acme.sh" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
  step "Requesting certificate for $value (port 80 must be reachable from the internet)..."
  local extra=()
  [ "$mode" = ip ] && extra=(--certificate-profile shortlived --days 3)
  "$AH/acme.sh" --issue -d "$value" --standalone --httpport 80 --server letsencrypt "${extra[@]}" --force \
    || [ -s "$AH/${value}_ecc/fullchain.cer" ] || [ -s "$AH/$value/fullchain.cer" ] || return 1
  "$AH/acme.sh" --install-cert -d "$value" --ecc \
    --key-file /etc/tunnelpanel/key.pem --fullchain-file /etc/tunnelpanel/cert.pem \
    --reloadcmd "systemctl restart tunnelpanel 2>/dev/null || true" >/dev/null 2>&1 \
    || "$AH/acme.sh" --install-cert -d "$value" \
    --key-file /etc/tunnelpanel/key.pem --fullchain-file /etc/tunnelpanel/cert.pem \
    --reloadcmd "systemctl restart tunnelpanel 2>/dev/null || true" >/dev/null 2>&1 || true
  [ -s /etc/tunnelpanel/cert.pem ] && [ -s /etc/tunnelpanel/key.pem ] || return 1
  chmod 600 /etc/tunnelpanel/key.pem
  return 0
}

PANEL_HOST="$SERVER_IP"
case "$CERT_MODE" in
  domain|ip)
    step "Creating certificate (Let's Encrypt, $CERT_MODE)..."
    if [ "$CERT_MODE" = domain ]; then WANT=$CERT_DOMAIN; else WANT=$SERVER_IP; fi
    if issue_acme_cert "$CERT_MODE" "$WANT"; then
      PANEL_HOST="$WANT"
      echo "Trusted certificate installed for $WANT (renews automatically)."
    else
      echo "!!! Could not get a Let's Encrypt certificate for $WANT." >&2
      echo "    Check: DNS/IP is correct, port 80 is open in the firewall and not used by another program." >&2
      if [ -s /etc/tunnelpanel/cert.pem ]; then
        echo "    The previous certificate was kept." >&2
      else
        echo "    Falling back to a self-signed certificate. Run the installer again later to retry." >&2
        CERT_MODE=self
      fi
    fi
    ;;
esac

# Self-signed certificate (also the fallback); used by the wss and nahangx transports too
if [ "$CERT_MODE" = self ] || [ ! -s /etc/tunnelpanel/cert.pem ]; then
  step "Creating self-signed certificate..."
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout /etc/tunnelpanel/key.pem -out /etc/tunnelpanel/cert.pem -subj "/CN=www.example.com" 2>/dev/null
  rm -f /etc/tunnelpanel/host
  [ "$CERT_MODE" = keep ] || CERT_MODE=self
fi
# Remember which host name the panel certificate is valid for (used by "sudo nahang")
case "$CERT_MODE" in
  domain|ip) printf '%s' "$PANEL_HOST" > /etc/tunnelpanel/host ;;
esac

# Download and verify the panel binary BEFORE stopping the service
# (if the download fails, the running panel is left untouched)
BASE="https://github.com/${REPO}/releases/latest/download"
step "Downloading panel binary..."
dl "$BASE/tunnelpanel-linux-$A" /tmp/tunnelpanel-linux-$A
dl "$BASE/SHA256SUMS" /tmp/SHA256SUMS
(cd /tmp && grep " tunnelpanel-linux-$A\$" SHA256SUMS | sha256sum -c -) || { echo "Panel binary checksum mismatch; install aborted"; exit 1; }

step "Installing and starting the panel service..."
systemctl stop tunnelpanel 2>/dev/null || true
install -m 755 /tmp/tunnelpanel-linux-$A /usr/local/bin/tunnelpanel

umask 077; printf '%s' "$PASS" > /etc/tunnelpanel/pass; umask 022

cat > "$SVC" <<EOF
[Unit]
Description=Tunnel Panel
After=network.target
[Service]
ExecStart=/usr/local/bin/tunnelpanel -listen $LISTEN -port $PORT -user admin $([ "$PUBLIC" = 1 ] && echo -tls)
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now tunnelpanel

# Xray service unit (only if none exists, so an existing setup is never overwritten).
# It is enabled but not started here: the panel starts it when it writes the first config.
if [ -x /usr/local/bin/xray ] && [ ! -f /etc/systemd/system/xray.service ]; then
  mkdir -p /usr/local/etc/xray
  cat > /etc/systemd/system/xray.service <<'XRAYUNIT'
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
XRAYUNIT
  systemctl daemon-reload && systemctl enable xray >/dev/null 2>&1 || true
fi

# Local installer copy (used for updates) and the nahang command
mkdir -p "$MENU_SHARE"
echo "$REPO" > "$MENU_SHARE/repo"
if [ -f "$0" ] && [ "$(readlink -f "$0")" != "$MENU_SHARE/install.sh" ]; then
  cp "$0" "$MENU_SHARE/install.sh"
elif [ ! -f "$MENU_SHARE/install.sh" ]; then
  # Run through a pipe (curl | bash): fetch a copy for future updates
  curl -fsSL --connect-timeout 15 --max-time 60 "https://raw.githubusercontent.com/$REPO/main/install.sh" -o "$MENU_SHARE/install.sh" || echo "Warning: could not save an installer copy for updates (not critical)."
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
  a=""; grep -q -- '-listen 0.0.0.0' "$SVC" && a=1
  ip=$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')
  if [ -n "$a" ] && [ -s "$DIR/host" ]; then
    echo "Panel address: https://$(cat "$DIR/host"):$p  (trusted Let's Encrypt certificate)"
  elif [ -n "$a" ]; then
    echo "Panel address: https://$ip:$p  (self-signed certificate, accept the browser warning)"
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
  if [ "$PUBLIC" = 1 ] && [ "$CERT_MODE" != self ]; then
    echo "Panel URL: https://$PANEL_HOST:$PORT  (trusted Let's Encrypt certificate)"
  elif [ "$PUBLIC" = 1 ]; then
    echo "Panel URL: https://$SERVER_IP:$PORT  (self-signed certificate, accept the browser warning)"
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
