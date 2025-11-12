#!/bin/bash
# install_yhds_fullcolor.sh
# YHDS VPN PREMIUM - Installer (Debian 11) - No Reboot
# Ports: SSH=80, Trojan WS TLS=443, SSH-over-WS(vm)=8080, Nginx=81, BadVPN udpgw template for UDP custom
# Uses IP (no domain). Telegram notify built-in with provided token/chatid.

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# ----------------- Configuration (edit only if needed) -----------------
TG_TOKEN="8052861512:AAE6AYA9eHz-Pf2ZVXOkBVFapkB7lKKHGZ4"
TG_CHATID="7709130318"
ADMIN_USER="bokzzz"
ADMIN_PASS="bokzzz"
LOG="/etc/log-create-user.log"
MENU_PATH="/usr/local/bin/menu"
SCRIPTS_DIR="/root/scripts"
HOST_IP="$(curl -s ipv4.icanhazip.com || echo "127.0.0.1")"
# ----------------------------------------------------------------------

# colors
RED="\e[31;1m"; GREEN="\e[32;1m"; YELLOW="\e[33;1m"; CYAN="\e[36;1m"; MAGENTA="\e[35;1m"; NC="\e[0m"; BOLD="\e[1m"

echo -e "${CYAN}==> Starting YHDS FullColor installer (Debian 11) - no reboot${NC}"

# 1) basic packages
apt update -y >/dev/null 2>&1 || true
apt install -y curl wget jq git lsb-release ca-certificates apt-transport-https gnupg2 python3 python3-pip build-essential cmake unzip uuid-runtime dialog net-tools iproute2 openssl >/dev/null 2>&1 || true

# create directories & logs
mkdir -p /etc/xray /etc/xray/ssl "$SCRIPTS_DIR" /root/backups
touch "$LOG"
chmod 644 "$LOG"

# create admin helper user (non-destructive)
if ! id "$ADMIN_USER" >/dev/null 2>&1; then
  useradd -r -d /home/script -s /bin/bash -M "$ADMIN_USER" >/dev/null 2>&1 || true
  echo -e "${ADMIN_PASS}\n${ADMIN_PASS}" | passwd "$ADMIN_USER" >/dev/null 2>&1 || true
  usermod -aG sudo "$ADMIN_USER" >/dev/null 2>&1 || true
fi

# 2) Install Xray (official) if possible
echo -e "${CYAN}==> Installing Xray (official installer)${NC}"
if ! command -v xray >/dev/null 2>&1; then
  bash <(curl -sL https://raw.githubusercontent.com/XTLS/Xray-install/main/install-release.sh) >/dev/null 2>&1 || echo -e "${YELLOW}Warning: Xray installer failed or blocked; continuing with local config (xray may not run until installer works).${NC}"
else
  echo -e "${GREEN}Xray already installed.${NC}"
fi

# 3) Install Nginx and set to listen on 81 to avoid conflict
apt install -y nginx >/dev/null 2>&1 || true
if [ -f /etc/nginx/sites-available/default ]; then
  sed -i 's/listen 80 default_server;/listen 81 default_server;/' /etc/nginx/sites-available/default 2>/dev/null || true
  sed -i 's/listen \[::\]:80 default_server;/listen \[::\]:81 default_server;/' /etc/nginx/sites-available/default 2>/dev/null || true
fi
systemctl enable --now nginx >/dev/null 2>&1 || true

# 4) Build BadVPN udpgw (if missing)
if [ ! -f /usr/local/bin/badvpn-udpgw ]; then
  echo -e "${CYAN}==> Compiling BadVPN udpgw (may take ~1-2 min)...${NC}"
  rm -rf /root/badvpn-src >/dev/null 2>&1 || true
  git clone https://github.com/ambrop72/badvpn.git /root/badvpn-src >/dev/null 2>&1 || true
  mkdir -p /root/badvpn-src/build
  pushd /root/badvpn-src/build >/dev/null 2>&1 || true
  cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 >/dev/null 2>&1 || true
  make -j2 >/dev/null 2>&1 || true
  cp badvpn-udpgw /usr/local/bin/ 2>/dev/null || true
  popd >/dev/null 2>&1 || true
fi

# 5) systemd template for badvpn
cat > /etc/systemd/system/badvpn-udpgw@.service <<'BADSVC'
[Unit]
Description=BadVPN UDPGW %i
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:%i --max-clients 500
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
BADSVC
systemctl daemon-reload >/dev/null 2>&1 || true

# start a few default badvpn instances to show UDP "ON" if build ok
for p in 4000 5000 6000; do
  systemctl enable --now badvpn-udpgw@${p}.service >/dev/null 2>&1 || true
done

# 6) Create self-signed TLS cert for IP SAN
echo -e "${CYAN}==> Creating self-signed TLS cert with IP SAN = ${HOST_IP}${NC}"
cat > /tmp/openssl-ip.cnf <<_CF
[ req ]
default_bits = 2048
prompt = no
distinguished_name = dn
x509_extensions = v3_ext

[ dn ]
C = ID
ST = Jakarta
L = Jakarta
O = YHDS
OU = YHDS VPN
CN = ${HOST_IP}

[ v3_ext ]
subjectAltName = @alt_names

[ alt_names ]
IP.1 = ${HOST_IP}
_CF
mkdir -p /etc/xray/ssl
openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
  -keyout /etc/xray/ssl/privkey.pem \
  -out /etc/xray/ssl/fullchain.pem \
  -config /tmp/openssl-ip.cnf >/dev/null 2>&1 || true
chmod 600 /etc/xray/ssl/privkey.pem || true
chmod 644 /etc/xray/ssl/fullchain.pem || true
rm -f /tmp/openssl-ip.cnf

# 7) Minimal Xray config (Trojan WS TLS @443, Vmess WS @8080)
echo -e "${CYAN}==> Writing /etc/xray/config.json (minimal)${NC}"
cat > /etc/xray/config.json <<'XCFG'
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "trojan",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "wsSettings": {
          "path": "/trojan-ws"
        },
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "/etc/xray/ssl/fullchain.pem",
              "keyFile": "/etc/xray/ssl/privkey.pem"
            }
          ]
        }
      }
    },
    {
      "port": 8080,
      "protocol": "vmess",
      "settings": {
        "clients": []
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/ssh-ws"
        }
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
XCFG

systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable --now xray >/dev/null 2>&1 || true
systemctl restart xray >/dev/null 2>&1 || true || echo -e "${YELLOW}Warning: xray may not have started (installer/network).${NC}"

# 8) Configure OpenSSH to listen on port 80 (append, don't duplicate)
echo -e "${CYAN}==> Configure OpenSSH to listen on port 80${NC}"
if [ -f /etc/ssh/sshd_config ]; then
  if ! grep -qE '^Port 80' /etc/ssh/sshd_config 2>/dev/null; then
    sed -i '/^Port /d' /etc/ssh/sshd_config 2>/dev/null || true
    echo "Port 80" >> /etc/ssh/sshd_config
  fi
  systemctl restart ssh >/dev/null 2>&1 || systemctl restart sshd >/dev/null 2>&1 || true
fi

# 9) helper scripts directory
mkdir -p "$SCRIPTS_DIR"

# Create create_account script (manual create, prints payload in sample format)
cat > "${SCRIPTS_DIR}/create_account.sh" <<'CREATE'
#!/bin/bash
LOG="/etc/log-create-user.log"
IP="$(curl -s ipv4.icanhazip.com || echo '127.0.0.1')"
timestamp(){ date "+%Y-%m-%d %H:%M:%S"; }

echo "Pilih jenis akun:"
echo "1) SSH (port 80)"
echo "2) UDP-Custom (badvpn)"
echo "3) SSH-over-WS (vmess @8080 path /ssh-ws)"
echo "4) Trojan WS TLS (port 443 path /trojan-ws)"
echo "5) Vmess (vmess @8080)"
read -p "Pilihan [1-5]: " tipe

read -p "Remarks (nama): " REMARKS
read -p "Limit IP (contoh 2): " LIMIT_IP
read -p "User Quota (contoh 1000 GB): " USER_QUOTA
read -p "Durasi (hari, kosong=30): " DAYS
if ! [[ "$DAYS" =~ ^[0-9]+$ ]]; then DAYS=30; fi
EXPIRE=$(date -d "+$DAYS days" +%Y-%m-%d)

case $tipe in
 1)
   read -p "Username: " USER
   read -p "Password (kosong=auto): " PASS
   if [ -z "$PASS" ]; then PASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c14); fi
   if id "$USER" >/dev/null 2>&1; then echo "User sudah ada"; exit 1; fi
   useradd -m -s /bin/bash -e "$EXPIRE" "$USER" >/dev/null 2>&1 || { echo "Gagal membuat user"; exit 1; }
   echo -e "$PASS\n$PASS" | passwd "$USER" >/dev/null 2>&1 || true
   echo "$(timestamp) SSH ${REMARKS} user:${USER} pass:${PASS} expire:${EXPIRE} limit_ip:${LIMIT_IP} quota:${USER_QUOTA}" >> "$LOG"
   echo
   echo "◇━━━━━━━━━━━━━━━━━━━━━━━◇   ⚡️ SSH Account ⚡️   ◇━━━━━━━━━━━━━━━━━━━━━━━◇"
   echo "» Remarks     : ${REMARKS}"
   echo "» Limit IP    : ${LIMIT_IP}"
   echo "» Host Server : ${IP}"
   echo "» User Quota  : ${USER_QUOTA}"
   echo "» Port SSH    : 80"
   echo "» User        : ${USER}"
   echo "◇━━━━━━━━━━━━━━━━━━━━━━━◇"
   echo "Payload / connect:"
   echo "ssh://${USER}@${IP}:80#${REMARKS}"
   ;;
 2)
   read -p "Record name: " NAME
   read -p "Port UDP (kosong=acak 10000-60000): " PPORT
   if [ -z "$PPORT" ]; then PPORT=$((10000 + RANDOM % 50000)); fi
   systemctl enable --now badvpn-udpgw@${PPORT}.service >/dev/null 2>&1 || true
   echo "$(timestamp) UDP ${REMARKS} name:${NAME} port:${PPORT} expire:${EXPIRE} limit_ip:${LIMIT_IP} quota:${USER_QUOTA}" >> "$LOG"
   echo
   echo "◇━━━━━━━━━━━━━━━━━━━━━━━◇   ⚡️ UDP Record ⚡️   ◇━━━━━━━━━━━━━━━━━━━━━━━◇"
   echo "» Remarks : ${REMARKS}"
   echo "» Port    : ${PPORT}"
   echo "» Host    : ${IP}"
   echo "◇━━━━━━━━━━━━━━━━━━━━━━━◇"
   echo "Payload (UDP gateway):"
   echo "udp://${IP}:${PPORT}"
   ;;
 3)
   read -p "Username (for payload): " USER
   UUID=$(cat /proc/sys/kernel/random/uuid)
   vmess_json="{\"v\":\"2\",\"ps\":\"YHDS_SSH_WS_${USER}\",\"add\":\"${IP}\",\"port\":\"8080\",\"id\":\"${UUID}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"/ssh-ws\",\"tls\":\"\"}"
   vmess_base=$(echo -n "$vmess_json" | base64 -w0)
   echo "$(timestamp) WS ${REMARKS} user:${USER} id:${UUID} expire:${EXPIRE} limit_ip:${LIMIT_IP} quota:${USER_QUOTA}" >> "$LOG"
   echo
   echo "◇━━━━━━━━━━━━━━━━━━━━━━━◇   ⚡️ SSH-over-WS (vmess) ⚡️   ◇━━━━━━━━━━━━━━━━━━━━━━━◇"
   echo "» Remarks : ${REMARKS}"
   echo "» Host    : ${IP}"
   echo "» Port    : 8080 (path /ssh-ws)"
   echo "» Payload : vmess://${vmess_base}"
   ;;
 4)
   USER_ID=$(cat /proc/sys/kernel/random/uuid)
   PW="$USER_ID"
   if command -v jq >/dev/null 2>&1 && [ -f /etc/xray/config.json ]; then
     tmp=$(mktemp)
     jq --arg pw "$PW" '(.inbounds[] | select(.protocol=="trojan").settings.clients) += [{"password":$pw}]' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
     systemctl restart xray >/dev/null 2>&1 || true
   fi
   echo "$(timestamp) Trojan ${REMARKS} id:${USER_ID} expire:${EXPIRE} limit_ip:${LIMIT_IP} quota:${USER_QUOTA}" >> "$LOG"
   PAY="trojan://${USER_ID}@${IP}:443?path=%2Ftrojan-ws&security=tls&host=${IP}&type=ws&sni=${IP}#${REMARKS}"
   echo
   echo "◇━━━━━━━━━━━━━━━━━━━━━━━◇   ⚡️ Xray/Trojan Account ⚡️   ◇━━━━━━━━━━━━━━━━━━━━━━━◇"
   echo "» Remarks     : ${REMARKS}"
   echo "» Limit IP    : ${LIMIT_IP}"
   echo "» Host Server : ${IP}"
   echo "» User Quota  : ${USER_QUOTA}"
   echo "» Port DNS    : 443,53"
   echo "» Port TLS    : 443"
   echo "» User ID     : ${USER_ID}"
   echo "◇━━━━━━━━━━━━━━━━━━━━━━━◇"
   echo "» Link WS     :  ${PAY}"
   ;;
 5)
   UUID=$(cat /proc/sys/kernel/random/uuid)
   if command -v jq >/dev/null 2>&1 && [ -f /etc/xray/config.json ]; then
     tmp=$(mktemp)
     jq --arg id "$UUID" '(.inbounds[] | select(.protocol=="vmess").settings.clients) += [{"id":$id,"alterId":0,"level":0}]' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
     systemctl restart xray >/dev/null 2>&1 || true
   fi
   vmess_json="{\"v\":\"2\",\"ps\":\"YHDS_VMESS\",\"add\":\"${IP}\",\"port\":\"8080\",\"id\":\"${UUID}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"\",\"path\":\"/ssh-ws\",\"tls\":\"\"}"
   vmess_base=$(echo -n "$vmess_json" | base64 -w0)
   echo "$(timestamp) V2Ray ${REMARKS} id:${UUID} expire:${EXPIRE} limit_ip:${LIMIT_IP} quota:${USER_QUOTA}" >> "$LOG"
   echo
   echo "◇━━━━━━━━━━━━━━━━━━━━━━━◇   ⚡️ Vmess Account ⚡️   ◇━━━━━━━━━━━━━━━━━━━━━━━◇"
   echo "» UUID : ${UUID}"
   echo "» Payload : vmess://${vmess_base}"
   ;;
  *)
   echo "Pilihan salah"; exit 1;;
esac

# Notify Telegram if configured in /etc/yhds_telegram.conf or env
if [ -f /etc/yhds_telegram.conf ]; then . /etc/yhds_telegram.conf; fi
if [ -n "${TG_TOKEN:-}" ] && [ -n "${TG_CHATID:-}" ]; then
  TEXT="<b>New Account</b>%0ARemarks: ${REMARKS}%0AType: ${tipe}%0AHost: ${IP}"
  curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" -d chat_id="${TG_CHATID}" -d parse_mode=html -d text="$TEXT" >/dev/null 2>&1 || true
fi

read -n1 -r -p "Tekan Enter..."
CREATE
chmod +x "${SCRIPTS_DIR}/create_account.sh"

# Trial script
cat > "${SCRIPTS_DIR}/trial_create.sh" <<'TRIAL'
#!/bin/bash
LOG="/etc/log-create-user.log"
IP=$(curl -s ipv4.icanhazip.com || echo "127.0.0.1")
timestamp(){ date "+%Y-%m-%d %H:%M:%S"; }

echo "Trial type:"
echo "1) SSH"
echo "2) UDP"
echo "3) Trojan"
read -p "Pilih [1-3]: " T

read -p "Prefix username (contoh trial): " PFX
if [ -z "$PFX" ]; then PFX="trial"; fi
USER="${PFX}$(date +%s | tail -c4)"
PASS=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c12)
echo "1) 1 jam  2) 6 jam  3) 24 jam"
read -p "Pilih durasi [1-3]: " D
case $D in
 1) DUR="+1 hour"; EXPI=$(date -d "+1 hour" +%Y-%m-%d_%H:%M:%S);;
 2) DUR="+6 hour"; EXPI=$(date -d "+6 hour" +%Y-%m-%d_%H:%M:%S);;
 3) DUR="+24 hour"; EXPI=$(date -d "+24 hour" +%Y-%m-%d_%H:%M:%S);;
 *) DUR="+1 hour"; EXPI=$(date -d "+1 hour" +%Y-%m-%d_%H:%M:%S);;
esac

case $T in
 1)
  useradd -M -s /bin/false -e "$(date -d "$DUR" +%Y-%m-%d_%H:%M:%S)" "$USER" 2>/dev/null || true
  echo -e "$PASS\n$PASS" | passwd "$USER" >/dev/null 2>&1 || true
  echo "$(timestamp) TRIAL_SSH $USER pass:$PASS expire:$EXPI" >> "$LOG"
  echo "=== TRIAL SSH ==="
  echo "User : $USER"
  echo "Pass : $PASS"
  echo "Expire: $EXPI"
  echo "Connect: ssh -p 80 $USER@$IP"
  ;;
 2)
  PORT=$((10000 + RANDOM % 50000))
  systemctl enable --now badvpn-udpgw@${PORT}.service >/dev/null 2>&1 || true
  echo "$(timestamp) TRIAL_UDP ${USER} port:${PORT} expire:${EXPI}" >> "$LOG"
  echo "=== TRIAL UDP ==="
  echo "Port: $PORT"
  echo "Expire: $EXPI"
  ;;
 3)
  PW="trial-$(date +%s | tail -c6)"
  if command -v jq >/dev/null 2>&1 && [ -f /etc/xray/config.json ]; then
    tmp=$(mktemp)
    jq --arg pw "$PW" '(.inbounds[] | select(.protocol=="trojan").settings.clients) += [{"password":$pw}]' /etc/xray/config.json > "$tmp" && mv "$tmp" /etc/xray/config.json
    systemctl restart xray >/dev/null 2>&1 || true
  fi
  echo "$(timestamp) TRIAL_TROJAN ${USER} pw:$PW expire:${EXPI}" >> "$LOG"
  echo "=== TRIAL TROJAN ==="
  echo "Payload:"
  echo "trojan://${PW}@${IP}:443?path=%2Ftrojan-ws&security=tls&host=${IP}&type=ws&sni=${IP}#${USER}"
  ;;
  *)
  echo "Pilihan salah"; exit 1;;
esac

read -n1 -r -p "Tekan Enter..."
TRIAL
chmod +x "${SCRIPTS_DIR}/trial_create.sh"

# list users script
cat > "${SCRIPTS_DIR}/list_users.sh" <<'LIST'
#!/bin/bash
LOG="/etc/log-create-user.log"
echo "=== Recent log (last 200 lines) ==="
tail -n 200 "$LOG"
echo
echo "=== System users (UID>=1000) ==="
awk -F: '($3>=1000)&&($1!="nobody"){printf "%-15s %-8s %s\n",$1,$3,$6}' /etc/passwd
echo
if [ -f /etc/xray/config.json ]; then
  echo "=== Trojan clients in /etc/xray/config.json ==="
  jq -r '.inbounds[] | select(.protocol=="trojan").settings.clients[]?.password' /etc/xray/config.json 2>/dev/null | nl -ba
fi
read -n1 -r -p "Tekan Enter..."
LIST
chmod +x "${SCRIPTS_DIR}/list_users.sh"

# extend account script
cat > "${SCRIPTS_DIR}/extend_account.sh" <<'EXT'
#!/bin/bash
LOG="/etc/log-create-user.log"
read -p "Masukan username / record name yang ingin diperpanjang: " NAME
read -p "Tambah berapa hari? " DAYS
if ! [[ "$DAYS" =~ ^[0-9]+$ ]]; then echo "Input harus angka"; exit 1; fi
if id "$NAME" >/dev/null 2>&1; then
  CUR=$(chage -l "$NAME" | grep "Account expires" | cut -d: -f2 | sed 's/^ //')
  NEW=$(date -d "$CUR + $DAYS days" +%Y-%m-%d 2>/dev/null || date -d "+$DAYS days" +%Y-%m-%d)
  usermod -e "$NEW" "$NAME" 2>/dev/null || true
  echo "$(date '+%Y-%m-%d %H:%M:%S') EXTEND SSH ${NAME} add_days:${DAYS} new_expire:${NEW}" >> "$LOG"
  echo "User $NAME diperpanjang hingga $NEW"
  if [ -f /etc/yhds_telegram.conf ]; then . /etc/yhds_telegram.conf; fi
  if [ -n "${TG_TOKEN:-}" ] && [ -n "${TG_CHATID:-}" ]; then
    TXT="Account extended: $NAME | new expire: $NEW"
    curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" -d chat_id="${TG_CHATID}" -d text="$TXT" >/dev/null 2>&1 || true
  fi
  exit 0
fi
if grep -qi "$NAME" "/etc/log-create-user.log" 2>/dev/null; then
  NEW=$(date -d "+$DAYS days" +%Y-%m-%d)
  echo "$(date '+%Y-%m-%d %H:%M:%S') EXTEND ${NAME} add_days:${DAYS} new_expire:${NEW}" >> "/etc/log-create-user.log"
  echo "Record $NAME diperpanjang (log-only) sampai $NEW"
  exit 0
fi
echo "Tidak menemukan user/record dengan nama $NAME"
EXT
chmod +x "${SCRIPTS_DIR}/extend_account.sh"

# configure telegram (interactive)
cat > "${SCRIPTS_DIR}/configure_telegram.sh" <<'TGCFG'
#!/bin/bash
CONF="/etc/yhds_telegram.conf"
read -p "Masukkan Bot Token (contoh 123:ABC...): " TG_TOKEN
read -p "Masukkan Chat ID (contoh -1001234567890): " TG_CHATID
cat > "$CONF" <<EOF
TG_TOKEN="${TG_TOKEN}"
TG_CHATID="${TG_CHATID}"
EOF
chmod 600 "$CONF"
echo "Mengirim test message..."
curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" -d chat_id="${TG_CHATID}" -d text="YHDS Bot terpasang di $(curl -s ipv4.icanhazip.com)" >/dev/null 2>&1 || echo "Gagal kirim test"
echo "Selesai."
TGCFG
chmod +x "${SCRIPTS_DIR}/configure_telegram.sh"

# restart_all script
cat > "${SCRIPTS_DIR}/restart_all.sh" <<'RST'
#!/bin/bash
echo "Restarting services: ssh, xray, nginx, badvpn instances..."
systemctl restart ssh >/dev/null 2>&1 || true
systemctl restart xray >/dev/null 2>&1 || true
systemctl restart nginx >/dev/null 2>&1 || true
for s in $(systemctl list-units --type=service --no-legend | awk '/badvpn-udpgw@/ {print $1}'); do
  systemctl restart "$s" >/dev/null 2>&1 || true
done
echo "Done."
read -n1 -r -p "Tekan Enter..."
RST
chmod +x "${SCRIPTS_DIR}/restart_all.sh"

# backup script & cron (12 hours) - sends to Telegram if configured
cat > /usr/local/bin/yhds_backup.sh <<'BACK'
#!/bin/bash
BACKUP_DIR="/root/backups"
mkdir -p "$BACKUP_DIR"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BACKUP_DIR/yhds-backup-$TIMESTAMP.tar.gz"
tar -czf "$OUT" /etc/xray /etc/nginx /etc/ssh /etc/log-create-user.log /etc/yhds_telegram.conf 2>/dev/null || true
if [ -f /etc/yhds_telegram.conf ]; then . /etc/yhds_telegram.conf; fi
if [ -n "${TG_TOKEN:-}" ] && [ -n "${TG_CHATID:-}" ]; then
  curl -s -F chat_id="${TG_CHATID}" -F document=@"${OUT}" "https://api.telegram.org/bot${TG_TOKEN}/sendDocument" >/dev/null 2>&1 || true
fi
BACK
chmod +x /usr/local/bin/yhds_backup.sh
cat > /etc/cron.d/yhds_backup <<'CRON'
0 */12 * * * root /usr/local/bin/yhds_backup.sh >/dev/null 2>&1
CRON
chmod 644 /etc/cron.d/yhds_backup

# Build menu/dashboard (colorful)
cat > "${MENU_PATH}" <<'MENU'
#!/bin/bash
NC='\e[0m'; BOLD='\e[1m'
RED='\e[31;1m'; GREEN='\e[32;1m'; YELLOW='\e[33;1m'; CYAN='\e[36;1m'; MAGENTA='\e[35;1m'
LOG="/etc/log-create-user.log"
HOST=$(hostname)
IP=$(curl -s ipv4.icanhazip.com || echo "127.0.0.1")
ISP=$(curl -s ipinfo.io/org | cut -d' ' -f2- || echo "Unknown")
CITY=$(curl -s ipinfo.io/city || echo "N/A")
OS=$(lsb_release -d 2>/dev/null | awk -F"\t" '{print $2}' || (grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"'))
KERNEL=$(uname -r)
UPTIME=$(uptime -p | sed 's/up //')
LOAD=$(uptime | awk -F'load average:' '{print $2}' | sed 's/^[ \t]*//')
RAM=$(free -m | awk 'NR==2{printf "%sMi/%sMi (%d%%)", $3,$2,($3*100/$2)}')
SWAP=$(free -m | awk 'NR==3{printf "%sMi/%sMi", $3,$2}')
DISK=$(df -h / | awk 'NR==2{printf "%s/%s (%s)",$3,$2,$5}')
XRAY_ON=$(systemctl is-active --quiet xray && echo "ON" || echo "OFF")
SSH_ON=$(systemctl is-active --quiet ssh && echo "ON" || echo "OFF")
NGINX_ON=$(systemctl is-active --quiet nginx && echo "ON" || echo "OFF")
BADVPN_CNT=$(systemctl list-units --type=service 'badvpn-udpgw@*' --no-legend 2>/dev/null | awk '/running/{c++} END{print c+0}')
UDP_ON=$( [ "$BADVPN_CNT" -gt 0 ] && echo "ON" || echo "OFF")
ssh_total=$(grep -iE "\bSSH\b" "$LOG" 2>/dev/null | wc -l || echo 0)
udp_total=$(grep -iE "\bUDP\b" "$LOG" 2>/dev/null | wc -l || echo 0)
ws_total=$(grep -iE "\bWS\b" "$LOG" 2>/dev/null | wc -l || echo 0)
trojan_total=$(grep -iE "Trojan " "$LOG" 2>/dev/null | wc -l || echo 0)
v2_total=$(grep -iE "V2Ray " "$LOG" 2>/dev/null | wc -l || echo 0)
trial_total=$(grep -iE "TRIAL_" "$LOG" 2>/dev/null | wc -l || echo 0)
total_all=$((ssh_total+udp_total+ws_total+trojan_total+v2_total))
col_on(){ [ "$1" = "ON" ] && echo -e "${GREEN}${1}${NC}" || echo -e "${RED}${1}${NC}"; }

clear
echo -e "${MAGENTA}${BOLD}"
cat <<'ASCII'
 __   __  _   _  ____   ____   ____   __     __
 \ \ / / | | | |  _ \ |  _ \ |  _ \  \ \   / /
  \ V /  | | | | | | || | | || | | |  \ \_/ / 
   | |   | |_| | |_| || |_| || |_| |   \   /  
   |_|    \___/|____/ |____/ |____/     \_/   
ASCII
echo -e "${NC}"
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}  ${BOLD}YHDS VPN PREMIUM${NC}"
echo -e "${CYAN}  Hostname : ${BOLD}${HOST}${NC}   IP: ${BOLD}${IP}${NC}"
echo -e "${CYAN}  ISP      : ${BOLD}${ISP}${NC}   Lokasi: ${BOLD}${CITY}${NC}"
echo -e "${CYAN}  OS       : ${BOLD}${OS}${NC}   Kernel: ${BOLD}${KERNEL}${NC}"
echo -e "${CYAN}  Uptime   : ${BOLD}${UPTIME}${NC}   Load: ${BOLD}${LOAD}${NC}"
echo -e "${CYAN}  RAM      : ${BOLD}${RAM}${NC}   SWAP: ${BOLD}${SWAP}${NC}"
echo -e "${CYAN}  Disk     : ${BOLD}${DISK}${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${YELLOW}Service Status:${NC}"
echo -e "  SSH   : $(col_on $SSH_ON)    Xray  : $(col_on $XRAY_ON)    Nginx: $(col_on $NGINX_ON)"
echo -e "  BadVPN: $(col_on $UDP_ON)    Instances: ${BOLD}${BADVPN_CNT}${NC}"
echo
echo -e "${GREEN}Account Summary:${NC}"
printf "  %-12s : %3s\n" "SSH" "$ssh_total"
printf "  %-12s : %3s\n" "UDP-CUSTOM" "$udp_total"
printf "  %-12s : %3s\n" "WS" "$ws_total"
printf "  %-12s : %3s\n" "TROJAN" "$trojan_total"
printf "  %-12s : %3s\n" "V2RAY" "$v2_total"
printf "  %-12s : %3s\n" "TRIALS" "$trial_total"
printf "  %-12s : %3s\n" "TOTAL" "$total_all"
echo
echo -e "${YELLOW}Menu:${NC}"
echo -e "${CYAN} 1) Create Account (manual)${NC}"
echo -e "${CYAN} 2) Create UDP (record)${NC}"
echo -e "${CYAN} 3) Create Trojan (full)${NC}"
echo -e "${CYAN} 4) Create Vmess${NC}"
echo -e "${CYAN} 5) Trial Account${NC}"
echo -e "${CYAN} 6) List Users / Logs${NC}"
echo -e "${CYAN} 7) Extend Account${NC}"
echo -e "${CYAN} 8) Configure Telegram Bot${NC}"
echo -e "${CYAN} 9) Restart All Services${NC}"
echo -e "${CYAN}10) Exit${NC}"
echo
read -p "Pilih [1-10]: " opt
case $opt in
 1) bash /root/scripts/create_account.sh ;;
 2) bash /root/scripts/create_account.sh ;; # inside choose UDP
 3) bash /root/scripts/create_account.sh ;; # inside choose Trojan
 4) bash /root/scripts/create_account.sh ;; # inside choose Vmess
 5) bash /root/scripts/trial_create.sh ;;
 6) bash /root/scripts/list_users.sh ;;
 7) bash /root/scripts/extend_account.sh ;;
 8) bash /root/scripts/configure_telegram.sh ;;
 9) bash /root/scripts/restart_all.sh ;;
 10) clear; exit 0 ;;
  *) echo "Pilihan salah"; sleep 1; $MENU_PATH ;;
esac
MENU
chmod +x "${MENU_PATH}"
ln -sf "${MENU_PATH}" /usr/bin/menu

# Save Telegram config file (pre-fill with provided token/chatid)
cat > /etc/yhds_telegram.conf <<EOF
TG_TOKEN="${TG_TOKEN}"
TG_CHATID="${TG_CHATID}"
EOF
chmod 600 /etc/yhds_telegram.conf

# Auto-run menu for root on login (append only)
if ! grep -q "/usr/local/bin/menu" /root/.profile 2>/dev/null; then
  cat >> /root/.profile <<'PROF'
if [ -f /usr/local/bin/menu ]; then
  /usr/local/bin/menu
fi
PROF
fi
chmod 644 /root/.profile

# Try start/restart services (no reboot)
systemctl enable --now xray >/dev/null 2>&1 || true
systemctl enable --now nginx >/dev/null 2>&1 || true
systemctl restart ssh >/dev/null 2>&1 || true

# Final Telegram notification (best effort)
curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage" \
  -d chat_id="${TG_CHATID}" \
  -d parse_mode=html \
  -d text="✅ YHDS installer finished on ${HOST_IP} (Debian 11). Use 'menu' to open dashboard." >/dev/null 2>&1 || true

echo -e "${GREEN}Installer complete (no reboot).${NC}"
echo -e "${YELLOW}Jalankan perintah: menu${NC}"
exit 0
