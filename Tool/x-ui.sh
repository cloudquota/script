#!/bin/bash
set -e

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error:${plain} 请用 root 权限运行脚本！" && exit 1

# ================== 可改参数（按需修改） ==================
PANEL_USER="admin"
PANEL_PASS="19991126."       # 登录密码（带点）
PANEL_PORT="54321"
WEB_BASE_PATH=""             # 为空就是根路径
DOMAIN=""                    # 留空=自签名证书；填域名=申请 Let's Encrypt（需要80端口可用）
# =========================================================

XUI_DIR="/usr/local/x-ui"
TMP_DIR="$(mktemp -d)"
cleanup(){ rm -rf "$TMP_DIR" 2>/dev/null || true; }
trap cleanup EXIT

# 检测系统类型
if [[ -f /etc/os-release ]]; then
  source /etc/os-release
  release=$ID
elif [[ -f /usr/lib/os-release ]]; then
  source /usr/lib/os-release
  release=$ID
else
  echo -e "${red}无法检测系统类型，请手动确认。${plain}" >&2
  exit 1
fi

# 检测架构
arch() {
  case "$(uname -m)" in
    x86_64|x64|amd64) echo 'amd64' ;;
    i*86|x86) echo '386' ;;
    armv8*|armv8|arm64|aarch64) echo 'arm64' ;;
    armv7*|armv7|arm) echo 'armv7' ;;
    s390x) echo 's390x' ;;
    *) echo -e "${red}不支持的架构：$(uname -m)${plain}" && exit 1 ;;
  esac
}

# 只装依赖：不做系统 update/upgrade，避免重启 sshd 把你踢下线
install_base_no_upgrade() {
  case "${release}" in
    ubuntu|debian|armbian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y curl tar tzdata ca-certificates openssl
      ;;
    centos|rhel|almalinux|rocky|ol)
      yum install -y curl tar tzdata ca-certificates openssl
      ;;
    fedora|amzn|virtuozzo)
      dnf install -y curl tar tzdata ca-certificates openssl
      ;;
    arch|manjaro|parch)
      pacman -Sy --noconfirm curl tar tzdata ca-certificates openssl
      ;;
    alpine)
      apk add --no-cache curl tar tzdata ca-certificates openssl
      ;;
    *)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y curl tar tzdata ca-certificates openssl
      ;;
  esac
}

get_latest_tag() {
  curl -fsSL "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" \
    | grep '"tag_name":' | head -n1 | cut -d\" -f4
}

download_and_install_xui() {
  local a tag url tarfile
  a="$(arch)"
  tag="$(get_latest_tag)"
  [[ -z "$tag" ]] && echo -e "${red}获取最新版本失败（GitHub API）。${plain}" && exit 1

  echo -e "${green}下载 3x-ui ${tag} (${a})...${plain}"
  url="https://github.com/MHSanaei/3x-ui/releases/download/${tag}/x-ui-linux-${a}.tar.gz"
  tarfile="${TMP_DIR}/x-ui.tar.gz"
  curl -fL --retry 5 --retry-delay 1 --connect-timeout 10 -o "$tarfile" "$url"

  systemctl stop x-ui 2>/dev/null || true
  rm -rf "$XUI_DIR"
  mkdir -p "$XUI_DIR"

  # 解压到临时目录，再把内容复制到 /usr/local/x-ui
  tar -xzf "$tarfile" -C "$TMP_DIR"

  # 找到包含 x-ui 可执行文件的目录（防止包结构变化）
  local found_dir=""
  found_dir="$(find "$TMP_DIR" -maxdepth 3 -type f -name "x-ui" -print | head -n1 | xargs -r dirname)"
  [[ -z "$found_dir" ]] && echo -e "${red}解压后未找到 x-ui 文件，可能 release 包结构变了。${plain}" && exit 1

  cp -a "$found_dir"/. "$XUI_DIR"/

  chmod +x "$XUI_DIR/x-ui" 2>/dev/null || true
  chmod +x "$XUI_DIR/x-ui.sh" 2>/dev/null || true

  # 安装 systemd 服务（优先用包自带的）
  if [[ -f "$XUI_DIR/x-ui.service" ]]; then
    cp -f "$XUI_DIR/x-ui.service" /etc/systemd/system/x-ui.service
  else
    cat > /etc/systemd/system/x-ui.service <<'EOF'
[Unit]
Description=3x-ui Service
After=network.target nss-lookup.target

[Service]
Type=simple
WorkingDirectory=/usr/local/x-ui
ExecStart=/usr/local/x-ui/x-ui
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
  fi

  systemctl daemon-reload
  systemctl enable x-ui
  systemctl start x-ui

  # 面板账号/端口配置
  "$XUI_DIR/x-ui" setting -username "${PANEL_USER}" -password "${PANEL_PASS}" -port "${PANEL_PORT}" -webBasePath "${WEB_BASE_PATH}"
  "$XUI_DIR/x-ui" migrate || true
}

setup_cert_selfsigned() {
  local ip="$1"
  local cert_dir="/root/cert/panel"
  mkdir -p "$cert_dir"

  echo -e "${yellow}生成自签名证书（不占80端口，不会因为申请证书中断）。${plain}"
  openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "${cert_dir}/privkey.pem" \
    -out "${cert_dir}/fullchain.pem" \
    -days 3650 \
    -subj "/CN=${ip}" >/dev/null 2>&1

  chmod 600 "${cert_dir}/privkey.pem" || true
  chmod 644 "${cert_dir}/fullchain.pem" || true

  "$XUI_DIR/x-ui" cert -webCert "${cert_dir}/fullchain.pem" -webCertKey "${cert_dir}/privkey.pem" || true
  systemctl restart x-ui
}

install_acme() {
  if [[ ! -x ~/.acme.sh/acme.sh ]]; then
    curl -fsSL https://get.acme.sh | sh
  fi
  ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1 || true
  ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
}

setup_cert_domain_acme() {
  local domain="$1"
  local cert_dir="/root/cert/${domain}"
  mkdir -p "$cert_dir"

  echo -e "${green}申请域名证书：${domain}${plain}"
  echo -e "${yellow}注意：需要80端口可从公网访问，且域名已解析到本机IP。${plain}"

  install_acme

  # standalone 会临时占用80端口
  if ! ~/.acme.sh/acme.sh --issue -d "${domain}" --standalone --httpport 80 --force; then
    echo -e "${red}申请失败：检查域名解析/80放行/80占用。将回退自签证书。${plain}"
    return 1
  fi

  ~/.acme.sh/acme.sh --installcert -d "${domain}" \
    --key-file "${cert_dir}/privkey.pem" \
    --fullchain-file "${cert_dir}/fullchain.pem" \
    --reloadcmd "systemctl restart x-ui" >/dev/null 2>&1 || true

  "$XUI_DIR/x-ui" cert -webCert "${cert_dir}/fullchain.pem" -webCertKey "${cert_dir}/privkey.pem" || true
  systemctl restart x-ui
  return 0
}

show_info() {
  local ip url
  ip="$(curl -s --max-time 5 https://api.ipify.org || echo "<你的IP>")"
  if [[ -n "${DOMAIN}" ]]; then
    url="https://${DOMAIN}:${PANEL_PORT}/"
  else
    url="https://${ip}:${PANEL_PORT}/"
  fi

  echo -e "\n${green}3x-ui 安装完成并运行中${plain}"
  echo -e "${green}=========================================${plain}"
  echo -e "${green}访问地址：${url}${plain}"
  echo -e "${green}用户名：${PANEL_USER}${plain}"
  echo -e "${green}密码：${PANEL_PASS}${plain}"
  echo -e "${green}=========================================${plain}"
  if [[ -z "${DOMAIN}" ]]; then
    echo -e "${yellow}提示：自签名证书浏览器提示“不安全”属正常。${plain}"
  fi
}

echo -e "${green}开始安装 3x-ui（不升级系统，避免SSH断开）...${plain}"
install_base_no_upgrade
download_and_install_xui

public_ip="$(curl -s --max-time 5 https://api.ipify.org || echo "127.0.0.1")"

# 证书：默认自签名；填了 DOMAIN 才尝试 acme
if [[ -n "${DOMAIN}" ]]; then
  setup_cert_domain_acme "${DOMAIN}" || setup_cert_selfsigned "${public_ip}"
else
  setup_cert_selfsigned "${public_ip}"
fi

show_info
