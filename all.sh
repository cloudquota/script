#!/bin/bash

# =========================
# 颜色定义
# =========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# =========================
# root 检查
# =========================
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}请以 root 用户运行本脚本！${NC}"
  exit 1
fi

set -euo pipefail

# =========================
# trap
# =========================
on_int() { echo -e "${RED}脚本被中断！${NC}"; exit 1; }
on_err() { echo -e "${RED}发生错误，脚本退出！${NC}"; exit 1; }
on_exit(){ echo -e "${YELLOW}脚本已退出${NC}"; }

trap on_int INT
trap on_err ERR
trap on_exit EXIT

# =========================
# 工具检查
# =========================
require_cmd() {
  for cmd in "$@"; do
    if ! command -v "$cmd" &>/dev/null; then
      echo -e "${RED}缺少必要命令: $cmd${NC}"
      exit 1
    fi
  done
}

# =========================
# 网络检查（修复 curl 依赖问题）
# =========================
check_network() {
  require_cmd curl
  curl -fsS --max-time 6 https://github.com >/dev/null || {
    echo -e "${RED}网络不可用或无法访问 GitHub${NC}"
    exit 1
  }
}

# =========================
# 状态输出
# =========================
status_msg() {
  local type="$1"
  local msg="$2"
  case "$type" in
    running) echo -e "${YELLOW}▶ $msg...${NC}" ;;
    success) echo -e "${GREEN}✓ $msg 成功${NC}" ;;
    error)   echo -e "${RED}✗ $msg 失败${NC}" ;;
  esac
}

# =========================
# Debian 判断
# =========================
ensure_debian_like() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo -e "${RED}仅支持 Debian/Ubuntu 系统${NC}"
    exit 1
  fi
}

# =========================
# 基础软件包
# =========================
install_packages() {
  status_msg running "安装基础软件包"

  ensure_debian_like
  require_cmd apt-get curl

  export DEBIAN_FRONTEND=noninteractive

  apt-get update
  apt-get install -y wget curl unzip jq ca-certificates openssl tzdata

  status_msg success "基础软件包"
}

# =========================
# BBR（标准 Debian 13 写法）
# =========================
enable_bbr() {
  status_msg running "启用 BBR 网络优化"

  # 写入标准 sysctl.d 文件（推荐方式）
  cat >/etc/sysctl.d/99-bbr.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

  # 立即生效（无需重启）
  sysctl --system >/dev/null || true

  # 验证
  local cc
  cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)

  if [[ "$cc" == "bbr" ]]; then
    status_msg success "BBR 已启用（当前: $cc）"
  else
    status_msg error "BBR 启用失败（当前: $cc）"
    return 1
  fi
}

# =========================
# X-UI
# =========================
install_xui() {
  status_msg running "安装 X-UI"

  require_cmd curl bash
  check_network

  bash <(curl -Ls https://raw.githubusercontent.com/alireza0/x-ui/master/install.sh)

  status_msg success "X-UI"
}

# =========================
# DDNS
# =========================
setup_ddns() {
  status_msg running "配置 DDNS"

  require_cmd curl bash
  check_network

  bash <(curl -fsSL https://raw.githubusercontent.com/cloudquota/script/main/Tool/install-ddns-go.sh)

  status_msg success "DDNS"
}

# =========================
# GOST
# =========================
install_gost() {
  status_msg running "安装 GOST"

  require_cmd wget bash
  check_network

  local file="gost.sh"

  if [[ ! -f "$file" ]]; then
    wget -q -O "$file" https://raw.githubusercontent.com/qqrrooty/EZgost/main/gost.sh
  fi

  chmod +x "$file"
  ./"$file"

  status_msg success "GOST"
}

# =========================
# Docker
# =========================
setup_docker() {
  status_msg running "安装 Docker"

  require_cmd wget bash
  check_network

  local file="install_docker_and_restart.sh"

  if [[ ! -f "$file" ]]; then
    wget -q -O "$file" https://raw.githubusercontent.com/cloudquota/script/main/Tool/install_docker_and_restart.sh
  fi

  bash "$file"

  status_msg success "Docker"
}

# =========================
# Docker 优化
# =========================
eu_docker_optimize() {
  status_msg running "Docker 优化"

  require_cmd curl bash
  check_network

  bash <(curl -fsSL https://raw.githubusercontent.com/fscarmen/tools/main/EU_docker_Up.sh)

  status_msg success "Docker优化"
}

# =========================
# 菜单
# =========================
show_menu() {
  clear
  echo -e "${BLUE}==== 服务器工具箱 (Debian 13) ====${NC}"
  echo "1. 系统基础 + BBR"
  echo "2. X-UI"
  echo "3. DDNS"
  echo "4. GOST"
  echo "5. Docker"
  echo "6. 全部初始化"
  echo "7. 退出"
}

valid_choice() {
  [[ "${1:-}" =~ ^[1-7]$ ]]
}

# =========================
# 执行逻辑
# =========================
process_choice() {
  case "$1" in
    1)
      install_packages
      enable_bbr
      ;;
    2) install_xui ;;
    3) setup_ddns ;;
    4) install_gost ;;
    5)
      setup_docker
      eu_docker_optimize
      ;;
    6)
      install_packages
      enable_bbr
      install_xui
      setup_ddns
      install_gost
      setup_docker
      eu_docker_optimize
      ;;
    7)
      echo -e "${GREEN}退出成功${NC}"
      exit 0
      ;;
  esac
}

# =========================
# 主函数
# =========================
main() {
  local last_choice=""

  while true; do
    show_menu
    read -r -p "请输入 (1-7, q退出): " choice

    [[ "$choice" == "q" || "$choice" == "Q" ]] && break

    if [[ -z "$choice" && -n "$last_choice" ]]; then
      choice="$last_choice"
    fi

    if valid_choice "$choice"; then
      last_choice="$choice"
      process_choice "$choice"
      read -r -p "按回车返回菜单..."
    else
      echo -e "${RED}输入错误${NC}"
      sleep 1
    fi
  done

  echo -e "${GREEN}已结束${NC}"
}

main
