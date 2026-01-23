#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 重置颜色

# 检查是否为root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}请以root用户运行本脚本！${NC}"
  exit 1
fi

# 更稳的严格模式
set -euo pipefail

# trap 优化（用函数，颜色变量可正常展开）
on_int() { echo -e "${RED}脚本被中断！${NC}"; exit 1; }
on_err() { echo -e "${RED}发生错误，脚本退出！${NC}"; exit 1; }
on_exit(){ echo -e "${YELLOW}脚本已退出。${NC}"; }
trap on_int INT
trap on_err ERR
trap on_exit EXIT

# 检查命令是否存在
require_cmd() {
  for cmd in "$@"; do
    if ! command -v "$cmd" &>/dev/null; then
      echo -e "${RED}缺少必要命令: ${cmd}，请先安装！${NC}"
      exit 1
    fi
  done
}

# 检查网络连通性（不用 ping，避免被禁 ICMP 误判）
check_network() {
  # 尽量用 HTTPS 访问判断（你后续要访问 GitHub RAW，这里也测 GitHub）
  if ! curl -fsS --max-time 6 https://github.com >/dev/null; then
    echo -e "${RED}网络不可用或无法访问 GitHub，请检查网络/解析/防火墙！${NC}"
    exit 1
  fi
}

# 显示带颜色状态的消息
status_msg() {
  local type="$1"
  local msg="$2"
  case "$type" in
    running) echo -e "${YELLOW}▶ ${msg}...${NC}" ;;
    success) echo -e "${GREEN}✓ ${msg}成功！${NC}" ;;
    error)   echo -e "${RED}✗ ${msg}失败！${NC}" >&2 ;;
  esac
}

# 系统与包管理器检查（你原脚本写死 apt，这里明确仅支持 Debian/Ubuntu）
ensure_debian_like() {
  if ! command -v apt-get >/dev/null 2>&1; then
    echo -e "${RED}未检测到 apt-get：本脚本当前仅支持 Debian/Ubuntu/Armbian。${NC}"
    exit 1
  fi
}

# 基础软件包安装（修正：apt update 没有 -y，脚本里用 apt-get 更稳）
install_packages() {
  status_msg running "更新软件源并安装基础软件包"
  ensure_debian_like
  require_cmd apt-get
  check_network

  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y

  # 说明：
  # - 去掉 nethogs：它不是必需，有时依赖/交互会带来麻烦
  # - 保留 wget/curl/unzip/jq：后续脚本依赖
  apt-get install -y wget curl unzip jq ca-certificates openssl tzdata

  status_msg success "软件包安装"
}

# 启用BBR优化（加容错）
enable_bbr() {
  status_msg running "启用BBR网络优化"

  grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf || echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf

  sysctl -p >/dev/null || true
  modprobe tcp_bbr 2>/dev/null || true

  status_msg success "BBR优化配置"
}

# X-UI面板安装
install_xui() {
  status_msg running "安装X-UI面板"
  require_cmd curl bash
  check_network
  bash <(curl -fsSL https://raw.githubusercontent.com/cloudquota/script/main/Tool/x-ui.sh)
  status_msg success "X-UI执行"
}

# DDNS配置
setup_ddns() {
  status_msg running "配置DDNS动态域名"
  require_cmd curl bash
  check_network
  bash <(curl -fsSL https://raw.githubusercontent.com/cloudquota/script/main/Tool/install-ddns-go.sh)
  status_msg success "DDNS配置"
}

# GOST代理安装
install_gost() {
  status_msg running "安装gost代理工具"
  require_cmd wget bash
  check_network

  local script_file="gost.sh"
  if [[ ! -f "$script_file" ]]; then
    wget --no-check-certificate -O "$script_file" \
      https://raw.githubusercontent.com/qqrrooty/EZgost/main/gost.sh
  fi
  chmod +x "$script_file"
  ./"$script_file"

  status_msg success "gost执行"
}

# Docker环境部署
setup_docker() {
  status_msg running "部署Docker运行环境"
  require_cmd wget bash
  check_network

  local script_file="install_docker_and_restart.sh"
  if [[ ! -f "$script_file" ]]; then
    wget -q -N https://raw.githubusercontent.com/cloudquota/script/main/Tool/install_docker_and_restart.sh
  fi
  bash "$script_file"

  status_msg success "Docker环境部署"
}

# 欧洲Docker优化
eu_docker_optimize() {
  status_msg running "执行Docker守护进程"
  require_cmd curl bash
  check_network
  bash <(curl -fsSL https://raw.githubusercontent.com/fscarmen/tools/main/EU_docker_Up.sh)
  status_msg success "Docker守护进程"
}

#--------- 主逻辑流程 ---------#

show_menu() {
  clear
  echo -e "${BLUE}==== 服务器配置工具箱 ====${NC}"
  echo "1. 系统基础配置 (安装软件包 + BBR)"
  echo "2. 安装X-UI面板"
  echo "3. DDNS动态域名配置"
  echo "4. gost代理工具部署"
  echo "5. Docker环境全配置"
  echo "6. 执行完整初始化流程"
  echo "7. 退出"
}

valid_choice() {
  [[ "${1:-}" =~ ^[1-7]$ ]]
}

process_choice() {
  case "$1" in
    1)
      install_packages
      enable_bbr
      ;;
    2)
      install_xui
      ;;
    3)
      setup_ddns
      ;;
    4)
      install_gost
      ;;
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
      echo -e "${GREEN}已退出系统${NC}"
      exit 0
      ;;
  esac
}

main() {
  local last_choice=""
  while true; do
    show_menu
    read -r -p "请输入操作编号 (1-7, q退出): " choice
    [[ "${choice}" == "q" || "${choice}" == "Q" ]] && break

    # 回车重复上次操作
    if [[ -z "${choice}" && -n "${last_choice}" ]]; then
      choice="${last_choice}"
    fi

    if valid_choice "${choice}"; then
      last_choice="${choice}"
      process_choice "${choice}"
      read -r -p "按回车返回主菜单..."
    else
      echo -e "${RED}无效输入，请输入1-7之间的数字${NC}"
      sleep 2
    fi
  done
  echo -e "${GREEN}感谢使用，再见！${NC}"
}

main
