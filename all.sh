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

# trap优化
trap "echo -e '${RED}脚本被中断！${NC}'; exit 1" INT
trap "echo -e '${RED}发生错误，脚本退出！${NC}'; exit 1" ERR
trap "echo -e '${YELLOW}脚本已退出。${NC}'" EXIT

set -eo pipefail

# 检查命令是否存在
require_cmd() {
  for cmd in "$@"; do
    if ! command -v "$cmd" &>/dev/null; then
      echo -e "${RED}缺少必要命令: $cmd，请先安装！${NC}"
      exit 1
    fi
  done
}

# 检查网络连通性
check_network() {
  if ! ping -c 1 -W 2 8.8.8.8 &>/dev/null; then
    echo -e "${RED}网络不可用，请检查网络连接！${NC}"
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
    error) echo -e "${RED}✗ ${msg}失败！${NC}" >&2 ;;
  esac
}

# 基础软件包安装
install_packages() {
  status_msg running "更新系统并安装基础软件包"
  require_cmd apt
  check_network
  apt update -y
  apt install -y wget curl unzip jq nethogs
  status_msg success "软件包安装"
}

# 启用BBR优化
enable_bbr() {
  status_msg running "启用BBR网络优化"
  grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf || \
    echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  grep -q "net.ipv4.tcp_congestion_control=bbr" /etc/sysctl.conf || \
    echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p >/dev/null
  modprobe tcp_bbr
  status_msg success "BBR优化配置"
}

# X-UI面板安装
install_xui() {
  status_msg running "安装X-UI面板"
  require_cmd curl bash
  check_network
  bash <(curl -fsSL https://raw.githubusercontent.com/cloudquota/script/main/Tool/x-ui.sh)
}

# X-UI更新
update_xui() {
  status_msg running "更新X-UI面板"
  require_cmd curl bash
  check_network
  bash <(curl -fsSL https://raw.githubusercontent.com/cloudquota/script/main/Tool/x-ui-update.sh)
}

# DDNS配置
setup_ddns() {
  status_msg running "配置DDNS动态域名"
  require_cmd curl bash
  check_network
  bash <(curl -fsSL https://raw.githubusercontent.com/cloudquota/script/main/Tool/install-ddns-go.sh)
}

# GOST代理安装
install_gost() {
  status_msg running "安装gost代理工具"
  require_cmd wget bash
  check_network
  script_file="gost.sh"
  [ ! -f "$script_file" ] && \
    wget --no-check-certificate -O "$script_file" \
    https://raw.githubusercontent.com/qqrrooty/EZgost/main/gost.sh
  chmod +x "$script_file"
  ./"$script_file"
}

# Docker环境部署
setup_docker() {
  status_msg running "部署Docker运行环境"
  require_cmd wget bash
  check_network
  script_file="install_docker_and_restart.sh"
  [ ! -f "$script_file" ] && \
    wget -q -N https://raw.githubusercontent.com/cloudquota/script/main/Tool/install_docker_and_restart.sh
  bash "$script_file"
}

# 欧洲Docker优化
eu_docker_optimize() {
  status_msg running "执行欧洲Docker优化配置"
  require_cmd curl bash
  check_network
  bash <(curl -fsSL https://raw.githubusercontent.com/fscarmen/tools/main/EU_docker_Up.sh)
}

#--------- 主逻辑流程 ---------#

# 显示交互菜单
show_menu() {
  clear
  echo -e "${BLUE}==== 服务器配置工具箱 ====${NC}"
  echo "1. 系统基础配置 (更新+软件包+BBR)"
  echo "2. 安装/更新X-UI面板"
  echo "3. DDNS动态域名配置"
  echo "4. gost代理工具部署"
  echo "5. Docker环境全配置"
  echo "6. 执行完整初始化流程"
  echo "7. 退出"
}

# 输入验证
valid_choice() {
  [[ "$1" =~ ^[1-7]$ ]]
}

# 执行对应操作
process_choice() {
  case $1 in
    1) 
      install_packages
      enable_bbr
      ;;
    2)
      install_xui
      update_xui
      ;;
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
      update_xui
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

# 主执行逻辑
main() {
  local last_choice=""
  while true; do
    show_menu
    read -p "请输入操作编号 (1-7, q退出): " choice
    [[ "$choice" == "q" || "$choice" == "Q" ]] && break
    if [[ -z "$choice" && -n "$last_choice" ]]; then
      choice="$last_choice"
    fi
    if valid_choice "$choice"; then
      last_choice="$choice"
      process_choice "$choice"
      read -p "按回车返回主菜单..."
    else
      echo -e "${RED}无效输入，请输入1-7之间的数字${NC}"
      sleep 2
    fi
  done
  echo -e "${GREEN}感谢使用，再见！${NC}"
}

# 脚本入口
main
