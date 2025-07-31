#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain}请用 root 权限运行脚本！" && exit 1

# 检测系统类型
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
else
    echo "无法检测系统类型，请手动确认。" >&2
    exit 1
fi

# 检测架构
arch() {
    case "$(uname -m)" in
        x86_64 | x64 | amd64) echo 'amd64' ;;
        i*86 | x86) echo '386' ;;
        armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
        armv7* | armv7 | arm) echo 'armv7' ;;
        *) echo -e "${red}不支持的架构！${plain}" && exit 1 ;;
    esac
}

# 检查 GLIBC >= 2.32
check_glibc_version() {
    glibc_version=$(ldd --version | head -n1 | awk '{print $NF}')
    required_version="2.32"
    if [[ "$(printf '%s\n' "$required_version" "$glibc_version" | sort -V | head -n1)" != "$required_version" ]]; then
        echo -e "${red}GLIBC 版本过低 (${glibc_version})，需要 >= 2.32${plain}"
        exit 1
    fi
}
check_glibc_version

# 安装依赖
install_base() {
    case "${release}" in
        ubuntu | debian | armbian) apt update && apt install -y wget curl tar tzdata ;;
        centos | rhel | almalinux | rocky | ol) yum update -y && yum install -y wget curl tar tzdata ;;
        fedora | amzn | virtuozzo) dnf update -y && dnf install -y wget curl tar tzdata ;;
        arch | manjaro | parch) pacman -Syu --noconfirm wget curl tar tzdata ;;
        *) apt update && apt install -y wget curl tar tzdata ;;
    esac
}

# 安装并配置 x-ui
install_x_ui() {
    cd /usr/local/
    arch_str=$(arch)

    # 获取最新版 tag
    tag_version=$(curl -sL "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | cut -d\" -f4)
    [ -z "$tag_version" ] && echo -e "${red}获取版本失败，请检查网络${plain}" && exit 1

    echo -e "${green}下载 x-ui ${tag_version}...${plain}"
    wget -N -O x-ui-linux-${arch_str}.tar.gz https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-${arch_str}.tar.gz || exit 1
    wget -O /usr/bin/x-ui-temp https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh

    # 停止服务并清理旧文件
    systemctl stop x-ui 2>/dev/null
    rm -rf /usr/local/x-ui/
    tar zxvf x-ui-linux-${arch_str}.tar.gz
    rm -f x-ui-linux-${arch_str}.tar.gz

    cd x-ui
    chmod +x x-ui x-ui.sh bin/xray-linux-${arch_str}
    mv /usr/bin/x-ui-temp /usr/bin/x-ui && chmod +x /usr/bin/x-ui

    # 安装 systemd 服务
    cp -f x-ui.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable x-ui
    systemctl start x-ui

    # 自动配置
    /usr/local/x-ui/x-ui setting -username "admin" -password "19991126." -port 54321 -webBasePath ""
    /usr/local/x-ui/x-ui migrate

    # 显示信息
    ip=$(curl -s --max-time 3 https://api.ipify.org || echo "<你的IP>")
    echo -e "\n${green}x-ui ${tag_version} 安装完成并运行中...${plain}"
    echo -e "${green}=========================================${plain}"
    echo -e "${green}访问地址：http://${ip}:54321/${plain}"
    echo -e "${green}用户名：admin${plain}"
    echo -e "${green}密码：19991126${plain}"
    echo -e "${green}=========================================${plain}"
}

echo -e "${green}开始安装 x-ui ...${plain}"
install_base
install_x_ui
