#!/bin/bash

# 安装 curl
apt install curl -y

# 停止可能正在运行的ddns-go服务
systemctl stop ddns-go

# 删除旧的ddns-go文件（如果存在）
rm -f /usr/bin/ddns-go

# 创建临时目录并进入
mkdir -p ./ddns
cd ./ddns

# 根据系统架构选择合适的下载链接
uname -m | grep -qi aarch64 && oarch=linux_arm64 || oarch=linux_x86_64;

# 下载最新的ddns-go版本
wget "$(curl -s https://api.github.com/repos/jeessy2/ddns-go/releases/latest | grep -i "browser_download_url.*${oarch}" | awk -F '"' '{print $(NF-1)}')"

# 解压下载的文件
tar -xzvf ./ddns*.tar.gz

# 赋予执行权限
chmod +x ./ddns-go

# 移动到/usr/bin
mv ./ddns-go /usr/bin

# 清理临时文件并返回上一级目录
cd ..
rm -rf ./ddns

# 安装ddns-go服务
ddns-go -s install

# 设置ddns-go服务开机自动启动
systemctl enable ddns-go

# 启动ddns-go服务
systemctl start ddns-go
