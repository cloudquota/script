#!/bin/bash

# 检查是否以root用户运行
if [ "$(id -u)" -ne 0 ]; then
  echo "请以root用户运行此脚本。"
  exit 1
fi

# 删除旧的 geoip.dat 和 geosite.dat 文件
rm -f /usr/local/x-ui/bin/geoip.dat /usr/local/x-ui/bin/geosite.dat

# 下载最新的 geoip.dat 文件
wget -O /usr/local/x-ui/bin/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat

# 下载最新的 geosite.dat 文件
wget -O /usr/local/x-ui/bin/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat

# 赋予 geoip.dat 和 geosite.dat 文件 755 权限
chmod 755 /usr/local/x-ui/bin/geoip.dat
chmod 755 /usr/local/x-ui/bin/geosite.dat

# 重启 x-ui 服务
systemctl restart x-ui

echo "geoip.dat 和 geosite.dat 已更新，并且 x-ui 服务已重启。"
