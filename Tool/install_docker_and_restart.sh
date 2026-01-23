#!/bin/bash

# 检查是否为root用户执行
if [ "$(id -u)" -ne 0 ]; then
   echo "该脚本需要以root权限运行" 1>&2
   exit 1
fi

# 安装Docker
curl -fsSL https://get.docker.com | bash

# 设置Docker开机自启动
systemctl enable docker

# 重启Docker服务
systemctl restart docker

echo "Docker已成功安装并重启。"
