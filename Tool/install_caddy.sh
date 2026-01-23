#!/bin/bash

# 安装必需的依赖
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https

# 导入Caddy的GPG密钥
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg

# 添加Caddy到APT源列表
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list

# 更新APT源并安装Caddy
sudo apt update && sudo apt install -y caddy

# 启用Caddy服务（确保它在开机时启动）
sudo systemctl enable caddy

# 启动Caddy服务
sudo systemctl start caddy
