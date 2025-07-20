#!/bin/bash

# 用法：./cloudflare_update_dns.sh <域名> <Cloudflare_API_Token>

# 检查参数
if [ "$#" -ne 2 ]; then
    echo "使用方法: $0 <域名> <Cloudflare_API_Token>"
    echo "示例: $0 388488.xyz vMS0Jxxxxxxx"
    exit 1
fi

DOMAIN=$1
CF_API_TOKEN=$2
RECORD_TYPE="A"
TTL=60
SUBDOMAIN=$(hostname)
FULLNAME="$SUBDOMAIN.$DOMAIN"

# 获取当前公网 IP
NEW_VALUE=$(curl -s https://api.ipify.org)
if [ -z "$NEW_VALUE" ]; then
    echo "无法获取公网 IP"
    exit 1
fi

# 获取 Zone ID
ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" | jq -r '.result[0].id')

if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" == "null" ]; then
    echo "获取 Zone ID 失败，请检查域名和 Token 是否正确。"
    exit 1
fi

# 获取 DNS记录 ID
record_info=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=$FULLNAME" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json")

RECORD_ID=$(echo "$record_info" | jq -r '.result[0].id')
CURRENT_VALUE=$(echo "$record_info" | jq -r '.result[0].content')

# 若 IP 无变化，跳过更新
if [ "$NEW_VALUE" == "$CURRENT_VALUE" ]; then
    echo "IP 无变化，跳过更新。"
    exit 0
fi

# 创建或更新记录
if [ -z "$RECORD_ID" ] || [ "$RECORD_ID" == "null" ]; then
    echo "记录不存在，正在创建..."
    response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
      -H "Authorization: Bearer $CF_API_TOKEN" \
      -H "Content-Type: application/json" \
      --data "{
        \"type\": \"$RECORD_TYPE\",
        \"name\": \"$FULLNAME\",
        \"content\": \"$NEW_VALUE\",
        \"ttl\": $TTL,
        \"proxied\": false
      }")
else
    echo "记录存在，正在更新..."
    response=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
      -H "Authorization: Bearer $CF_API_TOKEN" \
      -H "Content-Type: application/json" \
      --data "{
        \"type\": \"$RECORD_TYPE\",
        \"name\": \"$FULLNAME\",
        \"content\": \"$NEW_VALUE\",
        \"ttl\": $TTL,
        \"proxied\": false
      }")
fi

# 检查结果
if echo "$response" | grep -q '"success":true'; then
    echo "[$(date)] DNS 更新成功：$FULLNAME -> $NEW_VALUE"
else
    echo "[$(date)] DNS 更新失败，响应如下："
    echo "$response"
fi
