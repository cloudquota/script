#!/bin/bash

# 增强版GCP防火墙规则配置脚本
# 功能：创建基础网络规则并支持条件配置
# 特点：幂等性检查｜错误处理｜颜色提示｜安全警告

# 初始化颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # 重置颜色

# 配置参数（可修改）
NETWORK="default"
PRIORITY=1000
TAG_HTTP="http-server"
TAG_HTTPS="https-server"

# 预检测函数
check_dependency() {
  if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}错误：gcloud CLI 未安装，请先配置Google Cloud SDK${NC}"
    exit 1
  fi
}

# 带状态提示的规则创建函数
create_firewall_rule() {
  local rule_name=$1
  local description=$2
  shift 2

  echo -e "${BLUE}[操作] 正在配置规则：${rule_name}${NC}"
  
  if gcloud compute firewall-rules describe "$rule_name" --format="value(name)" >/dev/null 2>&1; then
    echo -e "${YELLOW}警告：规则 ${rule_name} 已存在，跳过创建${NC}"
    return 0
  fi

  if ! gcloud compute firewall-rules create "$rule_name" \
    --network="$NETWORK" \
    --priority="$PRIORITY" \
    "$@" \
    --description="$description" 2>/dev/null; then
    echo -e "${RED}错误：创建规则 ${rule_name} 失败${NC}"
    return 1
  fi
  
  echo -e "${GREEN}成功：规则 ${rule_name} 已生效${NC}"
}

# 安全警告提示
echo -e "${YELLOW}════════ 安全警告 ════════${NC}"
echo -e "${YELLOW}即将创建开放所有流量的规则！"
echo -e "请确认这是否符合您的安全要求${NC}"
read -p "是否继续？(Y/n) " -n 1 -r
echo
# 如果用户直接按回车（空输入），则默认为 Y
if [[ -z "$REPLY" || $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${GREEN}继续执行...${NC}"
else
    echo -e "${RED}操作已取消${NC}"
    exit 1
fi

# 主执行流程
check_dependency

# IPv4/IPv6全流量规则
for protocol in 4 6; do
  create_firewall_rule "allow-all-ingress-ipv${protocol}" \
    "Allow all IPv${protocol} inbound traffic" \
    --direction=INGRESS \
    --action=ALLOW \
    --rules=all \
    --source-ranges=$( [[ $protocol == 4 ]] && echo "0.0.0.0/0" || echo "::/0" )

  create_firewall_rule "allow-all-egress-ipv${protocol}" \
    "Allow all IPv${protocol} outbound traffic" \
    --direction=EGRESS \
    --action=ALLOW \
    --rules=all \
    --destination-ranges=$( [[ $protocol == 4 ]] && echo "0.0.0.0/0" || echo "::/0" )
done

# 应用服务规则
for service in http https; do
  create_firewall_rule "allow-${service}-tagged" \
    "Allow ${service^^} traffic to tagged instances" \
    --direction=INGRESS \
    --action=ALLOW \
    --rules=tcp:$( [[ $service == "http" ]] && echo "80" || echo "443" ) \
    --target-tags=$( [[ $service == "http" ]] && echo "$TAG_HTTP" || echo "$TAG_HTTPS" )
done

echo -e "\n${GREEN}======= 配置完成 =======${NC}"
echo -e "后续操作建议："
echo -e "1. 确保需要开放服务的实例已配置对应标签："
echo -e "   - HTTP服务实例标签: ${BLUE}${TAG_HTTP}${NC}"
echo -e "   - HTTPS服务实例标签: ${BLUE}${TAG_HTTPS}${NC}"
echo -e "2. 建议定期审查全开放规则的必要性"
