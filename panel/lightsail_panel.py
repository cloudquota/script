import streamlit as st
import streamlit.components.v1 as components
import boto3
import time
import json
import os
import re
import hmac
from botocore.exceptions import ClientError

# =========================================================
# 0) 页面设置（必须全局只调用一次，并且尽量靠前）
# =========================================================
st.set_page_config(page_title="AWS Lightsail 极速面板 Pro", layout="wide")

# =========================================================
# 1) 面板密码门禁（必须放在任何 AWS 操作前）
# =========================================================

# 按你要求保留“写死”逻辑；同时支持环境变量覆盖（服务器部署更方便）
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "19991126.")


def require_panel_password():
    if not PANEL_PASSWORD:
        st.error("未设置面板密码（PANEL_PASSWORD 为空），拒绝启动。")
        st.stop()

    st.session_state.setdefault("authed", False)
    st.session_state.setdefault("fail_count", 0)
    st.session_state.setdefault("lock_until", 0.0)

    now = time.time()
    if st.session_state["lock_until"] > now:
        left = int(st.session_state["lock_until"] - now)
        st.error(f"密码输错次数过多，已锁定 {left}s")
        st.stop()

    if st.session_state["authed"]:
        return

    st.title("🔒 私有面板")
    st.caption("请输入面板密码后才能进入。")

    pwd = st.text_input("面板密码", type="password")

    c1, c2 = st.columns([1, 1])

    with c1:
        if st.button("进入", use_container_width=True):
            ok = hmac.compare_digest(pwd or "", PANEL_PASSWORD)
            if ok:
                st.session_state["authed"] = True
                st.session_state["fail_count"] = 0
                st.session_state["lock_until"] = 0.0
                st.rerun()
            else:
                st.session_state["fail_count"] += 1
                st.error("密码错误")
                if st.session_state["fail_count"] >= 5:
                    st.session_state["lock_until"] = time.time() + 60  # 锁 60 秒
                st.stop()

    with c2:
        if st.button("清空输入", use_container_width=True):
            st.rerun()

    st.stop()


# =========================================================
# 2) 通过门禁后，才开始加载面板主体
# =========================================================

# --- bundle 配置映射（用于实例卡片显示配置）---
BUNDLE_SPECS = {
    "nano_3_0": {"ram": "512 MB RAM", "vcpu": "2 vCPU", "disk": "20 GB SSD"},
    "micro_3_0": {"ram": "1 GB RAM", "vcpu": "2 vCPU", "disk": "40 GB SSD"},
    "small_3_0": {"ram": "2 GB RAM", "vcpu": "2 vCPU", "disk": "60 GB SSD"},
    "medium_3_0": {"ram": "4 GB RAM", "vcpu": "2 vCPU", "disk": "80 GB SSD"},
}


def safe_key(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]", "_", s or "")


def copy_ip_widget(ip: str, name: str):
    sid = safe_key(name)
    ip_esc = (ip or "").replace('"', "&quot;").replace("'", "&#39;")
    components.html(
        f"""
        <div style="display:flex;align-items:center;gap:10px;margin:6px 0;">
          <input id="ip_{sid}" value="{ip_esc}" readonly
            style="width:170px;padding:6px 8px;border:1px solid #cfcfcf;border-radius:8px;background:#fafafa;" />
          <button id="btn_{sid}"
            style="padding:7px 10px;border:none;border-radius:8px;background:#0d6efd;color:#fff;cursor:pointer;">
            📋 复制 IP
          </button>
          <span id="msg_{sid}" style="font-size:12px;color:#2e7d32;"></span>
        </div>

        <script>
          const btn = document.getElementById("btn_{sid}");
          const msg = document.getElementById("msg_{sid}");
          const ip = "{ip_esc}";

          btn.addEventListener("click", async () => {{
            msg.textContent = "";
            try {{
              await navigator.clipboard.writeText(ip);
              msg.textContent = "已复制";
              setTimeout(() => msg.textContent = "", 1200);
            }} catch (e) {{
              const input = document.getElementById("ip_{sid}");
              input.focus();
              input.select();
              document.execCommand("copy");
              msg.textContent = "已复制";
              setTimeout(() => msg.textContent = "", 1200);
            }}
          }});
        </script>
        """,
        height=60,
    )


# --- 本地配置存储（按你要求：aws_config 不动，仍然明文保存）---
CONFIG_FILE = ".aws_config"


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
        except:
            pass
    return {"key": "", "secret": "", "region": "ap-northeast-1"}


def save_config(key, secret, reg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"key": key, "secret": secret, "region": reg}, f, ensure_ascii=False)


def _format_client_error(e: ClientError) -> str:
    code = e.response.get("Error", {}).get("Code", "Unknown")
    msg = e.response.get("Error", {}).get("Message", str(e))
    return f"{code}: {msg}"


# --- boto3 client 缓存（性能优化：避免每次 rerun 都新建 client）---
@st.cache_resource
def _cached_boto3_client(service_name: str, region: str, access_key: str, secret_key: str):
    return boto3.client(
        service_name,
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )


def get_lightsail_client():
    ak = st.session_state.get("aws_access_key")
    sk = st.session_state.get("aws_secret_key")
    rg = st.session_state.get("aws_region")
    if not ak or not sk:
        return None
    return _cached_boto3_client("lightsail", rg, ak, sk)


def get_service_quotas_client():
    ak = st.session_state.get("aws_access_key")
    sk = st.session_state.get("aws_secret_key")
    rg = st.session_state.get("aws_region")
    if not ak or not sk:
        return None
    return _cached_boto3_client("service-quotas", rg, ak, sk)


# --- 工具函数：重试/等待/强制释放静态IP ---
def is_not_found_error(e: ClientError) -> bool:
    code = e.response.get("Error", {}).get("Code", "")
    return code in ("NotFoundException", "ResourceNotFoundException")


def safe_retry(fn, *, retries=8, base_sleep=1.5, status=None, action_name="操作"):
    last_e = None
    for i in range(retries):
        try:
            return fn()
        except ClientError as e:
            last_e = e
            wait = base_sleep * (i + 1)
            if status:
                status.write(
                    f"⚠️ {action_name} 失败，重试 {i+1}/{retries}，等待 {wait:.1f}s ...\n"
                    f"   错误: {_format_client_error(e)}"
                )
            time.sleep(wait)
    raise last_e


def wait_static_ip_detached(client, static_ip_name, *, timeout_sec=90, status=None):
    start = time.time()
    while True:
        try:
            info = client.get_static_ip(staticIpName=static_ip_name)
            attached = info["staticIp"].get("isAttached", False)
            if not attached:
                return True
        except ClientError as e:
            if is_not_found_error(e):
                return True

        if time.time() - start > timeout_sec:
            return False

        if status:
            status.write("⏳ 等待 AWS 同步解绑状态...")
        time.sleep(2)


def force_detach_and_release_static_ip(client, static_ip_name, status=None):
    if status:
        status.write(f"⛓️ 解绑旧静态IP: {static_ip_name} ...")

    safe_retry(
        lambda: client.detach_static_ip(staticIpName=static_ip_name),
        retries=6,
        base_sleep=1.2,
        status=status,
        action_name="解绑静态IP",
    )

    ok = wait_static_ip_detached(client, static_ip_name, timeout_sec=90, status=status)
    if not ok and status:
        status.write("⚠️ 解绑等待超时，继续尝试释放（AWS 有时延迟更新）...")

    if status:
        status.write(f"🗑️ 释放(删除)旧静态IP: {static_ip_name} ...")

    safe_retry(
        lambda: client.release_static_ip(staticIpName=static_ip_name),
        retries=10,
        base_sleep=1.5,
        status=status,
        action_name="释放静态IP",
    )

    if status:
        status.write("🔍 校验旧静态IP是否已彻底删除...")

    start = time.time()
    while True:
        try:
            client.get_static_ip(staticIpName=static_ip_name)
            if time.time() - start > 60:
                raise RuntimeError(f"旧静态IP仍存在（超时未删除）：{static_ip_name}")
            time.sleep(2)
        except ClientError as e:
            if is_not_found_error(e):
                if status:
                    status.write("✅ 旧静态IP已确认删除")
                return True


def find_attached_static_ip_name(client, instance_name):
    s_ips = client.get_static_ips().get("staticIps", [])
    for si in s_ips:
        if si.get("attachedTo") == instance_name:
            return si.get("name"), si.get("ipAddress")
    return None, None


# --- 配额检测（自动搜索 On-demand/Spot vCPU 配额）---
def _pick_quota_value(service_quotas, keywords):
    hits = []
    for q in service_quotas:
        name = (q.get("QuotaName") or "").lower()
        if all(k.lower() in name for k in keywords):
            hits.append(q)
    if not hits:
        return None, None
    hits.sort(key=lambda x: len(x.get("QuotaName", "")), reverse=True)
    return hits[0].get("QuotaName"), hits[0].get("Value")


def test_vcpu_quotas(service_quotas_client):
    paginator = service_quotas_client.get_paginator("list_service_quotas")
    all_q = []
    for page in paginator.paginate(ServiceCode="ec2"):
        all_q.extend(page.get("Quotas", []))

    on_name, on_val = _pick_quota_value(all_q, ["running", "on-demand", "standard", "vcpu"])
    spot_name, spot_val = _pick_quota_value(all_q, ["running", "spot", "standard", "vcpu"])

    if on_val is None:
        on_name, on_val = _pick_quota_value(all_q, ["running", "on-demand", "standard"])
    if spot_val is None:
        spot_name, spot_val = _pick_quota_value(all_q, ["running", "spot", "standard"])

    return on_val, spot_val, {"on_name": on_name, "spot_name": spot_name}


# =========================================================
# 3) UI 渲染：侧边栏 / Tabs
# =========================================================

region_options = {
    "ap-northeast-1": "🇯🇵 东京 (Tokyo)",
    "ap-northeast-2": "🇰🇷 首尔 (Seoul)",
    "ap-southeast-1": "🇸🇬 新加坡 (Singapore)",
    "ap-southeast-2": "🇦🇺 悉尼 (Sydney)",
    "ap-south-1": "🇮🇳 孟买 (Mumbai)",
    "us-east-1": "🇺🇸 弗吉尼亚 (N. Virginia)",
    "us-east-2": "🇺🇸 俄亥俄 (Ohio)",
    "us-west-2": "🇺🇸 俄勒冈 (Oregon)",
    "ca-central-1": "🇨🇦 加拿大 (Central)",
    "eu-central-1": "🇩🇪 法兰克福 (Frankfurt)",
    "eu-west-1": "🇮🇪 爱尔兰 (Ireland)",
    "eu-west-2": "🇬🇧 伦敦 (London)",
    "eu-west-3": "🇫🇷 巴黎 (Paris)",
    "eu-north-1": "🇸🇪 斯德哥尔摩 (Stockholm)",
}


def init_session_from_config():
    saved_data = load_config()

    st.session_state.setdefault("aws_access_key", saved_data.get("key", ""))
    st.session_state.setdefault("aws_secret_key", saved_data.get("secret", ""))
    st.session_state.setdefault("aws_region", saved_data.get("region", "ap-northeast-1"))

    # 优化：默认实例名固定在一个会话里，避免每次 rerun 都变化
    st.session_state.setdefault("default_instance_name", f"vps-{int(time.time())}")


def render_sidebar_credentials():
    with st.sidebar:
        if st.button("🚪 退出面板", use_container_width=True):
            st.session_state["authed"] = False
            st.rerun()

        st.header("🔐 AWS 授权设置")

        with st.form("credentials_form"):
            st.write("填写后点保存（此处为 AWS 授权信息）")

            input_key = st.text_input(
                "Access Key ID",
                value=st.session_state.get("aws_access_key", ""),
                autocomplete="username",
            )
            input_secret = st.text_input(
                "Secret Access Key",
                value=st.session_state.get("aws_secret_key", ""),
                type="password",
                autocomplete="current-password",
            )

            region_keys = list(region_options.keys())
            current_region = st.session_state.get("aws_region", "ap-northeast-1")
            default_index = region_keys.index(current_region) if current_region in region_options else 0

            selected_region = st.selectbox(
                "选择地区",
                options=region_keys,
                format_func=lambda x: region_options[x],
                index=default_index,
            )

            submit_btn = st.form_submit_button("✅ 保存并连接")

            if submit_btn:
                st.session_state["aws_access_key"] = (input_key or "").strip()
                st.session_state["aws_secret_key"] = (input_secret or "").strip()
                st.session_state["aws_region"] = selected_region

                save_config(
                    st.session_state["aws_access_key"],
                    st.session_state["aws_secret_key"],
                    st.session_state["aws_region"],
                )

                # 关键：Key/Region 变化时，缓存的 boto3 client 需要失效
                st.cache_resource.clear()

                st.success("配置已保存到本地！")
                time.sleep(0.2)
                st.rerun()


def render_create_tab(lightsail):
    st.header("创建新服务器")
    col1, col2 = st.columns(2)

    with col1:
        instance_name = st.text_input("实例名称", value=st.session_state.get("default_instance_name", "vps-1"))

        blueprints = [
            {"id": "ubuntu_24_04", "name": "Ubuntu 24.04 LTS"},
            {"id": "ubuntu_22_04", "name": "Ubuntu 22.04 LTS"},
            {"id": "debian_12", "name": "Debian 12"},
            {"id": "debian_11", "name": "Debian 11"},
            {"id": "centos_7", "name": "CentOS 7"},
        ]
        selected_os = st.selectbox("选择系统", blueprints, format_func=lambda x: x["name"])

        bundles = [
            {"id": "nano_3_0", "name": "$5 / 月｜512MB 内存｜2 vCPU｜20GB SSD｜1TB 流量"},
            {"id": "micro_3_0", "name": "$7 / 月｜1GB 内存｜2 vCPU｜40GB SSD｜2TB 流量"},
            {"id": "small_3_0", "name": "$12 / 月｜2GB 内存｜2 vCPU｜60GB SSD｜3TB 流量"},
            {"id": "medium_3_0", "name": "$24 / 月｜4GB 内存｜2 vCPU｜80GB SSD｜4TB 流量"},
        ]
        selected_plan = st.selectbox("选择套餐", bundles, format_func=lambda x: x["name"])

    with col2:
        st.info("🔑 设置开机 Root 密码")
        root_pwd = st.text_input("Root 密码", type="password")
        enable_fw = st.checkbox("自动开启防火墙全端口 (0-65535)", value=True)

    if st.button("🚀 立即创建并启动"):
        if not root_pwd:
            st.error("请设置 Root 密码！")
        else:
            user_data = f"""#!/bin/bash
set -e
echo "root:{root_pwd}" | chpasswd
sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || true
sed -i 's/^PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config || true
sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
sed -i 's/^PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config || true
systemctl restart ssh || service ssh restart || true
systemctl restart sshd || service sshd restart || true
"""
            try:
                with st.spinner("AWS 正在拉取资源..."):
                    lightsail.create_instances(
                        instanceNames=[instance_name],
                        availabilityZone=f"{st.session_state['aws_region']}a",
                        blueprintId=selected_os["id"],
                        bundleId=selected_plan["id"],
                        userData=user_data,
                    )
                    if enable_fw:
                        time.sleep(4)
                        lightsail.open_instance_public_ports(
                            instanceName=instance_name,
                            portInfo={"fromPort": 0, "toPort": 65535, "protocol": "all"},
                        )
                st.success(f"✅ {instance_name} 创建成功！")
                time.sleep(0.8)
                st.rerun()
            except ClientError as e:
                st.error(f"失败: {_format_client_error(e)}")
            except Exception as e:
                st.error(f"失败: {str(e)}")


def render_manage_tab(lightsail):
    if st.button("🔄 刷新列表"):
        st.rerun()

    try:
        inst_resp = lightsail.get_instances()
        instances = inst_resp.get("instances", [])

        if not instances:
            st.info("该地区暂无实例。")
            return

        for inst in instances:
            name = inst.get("name", "unknown")
            status = inst.get("state", {}).get("name", "unknown")
            ip = inst.get("publicIpAddress", "分配中...")
            bundle_id = inst.get("bundleId", "")

            spec = BUNDLE_SPECS.get(bundle_id, {})
            ram = spec.get("ram", "未知 RAM")
            vcpu = spec.get("vcpu", "未知 CPU")
            disk = spec.get("disk", "未知 磁盘")

            title = f"🖥️ {name} | {ram} · {vcpu} · {disk} | 状态: {status} | IP: {ip}"

            with st.expander(title, expanded=False):
                if ip and ip != "分配中...":
                    copy_ip_widget(ip, name)
                else:
                    st.caption("公网 IP 仍在分配中...")

                st.caption(f"bundleId：{bundle_id or 'unknown'}")

                c1, c2, c3, c4 = st.columns(4)

                if c1.button("🗑️ 删除", key=f"del_{safe_key(name)}"):
                    try:
                        lightsail.delete_instance(instanceName=name)
                        st.rerun()
                    except ClientError as e:
                        st.error(_format_client_error(e))

                if c2.button("🔄 重启", key=f"reb_{safe_key(name)}"):
                    try:
                        lightsail.reboot_instance(instanceName=name)
                        st.toast("重启中...")
                    except ClientError as e:
                        st.error(_format_client_error(e))

                if c3.button("🛡️ 防火墙全开", key=f"fw_{safe_key(name)}"):
                    try:
                        lightsail.open_instance_public_ports(
                            instanceName=name,
                            portInfo={"fromPort": 0, "toPort": 65535, "protocol": "all"},
                        )
                        st.success("端口全开放")
                    except ClientError as e:
                        st.error(_format_client_error(e))

                if c4.button("♻️ 换IP (深度洗)", key=f"ip_{safe_key(name)}"):
                    with st.status("🚀 正在执行换IP流程...", expanded=True) as s:
                        try:
                            s.write("🔍 检查该实例已绑定的静态IP...")
                            old_static_name, old_ip = find_attached_static_ip_name(lightsail, name)

                            if old_static_name:
                                s.write(f"📌 发现旧静态IP：{old_ip}（名称：{old_static_name}）")
                                force_detach_and_release_static_ip(lightsail, old_static_name, status=s)
                            else:
                                s.write("✅ 未发现绑定的旧静态IP（可能之前用的是动态IP或已解绑）")

                            s.write("🆕 申请新静态IP...")
                            new_static_name = f"IP-{safe_key(name)}-{int(time.time())}"

                            safe_retry(
                                lambda: lightsail.allocate_static_ip(staticIpName=new_static_name),
                                retries=8,
                                base_sleep=1.2,
                                status=s,
                                action_name="申请静态IP",
                            )
                            time.sleep(2)

                            new_ip = lightsail.get_static_ip(staticIpName=new_static_name)["staticIp"]["ipAddress"]
                            s.write(f"✅ 新静态IP获取成功：{new_ip}")

                            s.write(f"🔗 绑定新静态IP到实例：{new_ip} ...")
                            safe_retry(
                                lambda: lightsail.attach_static_ip(staticIpName=new_static_name, instanceName=name),
                                retries=8,
                                base_sleep=1.2,
                                status=s,
                                action_name="绑定静态IP",
                            )

                            s.update(label=f"✨ 换IP成功: {new_ip}", state="complete")
                            time.sleep(0.8)
                            st.rerun()

                        except ClientError as e:
                            s.update(label="❌ 换IP失败", state="error")
                            st.error(f"换IP失败: {_format_client_error(e)}")
                        except Exception as e:
                            s.update(label="❌ 换IP失败", state="error")
                            st.error(f"换IP失败: {str(e)}")

    except ClientError as e:
        st.error(f"连接失败: {_format_client_error(e)}")
    except Exception as e:
        st.error(f"连接失败: {str(e)}")


def render_quota_tab(sq):
    st.header("测试配额")
    st.caption("用于判断当前区域 EC2 vCPU 配额（On-demand / Spot），常见会显示 8 或 16。")

    st.write(
        f"📍 当前区域：**{st.session_state['aws_region']}**  {region_options.get(st.session_state['aws_region'], '')}"
    )

    if not sq:
        st.warning("请先在左侧保存 AWS Key 后再测试。")
        return

    if st.button("✅ 测试", key="quota_test_btn"):
        with st.spinner("正在拉取配额信息..."):
            try:
                on_v, spot_v, names = test_vcpu_quotas(sq)

                if on_v is None and spot_v is None:
                    st.error("没找到对应的配额项（可能账号没有权限访问 Service Quotas，或 AWS 文案变化）。")
                    st.info("IAM 需要：servicequotas:ListServiceQuotas, servicequotas:GetServiceQuota")
                else:
                    on_show = "N/A" if on_v is None else int(on_v) if float(on_v).is_integer() else on_v
                    spot_show = "N/A" if spot_v is None else int(spot_v) if float(spot_v).is_integer() else spot_v

                    st.success(f"On-demand 配额: {on_show}    Spot 配额: {spot_show}")

                    with st.expander("查看匹配到的配额项名称（调试用）"):
                        st.write("On-demand:", names.get("on_name"))
                        st.write("Spot:", names.get("spot_name"))

            except ClientError as e:
                st.error(f"测试失败: {_format_client_error(e)}")
            except Exception as e:
                st.error(f"测试失败: {str(e)}")


# =========================================================
# 4) 主逻辑入口
# =========================================================

def main():
    require_panel_password()

    init_session_from_config()

    render_sidebar_credentials()

    st.title("🚀 AWS Lightsail 轻量管理面板")

    lightsail = get_lightsail_client()
    sq = get_service_quotas_client()

    if not lightsail:
        st.warning("👈 请先在左侧输入 AWS Key 并点击保存。")
        return

    tab1, tab2, tab3 = st.tabs(["✨ 创建实例", "🔧 实例管理 & 换IP", "🧪 测试配额"])

    with tab1:
        render_create_tab(lightsail)

    with tab2:
        render_manage_tab(lightsail)

    with tab3:
        render_quota_tab(sq)


if __name__ == "__main__":
    main()
