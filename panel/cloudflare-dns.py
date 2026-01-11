import streamlit as st
import requests
from typing import Dict, Any, Optional, Tuple, List

st.set_page_config(page_title="Cloudflare DNS 面板", layout="wide")

CF_API_BASE = "https://api.cloudflare.com/client/v4"

DNS_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SRV", "CAA"]
TTL_OPTIONS = [1, 60, 120, 300, 600, 1800, 3600, 7200, 86400]


def cf_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token.strip()}",
        "Content-Type": "application/json",
    }


def extract_error(data: Any) -> str:
    if isinstance(data, dict) and data.get("errors"):
        return "；".join(f"[{e.get('code')}] {e.get('message')}" for e in data["errors"])
    return str(data.get("message", "未知错误")) if isinstance(data, dict) else "未知错误"


def cf_request(
    method: str,
    path: str,
    token: str,
    params: Optional[Dict[str, Any]] = None,
    json: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Dict[str, Any], str]:
    try:
        r = requests.request(
            method,
            CF_API_BASE + path,
            headers=cf_headers(token),
            params=params,
            json=json,
            timeout=20,
        )
        data = r.json()
    except Exception as e:
        return False, {}, f"请求失败：{e}"

    if not r.ok or data.get("success") is False:
        return False, data, extract_error(data)

    return True, data, ""


def get_zones(token: str) -> List[Dict[str, Any]]:
    zones = []
    page = 1
    while True:
        ok, data, err = cf_request("GET", "/zones", token, params={"page": page, "per_page": 50})
        if not ok:
            raise RuntimeError(err)
        zones.extend(data.get("result", []))
        if page >= data.get("result_info", {}).get("total_pages", 1):
            break
        page += 1
    return zones


def list_dns(token: str, zone_id: str):
    ok, data, err = cf_request(
        "GET",
        f"/zones/{zone_id}/dns_records",
        token,
        params={"page": 1, "per_page": 50},
    )
    if not ok:
        raise RuntimeError(err)
    return data.get("result", [])


def create_dns(token: str, zone_id: str, payload: Dict[str, Any]):
    ok, _, err = cf_request("POST", f"/zones/{zone_id}/dns_records", token, json=payload)
    if not ok:
        raise RuntimeError(err)


def update_dns(token: str, zone_id: str, record_id: str, payload: Dict[str, Any]):
    ok, _, err = cf_request("PUT", f"/zones/{zone_id}/dns_records/{record_id}", token, json=payload)
    if not ok:
        raise RuntimeError(err)


def delete_dns(token: str, zone_id: str, record_id: str):
    ok, _, err = cf_request("DELETE", f"/zones/{zone_id}/dns_records/{record_id}", token)
    if not ok:
        raise RuntimeError(err)


def ttl_label(v: int) -> str:
    return "自动" if v == 1 else f"{v} 秒"


# ================= UI =================

st.title("☁️ Cloudflare DNS 面板")

with st.sidebar:
    st.header("🔐 认证")
    token_input = st.text_input("Cloudflare API Token", type="password")

    if st.button("使用 Token", use_container_width=True):
        if token_input.strip():
            st.session_state["cf_token"] = token_input.strip()
            st.success("Token 已加载")

    if st.button("忘记 Token", use_container_width=True):
        st.session_state.clear()
        st.success("已清除")

token = st.session_state.get("cf_token")
if not token:
    st.stop()

if "zones" not in st.session_state:
    st.session_state["zones"] = get_zones(token)

zones = st.session_state["zones"]
zone_map = {z["name"]: z["id"] for z in zones}

zone_name = st.sidebar.selectbox("选择域名", sorted(zone_map.keys()))
zone_id = zone_map[zone_name]

tab1, tab2 = st.tabs(["📄 DNS 记录管理", "➕ 新增 DNS"])

# ================= DNS 列表 =================
with tab1:
    st.subheader(f"DNS 记录管理 - {zone_name}")

    if st.button("🔄 刷新列表"):
        st.rerun()

    records = list_dns(token, zone_id)

    if not records:
        st.info("暂无 DNS 记录")
        st.stop()

    for r in records:
        rid = r["id"]
        status = "🟠 代理" if r.get("proxied") else "⚪ 仅 DNS"

        with st.expander(f"{status} | {r['type']} {r['name']} → {r['content']}"):
            name = st.text_input("Name", r["name"], key=f"name_{rid}")
            content = st.text_input("Content", r["content"], key=f"content_{rid}")
            ttl = st.selectbox(
                "TTL",
                TTL_OPTIONS,
                format_func=ttl_label,
                index=TTL_OPTIONS.index(r["ttl"]) if r["ttl"] in TTL_OPTIONS else 0,
                key=f"ttl_{rid}",
            )
            proxied = st.checkbox("开启 Cloudflare 代理", r.get("proxied", False), key=f"px_{rid}")

            c1, c2 = st.columns(2)

            with c1:
                if st.button("保存修改", key=f"save_{rid}", use_container_width=True):
                    update_dns(
                        token,
                        zone_id,
                        rid,
                        {
                            "type": r["type"],
                            "name": name.strip(),
                            "content": content.strip(),
                            "ttl": ttl,
                            "proxied": proxied,
                        },
                    )
                    st.success("已保存")
                    st.rerun()

            with c2:
                confirm = st.checkbox("确认删除", key=f"confirm_{rid}")
                if st.button("删除", key=f"del_{rid}", disabled=not confirm, use_container_width=True):
                    delete_dns(token, zone_id, rid)
                    st.success("已删除")
                    st.rerun()

# ================= 新增 =================
with tab2:
    rtype = st.selectbox("记录类型", DNS_TYPES)
    name = st.text_input("Name")
    content = st.text_input("Content")
    ttl = st.selectbox("TTL", TTL_OPTIONS, format_func=ttl_label)
    proxied = st.checkbox("开启 Cloudflare 代理")

    if st.button("创建记录"):
        create_dns(
            token,
            zone_id,
            {
                "type": rtype,
                "name": name.strip(),
                "content": content.strip(),
                "ttl": ttl,
                "proxied": proxied,
            },
        )
        st.success("创建成功")
