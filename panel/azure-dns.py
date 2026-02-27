import os
import json
import time
import re
from dataclasses import dataclass
from typing import Dict, Any, Optional, Tuple, List

import streamlit as st

from azure.identity import ClientSecretCredential
from azure.mgmt.dns import DnsManagementClient
from azure.mgmt.dns.models import (
    RecordSet,
    ARecord,
    AaaaRecord,
    CnameRecord,
    TxtRecord,
)
from azure.mgmt.resource import ResourceManagementClient


# ----------------------------
# 兼容所有 Streamlit 版本的 rerun
# ----------------------------
def do_rerun():
    """
    兼容所有 Streamlit 版本的安全刷新方案：
    - 新版：st.rerun()
    - 老版：st.experimental_rerun()
    - 更老：通过 session_state 触发下一次脚本重新执行
    """
    try:
        if hasattr(st, "rerun"):
            st.rerun()
            return
        if hasattr(st, "experimental_rerun"):
            st.experimental_rerun()
            return
    except Exception:
        pass
    st.session_state["_force_rerun"] = time.time()


# ----------------------------
# 基础配置
# ----------------------------
APP_TITLE = "Azure DNS 管理面板 (Streamlit)"
PANEL_PASSWORD = os.getenv("DNS_PANEL_PASSWORD", "19991126")

STORE_DIR = os.path.expanduser("~/.azure_dns_panel")
CREDS_FILE = os.path.join(STORE_DIR, "creds.enc")  # 加密存储
CACHE_TTL_SECONDS = 20

KEY_FILE = os.path.join(STORE_DIR, "key.bin")
ENV_KEY = os.getenv("DNS_PANEL_KEY", "")

# TTL 默认 1 秒（你要求）
DEFAULT_TTL = int(os.getenv("DNS_DEFAULT_TTL", "1"))


# ----------------------------
# 小工具：文件权限/加密存储
# ----------------------------
def _ensure_store_dir():
    os.makedirs(STORE_DIR, exist_ok=True)
    try:
        os.chmod(STORE_DIR, 0o700)
    except Exception:
        pass


def _load_fernet():
    try:
        from cryptography.fernet import Fernet  # type: ignore
    except Exception:
        return None, "未安装 cryptography，Azure 凭据将无法加密（将退回明文存储，不建议）。"

    _ensure_store_dir()

    if ENV_KEY:
        key = ENV_KEY.encode("utf-8")
        try:
            return Fernet(key), None
        except Exception:
            return None, "环境变量 DNS_PANEL_KEY 无效（必须是 Fernet key）。"

    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "rb") as f:
                key = f.read().strip()
            return Fernet(key), None
        except Exception:
            return None, "读取本地 key.bin 失败。"

    try:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        try:
            os.chmod(KEY_FILE, 0o600)
        except Exception:
            pass
        return Fernet(key), None
    except Exception:
        return None, "生成/保存加密 key 失败。"


def save_creds(creds: Dict[str, str]) -> Tuple[bool, str]:
    _ensure_store_dir()
    data = json.dumps(creds, ensure_ascii=False).encode("utf-8")

    fernet, warn = _load_fernet()
    if fernet is None:
        plain_path = os.path.join(STORE_DIR, "creds.json")
        try:
            with open(plain_path, "wb") as f:
                f.write(data)
            try:
                os.chmod(plain_path, 0o600)
            except Exception:
                pass
            return True, f"已保存（明文）到 {plain_path}。建议安装 cryptography 并启用加密。"
        except Exception as e:
            return False, f"保存失败：{e}"

    try:
        token = fernet.encrypt(data)
        with open(CREDS_FILE, "wb") as f:
            f.write(token)
        try:
            os.chmod(CREDS_FILE, 0o600)
        except Exception:
            pass
        msg = f"已加密保存到 {CREDS_FILE}。"
        if warn:
            msg += f"（注意：{warn}）"
        return True, msg
    except Exception as e:
        return False, f"加密保存失败：{e}"


def load_creds() -> Tuple[Optional[Dict[str, str]], str]:
    _ensure_store_dir()

    if os.path.exists(CREDS_FILE):
        fernet, warn = _load_fernet()
        if fernet is None:
            return None, f"发现加密凭据文件但无法解密：{warn or '未知原因'}"
        try:
            with open(CREDS_FILE, "rb") as f:
                token = f.read()
            data = fernet.decrypt(token)
            obj = json.loads(data.decode("utf-8"))
            return obj, "已从加密文件加载凭据。"
        except Exception as e:
            return None, f"解密/解析失败：{e}"

    plain_path = os.path.join(STORE_DIR, "creds.json")
    if os.path.exists(plain_path):
        try:
            with open(plain_path, "rb") as f:
                obj = json.loads(f.read().decode("utf-8"))
            return obj, f"已从明文文件加载凭据：{plain_path}（不推荐，建议改为加密存储）。"
        except Exception as e:
            return None, f"读取明文凭据失败：{e}"

    return None, "未发现已保存的 Azure 凭据。"


def clear_creds() -> Tuple[bool, str]:
    ok = True
    msgs = []
    for p in [CREDS_FILE, os.path.join(STORE_DIR, "creds.json")]:
        if os.path.exists(p):
            try:
                os.remove(p)
                msgs.append(f"已删除 {p}")
            except Exception as e:
                ok = False
                msgs.append(f"删除失败 {p}: {e}")
    return ok, "；".join(msgs) if msgs else "没有可删除的凭据文件。"


# ----------------------------
# Azure 客户端
# ----------------------------
@dataclass
class AzureClients:
    dns: DnsManagementClient
    rg: ResourceManagementClient


def make_clients(tenant_id: str, client_id: str, client_secret: str, subscription_id: str) -> AzureClients:
    cred = ClientSecretCredential(
        tenant_id=tenant_id.strip(),
        client_id=client_id.strip(),
        client_secret=client_secret.strip(),
    )
    dns_client = DnsManagementClient(cred, subscription_id.strip())
    rg_client = ResourceManagementClient(cred, subscription_id.strip())
    return AzureClients(dns=dns_client, rg=rg_client)


def parse_rg_from_id(resource_id: str) -> Optional[str]:
    m = re.search(r"/resourceGroups/([^/]+)/", resource_id, re.IGNORECASE)
    return m.group(1) if m else None


def normalize_record_name(relative: str) -> str:
    s = (relative or "@").strip()
    if s == "":
        s = "@"
    if s.endswith("."):
        s = s[:-1]
    return s


def safe_call(fn, *args, **kwargs):
    try:
        return True, fn(*args, **kwargs), ""
    except Exception as e:
        return False, None, str(e)


def record_type_from_full(rtype_full: str) -> str:
    return (rtype_full or "").split("/")[-1]


def record_values_to_lines(rec: RecordSet) -> List[str]:
    lines: List[str] = []
    if getattr(rec, "a_records", None):
        lines = [x.ipv4_address for x in rec.a_records if x and x.ipv4_address]
    elif getattr(rec, "aaaa_records", None):
        lines = [x.ipv6_address for x in rec.aaaa_records if x and x.ipv6_address]
    elif getattr(rec, "cname_record", None) and rec.cname_record:
        if rec.cname_record.cname:
            lines = [rec.cname_record.cname]
    elif getattr(rec, "txt_records", None):
        for tr in rec.txt_records or []:
            v = " ".join(tr.value or [])
            if v.strip():
                lines.append(v.strip())
    return lines


def apply_values_to_recordset(base: RecordSet, rtype: str, ttl: int, lines: List[str]) -> RecordSet:
    base.ttl = int(ttl)
    if rtype == "A":
        base.a_records = [ARecord(ipv4_address=x) for x in lines]
    elif rtype == "AAAA":
        base.aaaa_records = [AaaaRecord(ipv6_address=x) for x in lines]
    elif rtype == "CNAME":
        base.cname_record = CnameRecord(cname=lines[0] if lines else "")
    elif rtype == "TXT":
        base.txt_records = [TxtRecord(value=[x]) for x in lines]
    else:
        raise ValueError(f"不支持的类型：{rtype}")
    return base


def build_new_recordset(rtype: str, ttl: int, lines: List[str]) -> RecordSet:
    rs = RecordSet(ttl=int(ttl))
    if rtype == "A":
        rs.a_records = [ARecord(ipv4_address=x) for x in lines]
    elif rtype == "AAAA":
        rs.aaaa_records = [AaaaRecord(ipv6_address=x) for x in lines]
    elif rtype == "CNAME":
        rs.cname_record = CnameRecord(cname=lines[0] if lines else "")
    elif rtype == "TXT":
        rs.txt_records = [TxtRecord(value=[x]) for x in lines]
    else:
        raise ValueError(f"不支持的类型：{rtype}")
    return rs


# ----------------------------
# Streamlit 页面
# ----------------------------
st.set_page_config(page_title=APP_TITLE, layout="wide")
st.title(APP_TITLE)

# 用于最老版本触发 rerun 的 dummy state
_ = st.session_state.get("_force_rerun", 0)

if "authed" not in st.session_state:
    st.session_state.authed = False
if "clients" not in st.session_state:
    st.session_state.clients = None
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = 0.0
if "zones_cache" not in st.session_state:
    st.session_state.zones_cache = []
if "selected_zone" not in st.session_state:
    st.session_state.selected_zone = None


# ----------------------------
# 侧边栏：登录（修复：不需要点两次）
# ----------------------------
with st.sidebar:
    st.header("访问控制")

    if not st.session_state.authed:
        with st.form("login_form", clear_on_submit=False):
            pw = st.text_input("面板访问密码", type="password")
            submitted = st.form_submit_button("登录", use_container_width=True)

        if submitted:
            if pw == PANEL_PASSWORD:
                st.session_state.authed = True
                st.success("登录成功")
                do_rerun()
            else:
                st.error("密码错误")

        st.stop()
    else:
        st.success("已登录")
        if st.button("退出登录", use_container_width=True):
            st.session_state.authed = False
            st.session_state.clients = None
            st.session_state.selected_zone = None
            do_rerun()

    st.divider()
    st.header("Azure 凭据")
    saved, msg = load_creds()
    st.caption(msg)

    if st.button("清除已保存凭据", use_container_width=True):
        ok, m = clear_creds()
        (st.success if ok else st.error)(m)
        st.session_state.clients = None
        do_rerun()


# ----------------------------
# 主区域：凭据连接
# ----------------------------
colA, colB = st.columns([1, 2], vertical_alignment="top")

with colA:
    st.subheader("① 连接 Azure")

    with st.form("azure_creds_form", clear_on_submit=False):
        default = saved or {}
        tenant_id = st.text_input("Tenant ID", value=default.get("tenant_id", ""))
        client_id = st.text_input("Client ID", value=default.get("client_id", ""))
        client_secret = st.text_input("Client Secret", value=default.get("client_secret", ""), type="password")
        subscription_id = st.text_input("Subscription ID", value=default.get("subscription_id", ""))

        save_on_server = st.checkbox("保存凭据到服务器（推荐加密）", value=True)
        connect = st.form_submit_button("连接 / 刷新连接", use_container_width=True)

    if connect:
        if not all([tenant_id.strip(), client_id.strip(), client_secret.strip(), subscription_id.strip()]):
            st.error("四项必填：Tenant / Client / Secret / Subscription")
        else:
            with st.spinner("正在连接 Azure..."):
                ok, clients, err = safe_call(make_clients, tenant_id, client_id, client_secret, subscription_id)
                if not ok:
                    if "AADSTS700016" in err:
                        st.error(
                            "连接失败：AADSTS700016（Tenant 不匹配/默认目录找不到该应用）\n\n"
                            "请确认：订阅所属 Tenant 与你填的 Tenant ID 一致；并且该 Tenant 中存在该 Client ID。"
                        )
                    else:
                        st.error(f"连接失败：{err}")
                else:
                    st.session_state.clients = clients
                    st.session_state.last_refresh = 0.0
                    st.success("连接成功")
                    if save_on_server:
                        ok2, m2 = save_creds(
                            {
                                "tenant_id": tenant_id.strip(),
                                "client_id": client_id.strip(),
                                "client_secret": client_secret.strip(),
                                "subscription_id": subscription_id.strip(),
                            }
                        )
                        (st.success if ok2 else st.error)(m2)
                    do_rerun()

    st.divider()
    st.subheader("② 选择 DNS Zone")

    if st.session_state.clients is None:
        st.info("请先在上面填写凭据并连接。")
    else:
        now = time.time()
        if (now - st.session_state.last_refresh) > CACHE_TTL_SECONDS:
            with st.spinner("加载 DNS Zones..."):
                ok, zones_iter, err = safe_call(st.session_state.clients.dns.zones.list)
                if ok:
                    zones_list = []
                    for z in zones_iter:
                        rg = parse_rg_from_id(z.id or "")
                        zones_list.append({"name": z.name, "resource_group": rg or "", "id": z.id or "", "type": z.type or ""})
                    zones_list.sort(key=lambda x: (x["resource_group"], x["name"]))
                    st.session_state.zones_cache = zones_list
                    st.session_state.last_refresh = now
                else:
                    st.error(f"加载 Zone 失败：{err}")

        zones = st.session_state.zones_cache
        if not zones:
            st.warning("未找到任何 DNS Zone（确认订阅内有 Public DNS Zone，并且服务主体有权限）。")
        else:
            zone_labels = [f'{z["name"]}   (RG: {z["resource_group"]})' for z in zones]
            sel = st.selectbox("DNS Zone", options=list(range(len(zones))), format_func=lambda i: zone_labels[i])
            st.session_state.selected_zone = zones[sel]

            if st.button("刷新 Zone 列表", use_container_width=True):
                st.session_state.last_refresh = 0.0
                do_rerun()

with colB:
    st.subheader("③ DNS 记录管理（列表可改/删）")

    if st.session_state.clients is None:
        st.info("请先连接 Azure。")
        st.stop()

    zone = st.session_state.selected_zone
    if not zone:
        st.info("请先选择一个 DNS Zone。")
        st.stop()

    rg_name = zone["resource_group"]
    zone_name = zone["name"]

    if not rg_name:
        st.error("无法从 Zone ID 解析 Resource Group。请确认该 Zone 的资源 ID 正常。")
        st.stop()

    st.caption(f"当前 Zone：**{zone_name}** ｜ Resource Group：**{rg_name}**")

    tabs = st.tabs(["记录列表（可编辑）", "新增记录", "排错/说明"])

    # ----------------------------
    # 记录列表（可编辑）
    # ----------------------------
    with tabs[0]:
        c1, c2, c3 = st.columns([2, 1, 1])
        with c1:
            q = st.text_input("筛选（name/type/value）", value="")
        with c2:
            only_editable = st.checkbox("仅显示 A/AAAA/CNAME/TXT", value=True)
        with c3:
            if st.button("刷新记录列表", use_container_width=True):
                do_rerun()

        with st.spinner("加载记录列表..."):
            ok, rs_iter, err = safe_call(st.session_state.clients.dns.record_sets.list_by_dns_zone, rg_name, zone_name)
        if not ok:
            st.error(f"加载记录失败：{err}")
            st.stop()

        records: List[RecordSet] = list(rs_iter)

        def match_filter(rec: RecordSet) -> bool:
            rtype = record_type_from_full(rec.type or "")
            if only_editable and rtype not in ("A", "AAAA", "CNAME", "TXT"):
                return False
            if not q.strip():
                return True
            needle = q.strip().lower()
            vals = ",".join(record_values_to_lines(rec)).lower()
            return needle in (rec.name or "").lower() or needle in rtype.lower() or needle in vals

        records = [r for r in records if match_filter(r)]
        records.sort(key=lambda r: (record_type_from_full(r.type or ""), r.name or ""))

        st.write(f"共 {len(records)} 条记录（筛选后）")

        for rec in records:
            rtype = record_type_from_full(rec.type or "")
            ttl0 = int(getattr(rec, "ttl", DEFAULT_TTL) or DEFAULT_TTL)
            cur_lines = record_values_to_lines(rec)

            header = f"{rec.name}   [{rtype}]   TTL={ttl0}"
            with st.expander(header, expanded=False):
                st.write("当前值：")
                st.code("\n".join(cur_lines) if cur_lines else "(空)")

                if rtype in ("A", "AAAA", "CNAME", "TXT"):
                    with st.form(f"edit_{rec.name}_{rtype}"):
                        new_ttl = st.number_input(
                            "TTL（秒）",
                            min_value=1,
                            max_value=86400,
                            value=ttl0,
                            step=1,
                            key=f"ttl_{rec.name}_{rtype}",
                        )

                        new_value = st.text_area(
                            "新值（多行=多值；CNAME 只能 1 行；TXT 每行一条）",
                            value="\n".join(cur_lines),
                            height=120,
                            key=f"val_{rec.name}_{rtype}",
                        )

                        mode = st.radio(
                            "写入方式",
                            ["覆盖（推荐）", "追加（仅 A/AAAA/TXT）"],
                            horizontal=True,
                            key=f"mode_{rec.name}_{rtype}",
                        )

                        submit_update = st.form_submit_button("保存修改", use_container_width=True)

                    if submit_update:
                        lines = [x.strip() for x in (new_value or "").splitlines() if x.strip()]

                        if rtype in ("A", "AAAA", "TXT") and mode.startswith("追加"):
                            merged = cur_lines[:] + lines
                            seen = set()
                            lines2 = []
                            for x in merged:
                                if x not in seen:
                                    seen.add(x)
                                    lines2.append(x)
                            lines = lines2

                        if rtype in ("A", "AAAA", "TXT") and not lines:
                            st.error("请至少填写一行记录值。")
                        elif rtype == "CNAME" and len(lines) != 1:
                            st.error("CNAME 只能填写 1 行目标值。")
                        else:
                            okg, base, errg = safe_call(
                                st.session_state.clients.dns.record_sets.get,
                                rg_name,
                                zone_name,
                                rec.name,
                                rtype,
                            )
                            if not okg or base is None:
                                st.error(f"读取旧记录失败：{errg}")
                            else:
                                try:
                                    updated = apply_values_to_recordset(base, rtype, int(new_ttl), lines)
                                except Exception as e:
                                    st.error(f"构造更新数据失败：{e}")
                                    updated = None

                                if updated is not None:
                                    with st.spinner("提交更新..."):
                                        oku, _, erru = safe_call(
                                            st.session_state.clients.dns.record_sets.create_or_update,
                                            rg_name,
                                            zone_name,
                                            rec.name,
                                            rtype,
                                            updated,
                                        )
                                    if oku:
                                        st.success("更新成功 ✅")
                                        # 不强制 rerun，避免表单状态抖动；用户可点“刷新记录列表”
                                    else:
                                        st.error(
                                            "更新失败：\n\n"
                                            f"{erru}\n\n"
                                            "如果 TTL=1 失败，请把 TTL 改成 30/60 再试（某些环境最小 TTL 不是 1）。"
                                        )

                    del_cols = st.columns([1, 2])
                    with del_cols[0]:
                        confirm = st.checkbox("确认删除", key=f"confirm_del_{rec.name}_{rtype}")
                    with del_cols[1]:
                        if st.button(
                            "删除这条记录",
                            type="primary",
                            disabled=not confirm,
                            key=f"del_{rec.name}_{rtype}",
                        ):
                            with st.spinner("删除中..."):
                                okd, _, errd = safe_call(
                                    st.session_state.clients.dns.record_sets.delete,
                                    rg_name,
                                    zone_name,
                                    rec.name,
                                    rtype,
                                )
                            if okd:
                                st.success("删除成功 ✅（正在刷新）")
                                do_rerun()
                            else:
                                st.error(f"删除失败：{errd}")
                else:
                    st.info("该记录类型当前页面不提供编辑（仅支持 A/AAAA/CNAME/TXT）。")

    # ----------------------------
    # 新增记录
    # ----------------------------
    with tabs[1]:
        st.write("支持：A / AAAA / CNAME / TXT（TTL 默认 1 秒）")

        with st.form("create_record_form", clear_on_submit=False):
            rtype = st.selectbox("记录类型", ["A", "AAAA", "CNAME", "TXT"])
            name = st.text_input("记录名（相对域名）", value="www", help="根域用 @（例如 @ 表示 example.com）")
            ttl = st.number_input("TTL（秒）", min_value=1, max_value=86400, value=DEFAULT_TTL, step=1)

            value = st.text_area(
                "记录值",
                value="",
                help=(
                    "A：IPv4（可多行）\n"
                    "AAAA：IPv6（可多行）\n"
                    "CNAME：目标域名（单值，单行）\n"
                    "TXT：每行一条 TXT"
                ),
                height=140,
            )
            mode = st.radio("写入方式", ["覆盖（create_or_update）", "追加（若已存在则合并）"], horizontal=True)
            submitted = st.form_submit_button("创建/更新", use_container_width=True)

        if submitted:
            rname = normalize_record_name(name)
            lines = [x.strip() for x in (value or "").splitlines() if x.strip()]

            if rtype in ("A", "AAAA", "TXT") and not lines:
                st.error("请至少填写一行记录值。")
            elif rtype == "CNAME" and len(lines) != 1:
                st.error("CNAME 只能填写 1 行目标值。")
            else:
                final_lines = lines
                final_ttl = int(ttl)

                if mode.startswith("追加") and rtype in ("A", "AAAA", "TXT"):
                    okg, old, _ = safe_call(
                        st.session_state.clients.dns.record_sets.get,
                        rg_name,
                        zone_name,
                        rname,
                        rtype,
                    )
                    if okg and old is not None:
                        old_lines = record_values_to_lines(old)
                        merged = old_lines + lines
                        seen = set()
                        final_lines = []
                        for x in merged:
                            if x not in seen:
                                seen.add(x)
                                final_lines.append(x)

                rs = build_new_recordset(rtype, final_ttl, final_lines)

                with st.spinner("提交到 Azure..."):
                    ok, _, err = safe_call(
                        st.session_state.clients.dns.record_sets.create_or_update,
                        rg_name,
                        zone_name,
                        rname,
                        rtype,
                        rs,
                    )

                if ok:
                    st.success("创建/更新成功 ✅（已刷新）")
                    do_rerun()
                else:
                    st.error(
                        "创建/更新失败：\n\n"
                        f"{err}\n\n"
                        "如果 TTL=1 失败，请改成 30/60 再试（某些环境有最小 TTL 限制）。"
                    )

    # ----------------------------
    # 排错/说明
    # ----------------------------
    with tabs[2]:
        st.markdown(
            """
### 登录需要点两次（已修复）
- 原因：按钮 + st.stop 组合时，状态更新后页面没立即刷新
- 现在改用 form 提交 + do_rerun，登录一次即可

### AADSTS700016（默认目录找不到应用）
- 你填的 Tenant ID 不对 / 订阅 tenant 与应用 tenant 不一致
- 订阅在哪个 tenant，就要在那个 tenant 创建应用并用对应 tenant_id

### 权限不足（403 AuthorizationFailed）
- 给 DNS Zone 所在资源组分配：DNS Zone Contributor 给 Service Principal

### TTL=1 可能失败
- 你要求默认 1 秒我已设置
- 若 Azure 校验最小 TTL > 1，把 TTL 改 30/60 再提交
            """
        )
