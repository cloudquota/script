import streamlit as st
import requests
import time

API_BASE_URL = "https://api.digitalocean.com/v2"


# ----------------------------
# HTTP Helpers
# ----------------------------
def headers(token: str):
    return {
        "Authorization": f"Bearer {token.strip()}",
        "Content-Type": "application/json",
    }


def request_json(method: str, token: str, path: str, params=None, json=None, timeout=30):
    url = f"{API_BASE_URL}{path}"
    try:
        r = requests.request(
            method=method,
            url=url,
            headers=headers(token),
            params=params or {},
            json=json,
            timeout=timeout,
        )
        return r, None
    except requests.RequestException as e:
        return None, str(e)


def pretty_err(resp: requests.Response):
    if resp is None:
        return "请求失败：无响应"
    code = resp.status_code
    msg = resp.text or ""
    if code == 401:
        return f"401 未授权：Token 无效或权限不足。\n{msg}"
    if code == 429:
        return f"429 触发限流：请稍等再试。\n{msg}"
    if 500 <= code <= 599:
        return f"{code} 服务器错误：稍后再试。\n{msg}"
    return f"{code} 请求失败：\n{msg}"


# ----------------------------
# DigitalOcean API
# ----------------------------
def verify_token(token: str):
    r, err = request_json("GET", token, "/account", timeout=10)
    if err:
        return False, None, f"连接失败：{err}"
    if r.status_code == 200:
        email = r.json().get("account", {}).get("email", "")
        return True, email, None
    return False, None, pretty_err(r)


def fetch_regions(token: str):
    r, err = request_json("GET", token, "/regions", params={"per_page": 200}, timeout=15)
    if err:
        return [], f"网络错误：{err}"
    if r.status_code != 200:
        return [], pretty_err(r)
    regions = r.json().get("regions", []) or []
    return [x for x in regions if x.get("available")], None


def fetch_images(token: str):
    r, err = request_json(
        "GET",
        token,
        "/images",
        params={"type": "distribution", "per_page": 200},
        timeout=20,
    )
    if err:
        return [], f"网络错误：{err}"
    if r.status_code != 200:
        return [], pretty_err(r)

    images = r.json().get("images", []) or []
    images = [i for i in images if i.get("status") == "available"]
    images.sort(key=lambda x: (str(x.get("distribution", "")), str(x.get("name", ""))))
    return images, None


def fetch_sizes(token: str, only_1vcpu=True):
    r, err = request_json("GET", token, "/sizes", params={"per_page": 200}, timeout=20)
    if err:
        return [], {}, f"网络错误：{err}"
    if r.status_code != 200:
        return [], {}, pretty_err(r)

    all_sizes = r.json().get("sizes", []) or []
    filtered = []
    size_map = {}  # slug -> dict

    for s in all_sizes:
        slug = str(s.get("slug", ""))
        if slug:
            size_map[slug] = s

    for s in all_sizes:
        if not s.get("available"):
            continue
        slug = str(s.get("slug", ""))
        if only_1vcpu and "1vcpu" not in slug:
            continue
        filtered.append(s)

    if not filtered:
        filtered = [s for s in all_sizes if s.get("available")]

    filtered.sort(key=lambda x: float(x.get("price_monthly", 0)))
    return filtered, size_map, None


def list_droplets_no(token: str, size_map: dict):
    """
    返回：
      rows:    [{No, Name, Public IPv4, Status, Region, Plan, OS}, ...]
      index_map: {"1": "real_droplet_id", ...}
    """
    r, err = request_json("GET", token, "/droplets", params={"per_page": 200}, timeout=25)
    if err:
        return [], {}, f"网络错误：{err}"
    if r.status_code != 200:
        return [], {}, pretty_err(r)

    droplets = r.json().get("droplets", []) or []
    rows = []
    index_map = {}

    for idx, d in enumerate(droplets, start=1):
        real_id = str(d.get("id", ""))
        name = d.get("name", "N/A")
        status = d.get("status", "N/A")
        region = d.get("region", {}).get("slug", "N/A")

        ip = "N/A"
        for net in (d.get("networks", {}) or {}).get("v4", []) or []:
            if net.get("type") == "public":
                ip = net.get("ip_address", "N/A")
                break

        # ---- Plan: $4/mo | RAM:512MB | Disk:10GB | s-1vcpu-512mb-10gb
        size_slug = str(d.get("size_slug", "") or "")
        s = size_map.get(size_slug, {}) if size_slug else {}
        price = s.get("price_monthly")
        mem = s.get("memory")
        disk = s.get("disk")
        if price is None or mem is None or disk is None:
            plan = f"{size_slug or 'N/A'}"
        else:
            try:
                plan = f"${float(price):g}/mo | RAM:{int(mem)}MB | Disk:{int(disk)}GB | {size_slug}"
            except Exception:
                plan = f"${price}/mo | RAM:{mem}MB | Disk:{disk}GB | {size_slug}"

        # ---- OS: 详细系统内容（来自 droplet.image）
        img = d.get("image") or {}
        dist = img.get("distribution") or "N/A"
        img_name = img.get("name") or "N/A"
        img_slug = img.get("slug") or ""
        img_id = img.get("id") or ""
        # 尽量详细：distribution + name + slug/id
        os_text = f"{dist} | {img_name}"
        extra = []
        if img_slug:
            extra.append(f"slug={img_slug}")
        if img_id:
            extra.append(f"id={img_id}")
        if extra:
            os_text += " | " + ", ".join(extra)

        rows.append(
            {
                "No": idx,
                "Name": name,
                "Public IPv4": ip,
                "Status": status,
                "Region": region,
                "Plan": plan,
                "OS": os_text,
            }
        )

        if real_id:
            index_map[str(idx)] = real_id

    return rows, index_map, None


def create_droplet_root_password(
    token: str,
    name: str,
    region_slug: str,
    image_value,
    size_slug: str,
    enable_ipv6: bool,
    root_pass: str,
    tags=None,
):
    # root 密码登录（强制）
    user_data = f"""#cloud-config
chpasswd:
  list: |
    root:{root_pass}
  expire: False
ssh_pwauth: True
"""
    payload = {
        "name": name,
        "region": region_slug,
        "size": size_slug,
        "image": image_value,  # slug 或 id
        "ipv6": enable_ipv6,
        "user_data": user_data,
        "tags": tags or ["streamlit-panel"],
    }

    r, err = request_json("POST", token, "/droplets", json=payload, timeout=35)
    if err:
        return None, f"网络错误：{err}"
    if r.status_code in (200, 201, 202):
        return r.json().get("droplet", {}), None
    return None, pretty_err(r)


def droplet_action(token: str, droplet_id: str, action_type: str):
    payload = {"type": action_type}
    r, err = request_json(
        "POST", token, f"/droplets/{droplet_id}/actions", json=payload, timeout=20
    )
    if err:
        return False, f"网络错误：{err}"
    if r.status_code in (200, 201, 202):
        return True, None
    return False, pretty_err(r)


def delete_droplet(token: str, droplet_id: str):
    r, err = request_json("DELETE", token, f"/droplets/{droplet_id}", timeout=20)
    if err:
        return False, f"网络错误：{err}"
    if r.status_code == 204:
        return True, None
    return False, pretty_err(r)


# ----------------------------
# Streamlit UI
# ----------------------------
st.set_page_config(page_title="DigitalOcean Web 面板 (Streamlit)", layout="wide")
st.title("DigitalOcean 简易 Web 面板（单文件 Streamlit）")
st.caption("强制 root 密码登录（不使用 SSH Key）；列表显示 No=1/2/3...；删除二次点击确认。")

# 删除确认状态
if "delete_pending_no" not in st.session_state:
    st.session_state.delete_pending_no = None

# 登录状态
if "authed" not in st.session_state:
    st.session_state.authed = False
if "email" not in st.session_state:
    st.session_state.email = ""

with st.sidebar:
    st.header("登录")
    token = st.text_input("DigitalOcean API Token", type="password", placeholder="粘贴 token")
    c1, c2 = st.columns(2)
    btn_verify = c1.button("验证 Token", use_container_width=True)
    btn_clear = c2.button("清除会话", use_container_width=True)

    if btn_clear:
        for k in list(st.session_state.keys()):
            del st.session_state[k]
        st.success("已清除。")
        st.stop()

if btn_verify and token.strip():
    ok, email, err = verify_token(token)
    if ok:
        st.session_state.authed = True
        st.session_state.email = email or ""
        st.success(f"验证成功：{st.session_state.email}")
    else:
        st.session_state.authed = False
        st.error(err)

if not st.session_state.authed:
    st.info("请先在左侧输入 Token 并点击「验证 Token」。")
    st.stop()

st.success(f"当前账户：{st.session_state.email}")

tabs = st.tabs(["创建 Droplet", "列表/操作/删除", "运行说明"])


# ----------------------------
# Tab 1: Create (Root password only, no SSH key)
# ----------------------------
with tabs[0]:
    st.subheader("创建 Droplet（root 密码登录，不使用 SSH Key）")

    left, right = st.columns(2, gap="large")

    with left:
        only_1vcpu = st.toggle("只显示 1vCPU 便宜套餐", value=True)

        with st.spinner("拉取 Regions / Images / Sizes ..."):
            regions, e1 = fetch_regions(token)
            images, e2 = fetch_images(token)
            sizes, size_map, e3 = fetch_sizes(token, only_1vcpu=only_1vcpu)

        if e1 or e2 or e3:
            st.error("\n".join([x for x in [e1, e2, e3] if x]))
            st.stop()

        region_options = [f"{r.get('name')} ({r.get('slug')})" for r in regions]
        region_map = {f"{r.get('name')} ({r.get('slug')})": r.get("slug") for r in regions}
        region_choice = st.selectbox("Region", region_options)

        # 镜像搜索默认 debian
        kw = st.text_input("镜像搜索（默认 debian）", value="debian")
        kw_l = kw.strip().lower()

        filtered_images = []
        for img in images:
            dist = (img.get("distribution") or "").lower()
            name = (img.get("name") or "").lower()
            if (not kw_l) or (kw_l in dist) or (kw_l in name):
                filtered_images.append(img)
        if not filtered_images:
            filtered_images = images[:120]

        # “仔细的系统内容”：下拉显示更详细（含 slug/id）
        img_options = []
        img_value_map = {}
        img_detail_map = {}

        for img in filtered_images[:200]:
            dist = img.get("distribution", "N/A")
            name = img.get("name", "N/A")
            slug = img.get("slug")
            img_id = img.get("id")
            show_id = slug if slug else str(img_id)
            min_disk = img.get("min_disk_size")
            created_at = img.get("created_at", "")
            # label 尽量详细但别太长
            label = f"{dist} | {name} | {('slug='+slug) if slug else ('id='+str(img_id))}"
            img_options.append(label)
            img_value_map[label] = slug if slug else img_id

            detail_lines = [
                f"Distribution: {dist}",
                f"Name: {name}",
                f"Slug: {slug or 'N/A'}",
                f"ID: {img_id or 'N/A'}",
                f"Min Disk Size: {min_disk if min_disk is not None else 'N/A'}",
                f"Created At: {created_at or 'N/A'}",
                f"Status: {img.get('status','N/A')}",
            ]
            img_detail_map[label] = "\n".join(detail_lines)

        image_choice = st.selectbox("Image（系统）", img_options)

        with st.expander("查看所选系统的详细信息", expanded=False):
            st.code(img_detail_map.get(image_choice, "N/A"), language="text")

    with right:
        # Size 下拉展示更清晰
        size_options = []
        size_map_ui = {}

        for s in sizes[:60]:
            price = s.get("price_monthly", "N/A")
            mem = s.get("memory", "N/A")
            disk = s.get("disk", "N/A")
            slug = s.get("slug", "N/A")
            label = f"${price}/mo | RAM:{mem}MB | Disk:{disk}GB | {slug}"
            size_options.append(label)
            size_map_ui[label] = slug

        size_choice = st.selectbox("Size（配置）", size_options)
        enable_ipv6 = st.toggle("开启 IPv6", value=False)

        name = st.text_input("Droplet 名称", value="droplet-generated")
        tags = st.text_input("Tags（逗号分隔）", value="streamlit-panel")
        tag_list = [t.strip() for t in tags.split(",") if t.strip()] or ["streamlit-panel"]

        st.divider()
        st.markdown("### Root 密码（强制启用）")

        DEFAULT_ROOT_PASS = "258@45@6Wzy"
        root_pass = st.text_input("Root 密码（留空用默认）", type="password", value="")
        if not root_pass:
            st.info(f"将使用默认 Root 密码：{DEFAULT_ROOT_PASS}")

        create_btn = st.button("创建 Droplet", type="primary", use_container_width=True)

    if create_btn:
        region_slug = region_map.get(region_choice)
        image_value = img_value_map.get(image_choice)
        size_slug = size_map_ui.get(size_choice)

        final_pass = root_pass.strip() if root_pass.strip() else DEFAULT_ROOT_PASS

        if not region_slug or not image_value or not size_slug:
            st.error("Region / Image / Size 选择无效，请重试。")
        else:
            with st.spinner("正在创建 Droplet..."):
                droplet, err = create_droplet_root_password(
                    token=token,
                    name=name.strip() or "droplet-generated",
                    region_slug=region_slug,
                    image_value=image_value,
                    size_slug=size_slug,
                    enable_ipv6=enable_ipv6,
                    root_pass=final_pass,
                    tags=tag_list,
                )
            if err:
                st.error(err)
            else:
                d_id = str(droplet.get("id"))
                st.success(f"创建成功！Droplet ID: {d_id}")
                st.info("通常 1-2 分钟后公网 IP/初始化完成。")


# ----------------------------
# Tab 2: List / Actions / Delete (No + Plan + OS)
# ----------------------------
with tabs[1]:
    st.subheader("Droplet 列表 / 电源操作 / 删除（No 编号 + Plan + OS）")

    # 先拉 sizes（为了 plan 显示准确）
    _, size_map, e_sizes = fetch_sizes(token, only_1vcpu=False)
    if e_sizes:
        st.warning(f"获取 sizes 失败，Plan 可能显示不完整：{e_sizes}")
        size_map = {}

    if st.button("刷新列表", use_container_width=True):
        st.session_state.delete_pending_no = None
        st.rerun()

    rows, index_map, err = list_droplets_no(token, size_map)
    if err:
        st.error(err)
        st.stop()

    if not rows:
        st.info("当前没有 Droplet。")
        st.stop()

    # 列表显示（包含 Plan + OS）
    st.dataframe(rows, use_container_width=True, hide_index=True)

    if not index_map:
        st.warning("未能获取到 droplet ID 映射（index_map 为空），请刷新或检查权限。")
        st.stop()

    # 选择项：No + Name + IP + Plan（更直观）
    options = []
    for r in rows:
        no = str(r["No"])
        label = (
            f"{no}. {r.get('Name','N/A')} | {r.get('Public IPv4','N/A')} | "
            f"{r.get('Plan','N/A')} | {r.get('Status','N/A')} | {r.get('Region','N/A')}"
        )
        options.append((no, label))

    selected_label = st.selectbox("选择机器（按 No）", [x[1] for x in options], index=0)

    selected_no = None
    for no, label in options:
        if label == selected_label:
            selected_no = no
            break

    if not selected_no or selected_no not in index_map:
        st.error("选择的 No 无效或映射缺失，请刷新页面重试。")
        st.stop()

    real_id = index_map[selected_no]

    # 展示该机器 OS 详细（从表里反查）
    selected_row = None
    for r in rows:
        if str(r.get("No")) == str(selected_no):
            selected_row = r
            break

    if selected_row:
        with st.expander("当前选择机器详情（Plan / OS）", expanded=False):
            st.write(f"**No**: {selected_row.get('No')}")
            st.write(f"**Name**: {selected_row.get('Name')}")
            st.write(f"**Public IPv4**: {selected_row.get('Public IPv4')}")
            st.write(f"**Plan**: {selected_row.get('Plan')}")
            st.write(f"**OS**: {selected_row.get('OS')}")
            st.write(f"**Status**: {selected_row.get('Status')}")
            st.write(f"**Region**: {selected_row.get('Region')}")

    st.divider()

    c1, c2, c3, c4 = st.columns(4)

    if c1.button("Power On", use_container_width=True, key="btn_power_on"):
        ok, e = droplet_action(token, real_id, "power_on")
        st.success("已提交 power_on") if ok else st.error(e)

    if c2.button("Power Off", use_container_width=True, key="btn_power_off"):
        ok, e = droplet_action(token, real_id, "power_off")
        st.success("已提交 power_off") if ok else st.error(e)

    if c3.button("Reboot", use_container_width=True, key="btn_reboot"):
        ok, e = droplet_action(token, real_id, "reboot")
        st.success("已提交 reboot") if ok else st.error(e)

    # 删除：二次点击确认（无输入、无弹窗，最兼容）
    if c4.button("删除（第一步）", use_container_width=True, key="btn_delete_step1"):
        st.session_state.delete_pending_no = selected_no
        st.rerun()

    if st.session_state.delete_pending_no:
        pending_no = st.session_state.delete_pending_no

        if pending_no not in index_map:
            st.session_state.delete_pending_no = None
            st.warning("待删除项已变化/不存在，已取消删除确认。请重新选择。")
            st.stop()

        pending_real_id = index_map[pending_no]

        st.warning(
            f"⚠️ 确认删除机器 No={pending_no}（内部ID={pending_real_id}）？\n\n此操作不可恢复。",
            icon="⚠️",
        )

        cc1, cc2 = st.columns(2)
        if cc1.button("✅ 确认删除（第二步）", type="primary", use_container_width=True, key="btn_delete_confirm"):
            ok, e = delete_droplet(token, pending_real_id)
            if ok:
                st.success(f"已删除：No={pending_no}")
                st.session_state.delete_pending_no = None
                time.sleep(0.6)
                st.rerun()
            else:
                st.error(e)

        if cc2.button("取消", use_container_width=True, key="btn_delete_cancel"):
            st.session_state.delete_pending_no = None
            st.info("已取消删除。")
            st.rerun()


# ----------------------------
# Tab 3: Run tips
# ----------------------------
with tabs[2]:
    st.subheader("运行说明")
    st.code("streamlit run do_panel.py --server.address 0.0.0.0 --server.port 9000", language="bash")
    st.write("如端口被占用，换端口即可：")
    st.code("streamlit run do_panel.py --server.address 0.0.0.0 --server.port 19001", language="bash")
