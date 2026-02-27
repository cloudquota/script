import io
import re
import zipfile
from dataclasses import dataclass, asdict
from decimal import Decimal, InvalidOperation
from typing import List, Tuple

import pandas as pd
import pdfplumber
import streamlit as st


# =========================================================
# 页面设置
# =========================================================

st.set_page_config(
    page_title="发票PDF批量重命名（购买方名称+小写金额）",
    layout="wide"
)


# =========================================================
# 文件名安全
# =========================================================

def sanitize_filename_stem(stem: str, max_len: int = 120) -> str:

    stem = re.sub(r"[\\/:*?\"<>|\r\n\t]", "_", stem)
    stem = re.sub(r"\s+", " ", stem).strip()
    stem = stem.strip(". ")

    if len(stem) > max_len:
        stem = stem[:max_len].rstrip()

    return stem or "未命名"


# =========================================================
# PDF文本提取
# =========================================================

def extract_text_from_pdf_bytes(pdf_bytes: bytes) -> str:

    parts = []

    with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:

        for page in pdf.pages:

            text = page.extract_text()

            if text:
                parts.append(text)

    return "\n".join(parts)


# =========================================================
# 金额提取
# =========================================================

def pick_total_small_amount(text: str) -> str:

    t = text.replace("￥", "¥")

    m = re.search(
        r"价\s*税\s*合\s*计.*?\(\s*小\s*写\s*\).*?(¥\s*[0-9]+(?:\.[0-9]{1,2})?)",
        t,
        flags=re.DOTALL,
    )

    if m:
        return m.group(1).replace(" ", "")

    m = re.search(
        r"\(\s*小\s*写\s*\).*?(¥\s*[0-9]+(?:\.[0-9]{1,2})?)",
        t,
        flags=re.DOTALL,
    )

    if m:
        return m.group(1).replace(" ", "")

    amounts = re.findall(r"¥\s*([0-9]+(?:\.[0-9]{1,2})?)", t)

    if amounts:

        vals = [Decimal(a) for a in amounts]

        return f"¥{max(vals):.2f}"

    return ""


# =========================================================
# 金额格式化
# =========================================================

def amount_to_yuan_label(amount: str) -> str:

    if not amount:
        return "未知金额"

    try:

        d = Decimal(amount.replace("¥", ""))

        if d == d.to_integral():
            return f"{int(d)}元"

        s = format(d.normalize(), "f").rstrip("0").rstrip(".")

        return f"{s}元"

    except:
        return "未知金额"


# =========================================================
# 中文空格修复
# =========================================================

def remove_inner_spaces(s: str) -> str:

    return re.sub(r"(?<=\S)\s+(?=\S)", "", s).strip()


def cleanup_name_candidate(raw: str) -> str:

    name = remove_inner_spaces(raw)

    for marker in ["名称:", "名称", "纳税人识别号", "统一社会信用代码"]:
        if marker in name:
            name = name.split(marker, 1)[0]

    return name.strip(" :：;；，,")


def split_person_from_merged_company(name: str) -> str:

    city_markers = [
        "北京", "上海", "广州", "深圳", "苏州", "杭州", "南京", "天津", "重庆",
        "成都", "武汉", "西安", "长沙", "青岛", "宁波", "厦门", "东莞", "佛山",
        "郑州", "合肥", "济南", "福州", "无锡", "常州", "嘉兴", "昆山", "工业园区",
        "江苏", "浙江", "广东", "山东", "福建", "河北", "河南", "湖北", "湖南", "安徽",
    ]

    if not re.match(r"^[\u4e00-\u9fa5]{2,4}.+(公司|有限公司|有限责任公司|股份有限公司|集团)$", name):
        return name

    for marker in city_markers:
        pos = name.find(marker)

        if 1 < pos <= 6:
            return name[:pos]

    return name


# =========================================================
# 噪音过滤
# =========================================================

def is_noise(line: str) -> bool:

    bad = [
        "项目名称",
        "规格型号",
        "单位",
        "数量",
        "单价",
        "金额",
        "税率",
        "税额",
        "开票日期",
        "发票号码",
        "校验码",
        "收款人",
        "复核",
        "开票人",
        "税务局",
        "国家税务",
    ]

    return any(x in line for x in bad)


# =========================================================
# 提取购买方区域（关键修复）
# =========================================================

def extract_buyer_section(text: str) -> str:

    # 常见版式："购买方信息 ... 销售方信息"
    m = re.search(
        r"购\s*买\s*方\s*信\s*息(.*?)销\s*售\s*方\s*信\s*息",
        text,
        re.DOTALL,
    )

    if m:
        return m.group(1)

    # 部分提取文本会丢字，变成："购方信息 ... 销方信息"
    m = re.search(
        r"购\s*方\s*信\s*息(.*?)销\s*方\s*信\s*息",
        text,
        re.DOTALL,
    )

    if m:
        return m.group(1)

    return ""


# =========================================================
# 购买方名称提取（终极稳定版）
# =========================================================

def pick_buyer_name(text: str) -> str:

    text = text.replace("：", ":")

    lines = [remove_inner_spaces(x) for x in text.splitlines() if x.strip()]

    # 0. 先按购方/销方锚点做“同一行”精确截断，避免把销售方识别成购买方
    inline_patterns = [
        r"购\s*买\s*方\s*信\s*息.*?名\s*称\s*:\s*(.*?)\s*(?=销\s*售\s*方\s*信\s*息|$)",
        r"购\s*方\s*信\s*息.*?名\s*称\s*:\s*(.*?)\s*(?=销\s*方\s*信\s*息|$)",
    ]

    for p in inline_patterns:
        m = re.search(p, text, flags=re.DOTALL)

        if m:
            name = split_person_from_merged_company(cleanup_name_candidate(m.group(1)))

            if name and not is_noise(name):
                return name[:80]

    # 1. 同一行：购名称 xxx 销名称 xxx
    m = re.search(
        r"购\s*名\s*称\s*:\s*(.*?)\s*销\s*名\s*称",
        text,
    )

    if m:
        name = remove_inner_spaces(m.group(1))

        if not is_noise(name):
            return name[:80]

    # 2. 购买方区域查找
    section = extract_buyer_section(text)

    if section:

        m = re.search(
            r"名称\s*:\s*(.*?)\s*(?=名称\s*:|统一社会信用代码|纳税人识别号|$)",
            section,
        )

        if m:
            name = split_person_from_merged_company(cleanup_name_candidate(m.group(1)))

            if name and not is_noise(name):
                return name[:80]

        sec_lines = [remove_inner_spaces(x) for x in section.splitlines()]

        for i, line in enumerate(sec_lines):

            if "名称" in line and i + 1 < len(sec_lines):

                name = sec_lines[i + 1]

                if name and not is_noise(name):
                    return name[:80]

        # 税号锚点（只限购买方区域）
        taxid = re.compile(r"^[0-9A-Z]{15,20}$")

        for i, line in enumerate(sec_lines):

            if taxid.match(line) and i > 0:

                name = sec_lines[i - 1]

                if not is_noise(name):
                    return name[:80]

    # 3. 全局查找 名称:xxx
    name_lines = []

    for line in lines:

        if line.startswith("名称:"):

            raw = line.replace("名称:", "").strip()

            if not raw or is_noise(raw):
                continue

            if "名称:" in raw:
                raw = raw.split("名称:", 1)[0].strip()

            # ===== 关键修复：拆分左右列 =====

            # 情况1：两个名称紧挨着（个人 + 公司）
            # 检测公司关键词
            company_keywords = [
                "有限公司",
                "有限责任公司",
                "股份有限公司",
                "集团",
                "公司",
            ]

            cut_pos = None

            for kw in company_keywords:

                pos = raw.find(kw)

                if pos != -1:

                    # 如果公司关键词不是在最前面，说明前面是买方
                    if pos > 6:  # 避免公司本身
                        cut_pos = pos + len(kw)
                        break

            if cut_pos:
                possible = raw[:cut_pos]

                # 如果前面还有短姓名，优先取第一个词
                parts = possible.split()

                if len(parts) >= 2 and len(parts[0]) <= 6:
                    name_lines.append(parts[0])
                else:
                    name_lines.append(possible)

            else:
                # 如果没有公司关键词，取第一个词
                name_lines.append(raw.split()[0])

    if name_lines:
        candidate = split_person_from_merged_company(cleanup_name_candidate(name_lines[0]))
        return candidate[:80] if candidate else "未知购买方"

    return "未知购买方"

# =========================================================
# 数据结构
# =========================================================

@dataclass
class Row:

    原文件名: str
    购买方名称: str
    小写金额: str
    重命名文件名: str
    ZIP最终文件名: str
    状态: str
    预览文本: str


# =========================================================
# 构建文件名
# =========================================================

def build_new_filename(buyer, amount, delimiter):

    stem = sanitize_filename_stem(
        f"{buyer}{delimiter}{amount}"
    )

    return f"{stem}.pdf"


# =========================================================
# 单文件处理
# =========================================================

def process_one(name, data, delimiter):

    text = extract_text_from_pdf_bytes(data)

    preview = text[:2000]

    if not text:

        return Row(
            name,
            "",
            "",
            "",
            "",
            "扫描件",
            preview,
        ), ""

    buyer = pick_buyer_name(text)

    amount = amount_to_yuan_label(
        pick_total_small_amount(text)
    )

    status = "OK"

    if buyer == "未知购买方":
        status = "未识别购买方"

    newname = build_new_filename(
        buyer,
        amount,
        delimiter,
    )

    row = Row(
        name,
        buyer,
        amount,
        newname,
        "",
        status,
        preview,
    )

    return row, newname


# =========================================================
# UI
# =========================================================

st.title("发票PDF批量处理系统（完整修复版）")

delimiter = st.text_input("分隔符", " ___")

uploaded = st.file_uploader(
    "上传PDF",
    type=["pdf"],
    accept_multiple_files=True,
)


if st.button("开始处理"):

    rows = []

    zipbuf = io.BytesIO()

    used = set()

    prog = st.progress(0)

    with zipfile.ZipFile(zipbuf, "w") as zipf:

        for i, f in enumerate(uploaded):

            data = f.read()

            row, newname = process_one(
                f.name,
                data,
                delimiter,
            )

            final = newname

            base = newname[:-4]

            k = 2

            while final in used:

                final = f"{base}({k}).pdf"

                k += 1

            used.add(final)

            row.ZIP最终文件名 = final

            zipf.writestr(final, data)

            rows.append(row)

            prog.progress((i + 1) / len(uploaded))

    df = pd.DataFrame([asdict(r) for r in rows])

    st.dataframe(df.drop(columns=["预览文本"]))

    excel = io.BytesIO()

    with pd.ExcelWriter(excel, engine="openpyxl") as writer:

        df.drop(columns=["预览文本"]).to_excel(
            writer,
            index=False,
        )

    st.download_button(
        "下载Excel",
        excel.getvalue(),
        "发票结果.xlsx",
    )

    st.download_button(
        "下载ZIP",
        zipbuf.getvalue(),
        "重命名PDF.zip",
    )
