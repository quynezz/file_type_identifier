#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║          FILESHIELD — Cyber Security File Analyzer            ║
║          Magic Byte Detection + Threat Analysis Tool          ║
║          v1.0 | No external dependencies required             ║
╚═══════════════════════════════════════════════════════════════╝


Usage:
  python3 fileshield.py <file>              # Scan single file
  python3 fileshield.py <file1> <file2> ... # Scan multiple files
  python3 fileshield.py -d <directory>      # Scan entire directory
  python3 fileshield.py -h                  # Show help
  python3 fileshield.py --export report.json      # Export JSON report

  ── RECOVERY MODE ──────────────────────────────────────────────
  python3 fileshield.py --recover <file>           # Suggest possible file types & show recovery options
  python3 fileshield.py --recover <file> --as jpg  # Patch header to recover as specific type
  python3 fileshield.py --recover <file> --as pdf --output fixed.pdf
"""

import os
import sys
import math
import json
import struct
import hashlib
import argparse
import datetime

import pathlib
from typing import Optional



# ─────────────────────────────────────────────────────────────
#  ANSI COLOR ENGINE  (no external deps)
# ─────────────────────────────────────────────────────────────
class C:
    """Terminal colors & styles."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    BLINK   = "\033[5m"


    # Foreground
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    ORANGE  = "\033[38;5;208m"

    PURPLE  = "\033[95m"

    # Background
    BG_RED    = "\033[41m"
    BG_GREEN  = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE   = "\033[44m"


    @staticmethod
    def disable():
        """Disable colors (for piping output)."""
        for attr in ['RESET','BOLD','DIM','BLINK','RED','GREEN','YELLOW',
                     'BLUE','CYAN','WHITE','GRAY','ORANGE','PURPLE',
                     'BG_RED','BG_GREEN','BG_YELLOW','BG_BLUE']:
            setattr(C, attr, '')

def c(text, *styles) -> str:
    return ''.join(styles) + str(text) + C.RESET


# ─────────────────────────────────────────────────────────────

#  MAGIC BYTE DATABASE
# ─────────────────────────────────────────────────────────────
SIGNATURES = [
    # ── Executables (highest risk) ──────────────────────────
    {
        "magic": b"\x4D\x5A",
        "label": "Windows PE Executable (MZ)",
        "ext_hints": ["exe","dll","sys","scr","drv","com"],
        "category": "executable",
        "risk": "CRITICAL",
        "description": "Windows Portable Executable. File thực thi native trên Windows. "
                       "Nếu được upload lên server và execute, attacker có full control.",
        "attack_vectors": [
            "Rename thành .jpg để bypass upload filter",
            "Double extension: malware.jpg.exe",
            "Embed trong Office macro (dropper)",
        ],
    },
    {
        "magic": b"\x7F\x45\x4C\x46",
        "label": "ELF Executable (Linux/Android)",
        "ext_hints": ["elf","so","bin","out"],
        "category": "executable",
        "risk": "CRITICAL",
        "description": "Executable and Linkable Format — binary thực thi trên Linux/Android/Unix. "

                       "Nguy hiểm tương đương PE trên Windows.",
        "attack_vectors": [
            "Upload lên Linux server disguised dưới dạng data file",
            "Shared library (.so) injection",
        ],

    },
    {
        "magic": b"\xCA\xFE\xBA\xBE",

        "label": "Java Class / Mach-O Universal Binary",
        "ext_hints": ["class","jar","dylib"],

        "category": "executable",
        "risk": "CRITICAL",
        "description": "Java bytecode hoặc macOS universal binary (fat binary). "
                       "Java class có thể thực thi trên mọi JVM; đặc biệt nguy hiểm trong môi trường Java server.",
        "attack_vectors": [
            "Upload .class file lên Java web server → RCE",
            "Deserialization exploit payload",
        ],
    },
    {
        "magic": b"\xFE\xED\xFA\xCE",
        "label": "Mach-O Binary (macOS 32-bit)",
        "ext_hints": ["macho","dylib"],

        "category": "executable",
        "risk": "CRITICAL",
        "description": "macOS native executable (32-bit). Có thể chứa malicious code targeting Apple systems.",
        "attack_vectors": ["Upload lên macOS server và trigger execute"],
    },

    {
        "magic": b"\xFE\xED\xFA\xCF",
        "label": "Mach-O Binary (macOS 64-bit)",
        "ext_hints": ["macho","dylib"],
        "category": "executable",

        "risk": "CRITICAL",
        "description": "macOS native executable (64-bit). Nguy hiểm cao trên Apple Silicon và Intel Mac servers.",
        "attack_vectors": ["Upload lên macOS server và trigger execute"],
    },
    # ── Scripts ─────────────────────────────────────────────

    {
        "magic": b"\x23\x21",
        "label": "Script with Shebang (#!)",

        "ext_hints": ["sh","py","rb","pl","php","bash"],
        "category": "script",

        "risk": "HIGH",
        "description": "File script có shebang line (#!/...). Có thể thực thi trực tiếp trên Unix "
                       "nếu có execute permission. Rủi ro cao khi upload lên server.",
        "attack_vectors": [
            "chmod +x sau khi upload → execute trực tiếp",
            "Đổi tên thành .txt hoặc .log để bypass filter",
        ],
    },
    {
        "magic": b"\x3C\x3F\x70\x68\x70",  # <?php
        "label": "PHP Source Code",
        "ext_hints": ["php","php3","php4","php5","phtml"],
        "category": "script",
        "risk": "CRITICAL",
        "description": "PHP source code. Đây là kiểu tấn công webshell phổ biến nhất. "

                       "Attacker upload file PHP disguised là ảnh, sau đó gọi URL để execute.",
        "attack_vectors": [
            "shell.php → shell.jpg.php → shell.php%00.jpg",
            "Content-Type spoofing: gửi image/jpeg nhưng nội dung là PHP",
            "GIF header + PHP code (GIFAR technique)",
        ],
    },
    # ── Documents ───────────────────────────────────────────
    {
        "magic": b"\x25\x50\x44\x46",  # %PDF
        "label": "PDF Document",
        "ext_hints": ["pdf"],
        "category": "document",
        "risk": "MEDIUM",
        "description": "Portable Document Format. PDF hỗ trợ JavaScript, embedded files, và nhiều "
                       "feature phức tạp có thể bị khai thác. Nhiều CVE nghiêm trọng trong PDF readers.",
        "attack_vectors": [
            "Embedded JavaScript → RCE trong PDF reader",
            "Launch action → mở shell",
            "Embedded executable (file trong file)",
            "XXE qua PDF XML form",
        ],
    },
    {
        "magic": b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        "label": "Microsoft Office Legacy (OLE2/CFB)",
        "ext_hints": ["doc","xls","ppt","msg","vsd"],

        "category": "document",
        "risk": "HIGH",
        "description": "Microsoft Compound File Binary Format (OLE2). Format cũ của Office trước 2007. "
                       "Nổi tiếng với macro VBA — phương thức phát tán malware số 1 qua email.",
        "attack_vectors": [
            "VBA Macro → download & execute payload",

            "Embedded OLE object (exe trong doc)",
            "DDE (Dynamic Data Exchange) injection",
        ],
    },
    {
        "magic": b"\x50\x4B\x03\x04",  # PK zip
        "label": "ZIP Archive / Office Open XML (OOXML)",
        "ext_hints": ["zip","docx","xlsx","pptx","apk","jar","ipa"],
        "category": "archive",
        "risk": "MEDIUM",

        "description": "ZIP format, cũng là container của OOXML (Office 2007+), APK, JAR, IPA. "
                       "Có thể chứa bất kỳ file nào bên trong, kể cả executable.",
        "attack_vectors": [
            "Path traversal: ../../../etc/passwd trong zip entry",

            "Zip Bomb: compress ratio 1000:1 → DoS",
            "OOXML macro (docm, xlsm) → malware dropper",
            "APK với malicious Android code",
        ],
    },
    {
        "magic": b"\x52\x61\x72\x21\x1A\x07",  # Rar!
        "label": "RAR Archive",
        "ext_hints": ["rar"],
        "category": "archive",
        "risk": "MEDIUM",
        "description": "RAR archive. Có thể chứa malware, khai thác path traversal, hoặc được dùng "
                       "để đóng gói payload tránh antivirus detection.",
        "attack_vectors": [

            "Chứa executable hidden bên trong",
            "Path traversal attack khi extract",
        ],

    },
    {
        "magic": b"\x37\x7A\xBC\xAF\x27\x1C",  # 7z
        "label": "7-Zip Archive",

        "ext_hints": ["7z"],
        "category": "archive",
        "risk": "MEDIUM",
        "description": "7-Zip archive với compression cao. Thường dùng để che giấu payload.",
        "attack_vectors": ["Chứa executable", "Nested archive (archive trong archive)"],
    },
    {
        "magic": b"\x1F\x8B",  # gzip
        "label": "GZIP Compressed",
        "ext_hints": ["gz","tgz","tar.gz"],
        "category": "archive",
        "risk": "LOW",
        "description": "GZIP compression. Cần decompress và scan nội dung bên trong.",
        "attack_vectors": ["Chứa malicious content sau khi extract"],
    },
    # ── Images ──────────────────────────────────────────────
    {
        "magic": b"\xFF\xD8\xFF",

        "label": "JPEG Image",
        "ext_hints": ["jpg","jpeg","jpe","jfif"],
        "category": "image",
        "risk": "LOW",

        "description": "JPEG image format. Tương đối an toàn nhưng có thể bị dùng trong "
                       "polyglot attack — file vừa là JPEG hợp lệ vừa là script.",
        "attack_vectors": [
            "JPEG + PHP polyglot: magic bytes JPEG nhưng PHP code ở cuối file",
            "ImageMagick exploit (CVE-2016-3714 'ImageTragick')",
            "Steganography để ẩn payload trong pixel data",
        ],
    },
    {
        "magic": b"\x89\x50\x4E\x47\x0D\x0A\x1A\x0A",
        "label": "PNG Image",
        "ext_hints": ["png"],

        "category": "image",
        "risk": "LOW",
        "description": "PNG image format. Có cấu trúc chunk-based có thể bị abuse để embed data.",
        "attack_vectors": [
            "PNG + PHP polyglot",
            "Malicious tEXt chunk trong PNG",
            "ImageMagick exploitation",

        ],
    },
    {

        "magic": b"\x47\x49\x46\x38",  # GIF8
        "label": "GIF Image",
        "ext_hints": ["gif"],

        "category": "image",
        "risk": "LOW",
        "description": "GIF image. Đặc biệt nổi tiếng với kỹ thuật GIFAR (GIF + JAR) — "
                       "file vừa là GIF hợp lệ vừa là Java Archive thực thi được.",
        "attack_vectors": [
            "GIFAR: GIF header + JAR content → execute trong Java sandbox",
            "GIF + PHP payload (polyglot webshell)",
            "Animated GIF với XSS payload trong metadata",
        ],

    },
    {
        "magic": b"\x42\x4D",  # BM
        "label": "BMP Image",
        "ext_hints": ["bmp","dib"],
        "category": "image",
        "risk": "LOW",
        "description": "Windows Bitmap. Uncompressed, ít được dùng cho attack nhưng vẫn có thể polyglot.",
        "attack_vectors": ["BMP + PE polyglot"],
    },
    # ── Media ────────────────────────────────────────────────

    {
        "magic": b"\xFF\xFB",
        "label": "MP3 Audio",
        "ext_hints": ["mp3"],

        "category": "media",
        "risk": "LOW",
        "description": "MP3 audio file. Rủi ro thấp nhưng metadata (ID3 tags) có thể chứa payload.",

        "attack_vectors": ["ID3 tag injection → stored XSS khi hiển thị metadata"],
    },
    {
        "magic": b"\x52\x49\x46\x46",  # RIFF
        "label": "RIFF Container (WAV/AVI/WebP)",
        "ext_hints": ["wav","avi","webp"],
        "category": "media",
        "risk": "LOW",
        "description": "RIFF container format. Dùng cho WAV audio, AVI video, WebP image.",
        "attack_vectors": ["Malformed RIFF header → buffer overflow trong parser"],
    },
    # ── Text/Markup ─────────────────────────────────────────
    {
        "magic": b"\x3C\x3F\x78\x6D\x6C",  # <?xml
        "label": "XML Document",
        "ext_hints": ["xml","xsl","xsd","rss","atom","svg"],
        "category": "text",
        "risk": "MEDIUM",

        "description": "XML document. Dễ bị tấn công XXE (XML External Entity) nếu parser không disable DTD.",
        "attack_vectors": [
            "XXE Injection → đọc /etc/passwd",
            "XXE → SSRF (truy cập internal network)",
            "SVG với embedded JavaScript → stored XSS",
            "Billion Laughs attack → DoS",
        ],
    },
    {
        "magic": b"\x3C\x68\x74\x6D\x6C",  # <html
        "label": "HTML Document",
        "ext_hints": ["html","htm"],
        "category": "text",
        "risk": "MEDIUM",

        "description": "HTML file. Nếu serve trực tiếp từ server với Content-Type text/html, "
                       "sẽ render và execute JavaScript → XSS.",
        "attack_vectors": [
            "Upload HTML → Stored XSS",
            "HTML với <script> tag → steal cookies",
        ],
    },
    # ── Database ─────────────────────────────────────────────

    {
        "magic": b"\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00",
        "label": "SQLite Database",

        "ext_hints": ["db","sqlite","sqlite3"],
        "category": "data",
        "risk": "LOW",

        "description": "SQLite database file. Có thể chứa sensitive data.",
        "attack_vectors": ["Exfiltrate database chứa credentials, PII"],
    },
    # ── Dangerous specific ───────────────────────────────────
    {
        "magic": b"\x4C\x00\x00\x00\x01\x14\x02\x00",
        "label": "Windows LNK Shortcut",
        "ext_hints": ["lnk"],
        "category": "executable",
        "risk": "CRITICAL",
        "description": "Windows Shell Link (.lnk). Có thể trigger arbitrary command execution "
                       "khi user chỉ nhìn vào folder (không cần double-click). "
                       "Được dùng trong Stuxnet và nhiều APT attack.",
        "attack_vectors": [
            "CVE-2010-2568 (Stuxnet): chỉ cần display icon → RCE",
            "LNK với target trỏ đến malware trên network share",
        ],
    },
    {
        "magic": b"\x46\x57\x53",  # FWS (SWF uncompressed)
        "label": "Adobe Flash SWF (Uncompressed)",
        "ext_hints": ["swf"],
        "category": "media",
        "risk": "HIGH",
        "description": "Adobe Flash SWF file. Flash đã bị deprecated và disable trên tất cả browsers. "
                       "Hàng trăm CVE nghiêm trọng. Không nên cho phép upload loại file này.",
        "attack_vectors": [

            "ActionScript → arbitrary code execution",
            "Hàng trăm unpatched CVE trong Flash player",

        ],
    },
    {

        "magic": b"\x43\x57\x53",  # CWS (SWF compressed)
        "label": "Adobe Flash SWF (Compressed)",
        "ext_hints": ["swf"],

        "category": "media",
        "risk": "HIGH",
        "description": "Adobe Flash SWF (zlib compressed). Tương tự uncompressed SWF.",
        "attack_vectors": ["Tương tự uncompressed SWF"],
    },
    {
        "magic": b"\x7B\x5C\x72\x74\x66\x31",  # {\rtf1
        "label": "RTF Document",

        "ext_hints": ["rtf"],
        "category": "document",
        "risk": "HIGH",

        "description": "Rich Text Format. Có thể chứa embedded OLE objects và exploit code. "
                       "Nhiều exploit kit dùng RTF để bypass sandbox.",
        "attack_vectors": [
            "Embedded OLE → execute payload",
            "CVE-2017-11882 (Equation Editor exploit trong RTF)",
            "\\objdata với malicious ActiveX",
        ],
    },

    {
        "magic": b"\xD4\xC3\xB2\xA1",
        "label": "PCAP Network Capture",

        "ext_hints": ["pcap"],
        "category": "data",
        "risk": "LOW",
        "description": "Wireshark/tcpdump packet capture. Có thể chứa credentials hoặc sensitive data trong unencrypted traffic.",
        "attack_vectors": ["Extract passwords, cookies từ HTTP/FTP traffic trong pcap"],
    },
    {
        "magic": b"\x0A\x0D\x0D\x0A",
        "label": "PCAPNG Network Capture",
        "ext_hints": ["pcapng"],
        "category": "data",
        "risk": "LOW",
        "description": "PCAP Next Generation format. Xem PCAP.",
        "attack_vectors": ["Extract sensitive data từ captured traffic"],
    },
]

# Known dangerous extensions (blacklist)
DANGEROUS_EXTENSIONS = {
    'exe','dll','sys','bat','cmd','sh','bash','zsh','fish',
    'php','php3','php4','php5','php7','phtml','phps',
    'py','pyc','rb','pl','lua','tcl',
    'vbs','vbe','js','jse','wsf','wsh','ps1','psm1','psd1',
    'com','scr','pif','msi','msc','hta','cpl','inf',
    'elf','so','dylib','class','jar',
    'lnk','url','swf','xap',
    'asp','aspx','jsp','jspx','cfm','cgi',

}


# Extension → expected category mapping
EXT_CATEGORY_MAP = {
    'jpg':'image','jpeg':'image','png':'image','gif':'image','bmp':'image',
    'webp':'image','ico':'image','tiff':'image','svg':'image',
    'mp4':'media','mp3':'media','wav':'media','avi':'media','mkv':'media',
    'mov':'media','flac':'media','aac':'media','ogg':'media','webm':'media',
    'pdf':'document','doc':'document','docx':'document','xls':'document',
    'xlsx':'document','ppt':'document','pptx':'document','txt':'text',
    'rtf':'document','odt':'document','ods':'document',
    'zip':'archive','rar':'archive','7z':'archive','gz':'archive',
    'tar':'archive','bz2':'archive','xz':'archive','cab':'archive',
    'exe':'executable','dll':'executable','so':'executable','dylib':'executable',
    'elf':'executable','class':'executable','jar':'executable',
    'bat':'script','sh':'script','ps1':'script','py':'script',
    'rb':'script','php':'script','js':'script','vbs':'script',
    'db':'data','sqlite':'data','json':'data','xml':'text',

    'html':'text','htm':'text','css':'text','csv':'data',

}

CATEGORY_RISK = {
    'executable': 'CRITICAL',
    'script': 'HIGH',

    'document': 'MEDIUM',
    'archive': 'MEDIUM',
    'image': 'LOW',
    'media': 'LOW',
    'text': 'LOW',
    'data': 'LOW',
}


RISK_COLOR = {
    'CRITICAL': C.RED,
    'HIGH':     C.ORANGE,
    'MEDIUM':   C.YELLOW,
    'LOW':      C.GREEN,
    'INFO':     C.CYAN,

}


RISK_ICON = {
    'CRITICAL': '☠',
    'HIGH':     '⚠',
    'MEDIUM':   '!',
    'LOW':      '✓',

    'INFO':     'ℹ',
}


# ─────────────────────────────────────────────────────────────
#  ANALYSIS ENGINE
# ─────────────────────────────────────────────────────────────
def read_bytes(filepath: str, n: int = 1024) -> bytes:
    with open(filepath, 'rb') as f:
        return f.read(n)


def detect_type(raw: bytes) -> Optional[dict]:
    """Match magic bytes against signature database."""
    for sig in SIGNATURES:
        magic = sig['magic']
        if raw[:len(magic)] == magic:
            return sig
    # UTF-8/ASCII text heuristic
    if all(b >= 0x09 and (b == 0x0A or b == 0x0D or b >= 0x20) for b in raw[:64] if b != 0x1B):
        if raw[:3] == b'\xef\xbb\xbf':  # UTF-8 BOM
            return {"label":"UTF-8 Text with BOM","ext_hints":["txt"],"category":"text","risk":"LOW",
                    "description":"Plain text file với UTF-8 BOM.","attack_vectors":[]}
        return {"label":"Plain Text / ASCII","ext_hints":["txt"],"category":"text","risk":"LOW",
                "description":"File văn bản thuần túy.","attack_vectors":[]}
    return None


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy in bits/byte."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    n = len(data)
    for f in freq:
        if f:
            p = f / n
            entropy -= p * math.log2(p)

    return entropy



def compute_hashes(filepath: str) -> dict:
    """Compute MD5, SHA1, SHA256."""
    h_md5 = hashlib.md5()
    h_sha1 = hashlib.sha1()
    h_sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            h_md5.update(chunk)
            h_sha1.update(chunk)
            h_sha256.update(chunk)
    return {
        'md5': h_md5.hexdigest(),
        'sha1': h_sha1.hexdigest(),
        'sha256': h_sha256.hexdigest(),
    }



def check_null_bytes(raw: bytes) -> int:
    return sum(1 for b in raw if b == 0x00)



def check_php_in_image(raw: bytes) -> bool:
    """Detect PHP code injected into image (polyglot)."""
    php_markers = [b'<?php', b'<?=', b'<?\n', b'<?\r']

    for marker in php_markers:
        if marker in raw:

            return True
    return False


def check_pe_in_other(raw: bytes, ext: str) -> bool:
    """Detect PE header in non-executable file."""
    if ext not in DANGEROUS_EXTENSIONS and raw[:2] == b'MZ':
        return True
    return False



def analyze(filepath: str) -> dict:
    """Full analysis of a single file. Returns result dict."""
    path = pathlib.Path(filepath)

    if not path.exists():

        return {"error": f"File không tồn tại: {filepath}"}
    if not path.is_file():
        return {"error": f"Đây không phải file: {filepath}"}

    stat = path.stat()
    ext = path.suffix.lstrip('.').lower() if path.suffix else ''

    name = path.name
    size = stat.st_size

    # Read bytes for analysis
    raw = read_bytes(filepath, min(size, 4096))
    first_bytes = raw[:16]


    # Detect file type
    detected = detect_type(raw)


    # Hashes
    hashes = compute_hashes(filepath)

    # Entropy (on first 4096 bytes)
    entropy = shannon_entropy(raw)

    # Double extension check

    parts = name.split('.')

    extensions = parts[1:] if len(parts) > 1 else []
    double_ext = len(extensions) > 1

    # Dangerous extension
    dangerous_ext = ext in DANGEROUS_EXTENSIONS

    # Extension vs content mismatch
    declared_category = EXT_CATEGORY_MAP.get(ext, 'unknown')
    actual_category = detected['category'] if detected else 'unknown'
    mismatch = (declared_category != 'unknown' and
                actual_category != 'unknown' and
                declared_category != actual_category)


    # Null bytes
    null_count = check_null_bytes(raw[:512])
    has_null = null_count > 3


    # Polyglot detection
    php_polyglot = check_php_in_image(raw)

    pe_hidden = check_pe_in_other(raw, ext)

    # ── Build threats ──
    threats = []

    risk_score = 0

    if mismatch:
        risk_score += 40
        threats.append({
            "level": "CRITICAL",
            "name": "EXTENSION MISMATCH",
            "detail": (
                f"Extension '.{ext}' ({declared_category}) không khớp với "
                f"nội dung thực tế: {detected['label'] if detected else 'UNKNOWN'} ({actual_category}).\n"
                f"          Attacker đổi tên file thực thi/script thành extension ảnh/text để bypass upload validation."
            )
        })

    if dangerous_ext:

        risk_score += 35
        threats.append({
            "level": "CRITICAL",
            "name": "DANGEROUS EXTENSION",
            "detail": (
                f"Extension '.{ext}' là loại thực thi/script. "
                f"File này có thể được execute trực tiếp trên server nếu được upload."
            )

        })

    if php_polyglot and actual_category in ('image', 'media'):

        risk_score += 45
        threats.append({
            "level": "CRITICAL",
            "name": "PHP POLYGLOT / WEBSHELL DETECTED",
            "detail": (
                "Phát hiện PHP code (<?php hoặc <?=) bên trong file binary/image. "
                "Đây là kỹ thuật webshell nguy hiểm — file qua được image validation "
                "nhưng execute như PHP khi request đến server."
            )
        })

    if pe_hidden:
        risk_score += 45
        threats.append({
            "level": "CRITICAL",
            "name": "PE EXECUTABLE HIDDEN IN FILE",
            "detail": (
                "Phát hiện MZ signature (PE/EXE) trong file với extension không phải executable. "
                "Attacker đang ẩn Windows executable bên trong file giả mạo."
            )

        })

    if double_ext:
        risk_score += 20
        threats.append({
            "level": "HIGH",
            "name": "DOUBLE EXTENSION ATTACK",
            "detail": (
                f"Filename chứa {len(extensions)} extensions: "
                f"{' → '.join('.' + e for e in extensions)}. "
                f"Kỹ thuật này đánh lừa validator chỉ kiểm tra extension cuối, "
                f"trong khi server có thể xử lý extension khác."
            )
        })

    if has_null and detected and detected['category'] in ('text', 'script'):
        risk_score += 20
        threats.append({
            "level": "HIGH",
            "name": "NULL BYTE INJECTION",
            "detail": (
                f"Phát hiện {null_count} null byte (0x00) trong text/script file. "

                f"Null byte injection (shell.php%00.jpg) có thể truncate filename "
                f"trên một số server/framework cũ → bypass extension check."
            )
        })


    if entropy > 7.2:
        risk_score += 20
        threats.append({
            "level": "HIGH",
            "name": "HIGH ENTROPY — POSSIBLE PACKER/CRYPTER",
            "detail": (
                f"Shannon entropy = {entropy:.4f} bits/byte (threshold: 7.2). "
                f"Entropy cao bất thường gợi ý file bị packed, encrypted, hoặc obfuscated. "
                f"Malware thường dùng packer để tránh signature detection."
            )
        })


    if detected and detected.get('risk') in ('HIGH', 'CRITICAL'):
        risk_score += 15
        threats.append({
            "level": detected['risk'],
            "name": f"INHERENTLY DANGEROUS FORMAT: {detected['label'].upper()}",
            "detail": detected['description']
        })
    elif detected and detected.get('risk') == 'MEDIUM':
        risk_score += 8
        threats.append({
            "level": "MEDIUM",
            "name": f"POTENTIALLY UNSAFE FORMAT: {detected['label'].upper()}",
            "detail": detected['description']

        })

    if size == 0:
        threats.append({
            "level": "INFO",
            "name": "EMPTY FILE",
            "detail": "File rỗng (0 bytes). Có thể là placeholder hoặc file corrupt."
        })

    if not threats:

        threats.append({
            "level": "LOW",
            "name": "NO SIGNIFICANT THREATS DETECTED",
            "detail": "Không phát hiện mối đe dọa rõ ràng. Luôn scan bằng antivirus và validate server-side."
        })

    risk_score = min(risk_score, 99)

    return {
        "filepath": str(filepath),
        "filename": name,
        "extension": ext,
        "size": size,
        "detected": detected,
        "hashes": hashes,
        "entropy": entropy,
        "first_bytes": first_bytes,
        "extensions": extensions,
        "double_ext": double_ext,
        "dangerous_ext": dangerous_ext,
        "mismatch": mismatch,
        "null_bytes": null_count,

        "php_polyglot": php_polyglot,
        "pe_hidden": pe_hidden,
        "threats": threats,
        "risk_score": risk_score,
        "timestamp": datetime.datetime.utcnow().isoformat() + 'Z',
    }



# ─────────────────────────────────────────────────────────────
#  DISPLAY ENGINE

# ─────────────────────────────────────────────────────────────
TERM_WIDTH = min(os.get_terminal_size().columns if sys.stdout.isatty() else 80, 100)

def hr(ch='─', color=C.GRAY):
    print(c(ch * TERM_WIDTH, color))


def section(title: str, color=C.CYAN):
    print()
    print(c(f" {'═'*3} {title} {'═'*(TERM_WIDTH - len(title) - 6)}", color))


def label_val(label: str, val: str, lw=22):
    print(f"  {c(label.ljust(lw), C.GRAY)} {val}")



def print_banner():
    banner = r"""
  ███████╗██╗██╗     ███████╗███████╗██╗  ██╗██╗███████╗██╗     ██████╗
  ██╔════╝██║██║     ██╔════╝██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗
  █████╗  ██║██║     █████╗  ███████╗███████║██║█████╗  ██║     ██║  ██║
  ██╔══╝  ██║██║     ██╔══╝  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║
  ██║     ██║███████╗███████╗███████║██║  ██║██║███████╗███████╗██████╔╝
  ╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝"""
    print(c(banner, C.CYAN + C.BOLD))
    print(c(f"  {'Cyber Security File Analyzer':^{TERM_WIDTH-2}}", C.GRAY))
    print(c(f"  {'Magic Byte Detection • Entropy Analysis • Threat Intelligence':^{TERM_WIDTH-2}}", C.GRAY))
    print()


def fmt_size(n: int) -> str:
    if n < 1024: return f"{n} B"
    if n < 1024**2: return f"{n/1024:.1f} KB"
    if n < 1024**3: return f"{n/1024**2:.2f} MB"
    return f"{n/1024**3:.3f} GB"



def fmt_hex(data: bytes, per_row=16) -> list[str]:
    lines = []
    for i in range(0, len(data), per_row):
        chunk = data[i:i+per_row]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(chr(b) if 0x20 <= b < 0x7F else '.' for b in chunk)

        lines.append(f"  {c(f'{i:04X}', C.GRAY)}  {c(hex_part.ljust(per_row*3-1), C.CYAN)}  {c(ascii_part, C.GRAY)}")
    return lines


def entropy_bar(entropy: float, width: int = 40) -> str:
    pct = entropy / 8.0
    filled = int(pct * width)
    bar = '█' * filled + '░' * (width - filled)

    if entropy > 7.2:
        color = C.RED
    elif entropy > 6.0:
        color = C.YELLOW
    else:
        color = C.GREEN
    return f"{c(bar, color)} {c(f'{entropy:.4f}', color + C.BOLD)} bits/byte"


def risk_badge(score: int) -> str:
    if score >= 70:
        return c(f" ☠ CRITICAL  RISK: {score:02d}/99 ", C.BOLD + C.BG_RED + C.WHITE)
    elif score >= 40:
        return c(f" ⚠ HIGH      RISK: {score:02d}/99 ", C.BOLD + C.RED)
    elif score >= 15:
        return c(f" ! MEDIUM    RISK: {score:02d}/99 ", C.BOLD + C.YELLOW)
    else:
        return c(f" ✓ LOW       RISK: {score:02d}/99 ", C.BOLD + C.GREEN)



def print_result(r: dict, idx: int = 1, total: int = 1):
    if 'error' in r:
        print(c(f"\n  [ERROR] {r['error']}", C.RED))
        return

    hr('═')
    if total > 1:
        print(c(f"  FILE {idx}/{total}: {r['filename']}", C.BOLD + C.WHITE))
        hr('─')

    # ── File Info ──────────────────────────────────────────
    section("FILE INFORMATION")
    label_val("Name:", c(r['filename'], C.WHITE + C.BOLD))
    label_val("Path:", c(r['filepath'], C.GRAY))
    label_val("Size:", c(fmt_size(r['size']), C.WHITE))
    label_val("Extension:", c(f".{r['extension']}" if r['extension'] else "(none)", C.YELLOW))

    # Detected type
    det = r['detected']
    if det:
        risk_color = RISK_COLOR.get(det.get('risk','INFO'), C.CYAN)
        label_val("Detected Type:", c(det['label'], risk_color + C.BOLD))
        label_val("Category:", c(det['category'].upper(), risk_color))
        label_val("Inherent Risk:", c(f"{RISK_ICON.get(det.get('risk','INFO'),'')} {det.get('risk','INFO')}", risk_color))
    else:

        label_val("Detected Type:", c("UNKNOWN / Unrecognized", C.RED))

    # Mismatch flag
    if r['mismatch']:
        label_val("Ext vs Content:", c("⚠ MISMATCH — Extension does NOT match content!", C.RED + C.BOLD))
    else:
        label_val("Ext vs Content:", c("✓ Consistent", C.GREEN))


    if r['double_ext']:
        label_val("Double Extension:", c(f"⚠ YES ({' → '.join('.'+e for e in r['extensions'])})", C.RED))
    if r['dangerous_ext']:
        label_val("Dangerous Ext:", c(f"☠ YES (.{r['extension']} is executable/script)", C.RED + C.BOLD))
    if r['php_polyglot']:
        label_val("PHP Polyglot:", c("☠ PHP CODE DETECTED IN BINARY FILE!", C.RED + C.BOLD + C.BLINK))
    if r['pe_hidden']:
        label_val("Hidden PE:", c("☠ WINDOWS EXECUTABLE HIDDEN IN FILE!", C.RED + C.BOLD + C.BLINK))


    # ── Magic Bytes ────────────────────────────────────────
    section("MAGIC BYTES — FIRST 16 BYTES")
    for line in fmt_hex(r['first_bytes']):
        print(line)

    if det and det.get('magic'):
        magic_hex = ' '.join(f'{b:02X}' for b in det['magic'])
        print(f"\n  {c('Expected signature:', C.GRAY)} {c(magic_hex, C.CYAN + C.BOLD)}")

    # ── Entropy ────────────────────────────────────────────
    section("ENTROPY ANALYSIS")

    print(f"  {entropy_bar(r['entropy'])}")
    print()
    entropy = r['entropy']
    print(f"  {c('0.0–4.0', C.GREEN)}  Plain text, structured data")
    print(f"  {c('4.0–6.0', C.GREEN)}  Light compression / mixed content")
    print(f"  {c('6.0–7.2', C.YELLOW)}  Binary, media files")
    print(f"  {c('7.2–8.0', C.RED)}  {'← YOU ARE HERE  ' if entropy > 7.2 else ''}Packed / Encrypted / Obfuscated ⚠")
    if r['null_bytes'] > 3:
        nb = r['null_bytes']
        print(f"\n  {c(f'⚠ Null bytes detected: {nb} occurrences (possible null byte injection)', C.ORANGE)}")

    # ── Hashes ──────────────────────────────────────────────
    section("CRYPTOGRAPHIC HASHES")
    label_val("MD5:", c(r['hashes']['md5'], C.GRAY))
    label_val("SHA-1:", c(r['hashes']['sha1'], C.GRAY))
    label_val("SHA-256:", c(r['hashes']['sha256'], C.CYAN))
    print(c("\n  Tip: Paste SHA-256 vào VirusTotal.com để kiểm tra xem file đã bị báo cáo chưa.", C.GRAY))

    # ── Attack Vectors ─────────────────────────────────────

    if det and det.get('attack_vectors'):

        section("KNOWN ATTACK VECTORS FOR THIS FILE TYPE")
        for av in det['attack_vectors']:
            print(f"  {c('▸', C.ORANGE)} {av}")

    # ── Threats ────────────────────────────────────────────
    section("THREAT ANALYSIS")
    for t in r['threats']:

        level = t['level']
        color = RISK_COLOR.get(level, C.CYAN)
        icon = RISK_ICON.get(level, '•')
        print(f"\n  {c(f'[{icon} {level}]', color + C.BOLD)} {c(t['name'], C.WHITE + C.BOLD)}")

        # Word wrap detail
        detail = t['detail']
        print(f"  {c(detail, C.GRAY)}")


    # ── Verdict ────────────────────────────────────────────
    section("VERDICT")
    print(f"\n  {risk_badge(r['risk_score'])}")
    print()
    if r['risk_score'] >= 70:
        print(c("  ☠ DO NOT PROCESS THIS FILE — Immediate threat detected.", C.RED + C.BOLD))
        print(c("    Cách ly file, báo cáo cho security team, không upload lên bất kỳ server nào.", C.RED))
    elif r['risk_score'] >= 40:

        print(c("  ⚠ HIGH RISK — File này có dấu hiệu đáng ngờ nghiêm trọng.", C.ORANGE + C.BOLD))
        print(c("    Scan bằng antivirus, kiểm tra kỹ trước khi xử lý.", C.ORANGE))
    elif r['risk_score'] >= 15:
        print(c("  ! SUSPICIOUS — Cần review thêm trước khi chấp nhận file.", C.YELLOW + C.BOLD))
        print(c("    Validate content, kiểm tra metadata, scan virus.", C.YELLOW))
    else:
        print(c("  ✓ LOW RISK — Không phát hiện mối đe dọa rõ ràng.", C.GREEN + C.BOLD))
        print(c("    Vẫn nên scan antivirus và validate server-side.", C.GREEN))

    # ── Recommendations ────────────────────────────────────
    section("SECURITY RECOMMENDATIONS")
    recs = [
        ("🛡", "Validate file type bằng magic bytes, KHÔNG dùng extension — dùng python-magic hoặc file-type (Node.js)"),
        ("📁", "Lưu file upload ra ngoài webroot — không bao giờ để server execute file trong upload directory"),

        ("✂", "Rename file ngẫu nhiên khi lưu vào server, strip toàn bộ extension gốc"),
        ("🔒", "Serve file với header: Content-Disposition: attachment — ngăn browser tự render"),
        ("🔍", "Tích hợp ClamAV hoặc VirusTotal API để scan file trước khi lưu"),
        ("📏", "Giới hạn file size, whitelist MIME type, và set upload rate limiting"),
    ]
    if r['mismatch']:
        recs.insert(0, ("⛔", "KHẨN CẤP: Từ chối file này — extension không khớp nội dung, đây là dấu hiệu bypass attack"))
    if r['dangerous_ext']:
        recs.insert(0, ("⛔", f"KHẨN CẤP: Blacklist extension '.{r['extension']}' — không bao giờ cho phép upload loại này"))
    for icon, text in recs:
        print(f"  {icon} {c(text, C.GRAY)}")

    print()
    hr('═')


def print_summary(results: list):
    """Print summary table for multiple files."""

    if len(results) <= 1:

        return
    print()
    print(c(f"\n  {'SCAN SUMMARY':^{TERM_WIDTH-2}}", C.BOLD + C.WHITE))

    hr('─')

    header = f"  {'FILENAME':<35} {'EXT':<8} {'DETECTED TYPE':<28} {'RISK':>6}"
    print(c(header, C.GRAY))
    hr('─')
    for r in results:

        if 'error' in r:
            print(f"  {c(r.get('filename','?')[:33], C.GRAY):<35} {c('ERROR', C.RED)}")
            continue
        score = r['risk_score']

        color = C.RED if score >= 40 else C.YELLOW if score >= 15 else C.GREEN
        det_label = (r['detected']['label'][:26] if r['detected'] else 'UNKNOWN')
        ext = f".{r['extension']}" if r['extension'] else '-'
        fname = r['filename'][:33]
        print(f"  {c(fname, C.WHITE):<35} {c(ext, C.YELLOW):<8} {c(det_label, C.CYAN):<28} {c(str(score), color + C.BOLD):>6}")
    hr('─')
    total = len(results)
    high = sum(1 for r in results if 'error' not in r and r['risk_score'] >= 40)
    med = sum(1 for r in results if 'error' not in r and 15 <= r['risk_score'] < 40)
    low = sum(1 for r in results if 'error' not in r and r['risk_score'] < 15)
    print(f"\n  Total: {c(str(total), C.WHITE + C.BOLD)} files  "
          f"| {c(str(high), C.RED + C.BOLD)} HIGH/CRITICAL  "
          f"| {c(str(med), C.YELLOW + C.BOLD)} MEDIUM  "
          f"| {c(str(low), C.GREEN + C.BOLD)} LOW")


# ─────────────────────────────────────────────────────────────
#  RECOVERY ENGINE

# ─────────────────────────────────────────────────────────────

# Full recovery profiles — each defines: magic header to patch,
# minimum viable body structure, validation hints, and recovery strategy
RECOVERY_PROFILES = {
    # ── Images ───────────────────────────────────────────────
    "jpg": {

        "label": "JPEG Image",
        "ext": "jpg",

        "category": "image",
        "magic": bytes([0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01]),
        "magic_len": 12,
        "footer": bytes([0xFF, 0xD9]),  # EOI marker
        "min_size": 100,
        "indicators": ["ffd8", "jfif", "exif", "jpeg", "photo", "img", "camera"],
        "byte_hints": lambda raw: (
            raw[6:10] in (b'JFIF', b'Exif') or
            b'\xFF\xE1' in raw[:64] or   # APP1 segment
            b'\xFF\xDB' in raw[:128]     # DQT (quantization table)
        ),

        "entropy_range": (4.5, 8.0),
        "strategy": "Patch SOI marker (FF D8) + JFIF APP0 header. Giữ nguyên body data (Huffman tables, DCT blocks). Append EOI (FF D9) nếu thiếu.",
        "patchable": True,
        "patch_fn": "_patch_jpeg",

    },
    "png": {
        "label": "PNG Image",
        "ext": "png",
        "category": "image",
        "magic": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
        "magic_len": 8,
        "footer": bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),  # IEND chunk
        "min_size": 67,  # smallest valid PNG
        "indicators": ["png", "ihdr", "idat", "iend", "rgba", "image"],
        "byte_hints": lambda raw: (

            b'IHDR' in raw[:64] or
            b'IDAT' in raw or
            b'IEND' in raw[-32:]
        ),
        "entropy_range": (4.0, 8.0),
        "strategy": "Patch 8-byte PNG signature. Giữ nguyên IHDR/IDAT/IEND chunks. PNG dùng zlib compress nên không thể rebuild từ đầu.",
        "patchable": True,
        "patch_fn": "_patch_png",
    },
    "gif": {

        "label": "GIF Image",
        "ext": "gif",
        "category": "image",
        "magic": b"GIF89a",

        "magic_len": 6,
        "footer": bytes([0x3B]),  # GIF trailer
        "min_size": 35,

        "indicators": ["gif89", "gif87", "netscape", "animation", "lzw"],
        "byte_hints": lambda raw: (
            raw[3:6] in (b'87a', b'89a') or
            b'\x21\xF9' in raw[:256]  # GCE block

        ),
        "entropy_range": (3.5, 7.5),
        "strategy": "Patch GIF header (GIF89a + logical screen descriptor). Body LZW data giữ nguyên. Append trailer (0x3B) nếu thiếu.",
        "patchable": True,
        "patch_fn": "_patch_gif",
    },
    "bmp": {
        "label": "BMP Bitmap Image",

        "ext": "bmp",
        "category": "image",
        "magic": bytes([0x42, 0x4D]),
        "magic_len": 2,
        "footer": None,
        "min_size": 54,
        "indicators": ["bmp", "dib", "bitmap", "rgb", "pixel"],

        "byte_hints": lambda raw: (
            len(raw) > 10 and
            struct.unpack_from('<I', raw, 2)[0] if len(raw) >= 6 else False
        ),
        "entropy_range": (0.0, 7.0),
        "strategy": "Patch BM signature (42 4D) + rebuild file size field ở offset 2 dựa trên actual size. BITMAPINFOHEADER ở offset 14.",
        "patchable": True,
        "patch_fn": "_patch_bmp",
    },
    # ── Documents ─────────────────────────────────────────────
    "pdf": {
        "label": "PDF Document",
        "ext": "pdf",
        "category": "document",
        "magic": b"%PDF-1.",
        "magic_len": 7,
        "footer": b"%%EOF",
        "min_size": 67,
        "indicators": ["pdf", "obj", "endobj", "stream", "xref", "trailer", "startxref", "page"],
        "byte_hints": lambda raw: (

            b'obj' in raw or
            b'stream' in raw or
            b'endstream' in raw or
            b'xref' in raw or
            b'%%EOF' in raw[-128:]
        ),
        "entropy_range": (3.0, 8.0),
        "strategy": "Patch %PDF-1.x header. Nếu có xref table và trailer trong body → file có thể parse được. Append %%EOF nếu thiếu. Dùng PDF reader để verify sau khi patch.",
        "patchable": True,
        "patch_fn": "_patch_pdf",
    },
    # ── Archives ──────────────────────────────────────────────

    "zip": {
        "label": "ZIP Archive",
        "ext": "zip",
        "category": "archive",
        "magic": bytes([0x50, 0x4B, 0x03, 0x04]),
        "magic_len": 4,
        "footer": bytes([0x50, 0x4B, 0x05, 0x06]),  # EOCD signature
        "min_size": 22,
        "indicators": ["zip", "pk", "deflate", "stored", "local file", "central dir"],
        "byte_hints": lambda raw: (
            b'PK\x01\x02' in raw or   # Central directory
            b'PK\x05\x06' in raw or   # EOCD
            b'PK\x03\x04' in raw[4:]  # Another local file header later
        ),

        "entropy_range": (5.0, 8.0),
        "strategy": "Patch Local File Header signature (PK 03 04) ở đầu. ZIP structure: Local headers → file data → Central Directory → EOCD. Nếu Central Dir còn nguyên (PK 01 02) thì recovery khả thi cao.",
        "patchable": True,
        "patch_fn": "_patch_zip",
    },
    "gz": {
        "label": "GZIP Compressed File",
        "ext": "gz",
        "category": "archive",
        "magic": bytes([0x1F, 0x8B, 0x08]),
        "magic_len": 3,
        "footer": None,

        "min_size": 18,
        "indicators": ["gz", "gzip", "deflate", "compressed"],
        "byte_hints": lambda raw: len(raw) > 10 and raw[2] == 0x08,

        "entropy_range": (6.0, 8.0),
        "strategy": "Patch GZIP magic (1F 8B) + CM byte (08 = deflate). Header gồm 10 bytes. Body là deflate stream, footer là CRC32 + size. Chỉ patch header, body và CRC giữ nguyên.",
        "patchable": True,
        "patch_fn": "_patch_gz",
    },
    # ── Media ─────────────────────────────────────────────────

    "mp3": {
        "label": "MP3 Audio",
        "ext": "mp3",

        "category": "media",
        "magic": bytes([0xFF, 0xFB]),
        "magic_len": 2,
        "footer": None,
        "min_size": 128,

        "indicators": ["id3", "mp3", "mpeg", "audio", "lame", "vbr", "cbr", "tag"],
        "byte_hints": lambda raw: (
            raw[:3] == b'ID3' or          # ID3v2 tag
            raw[-128:-125] == b'TAG' or   # ID3v1 tag at end
            b'LAME' in raw[:512] or
            b'Info' in raw[:512] or
            (len(raw) > 4 and raw[0] == 0xFF and (raw[1] & 0xE0) == 0xE0)
        ),
        "entropy_range": (5.0, 8.0),
        "strategy": "MP3 không có fixed magic nếu không có ID3 tag. Nếu có ID3v2 ở đầu → patch 'ID3'. Nếu không → tìm sync word FF FB/FD/FA trong body và strip garbage ở đầu.",
        "patchable": True,
        "patch_fn": "_patch_mp3",
    },

    "wav": {
        "label": "WAV Audio",
        "ext": "wav",
        "category": "media",
        "magic": bytes([0x52, 0x49, 0x46, 0x46]),  # RIFF
        "magic_len": 4,
        "footer": None,
        "min_size": 44,
        "indicators": ["riff", "wave", "fmt ", "data", "audio", "pcm", "wav"],
        "byte_hints": lambda raw: (
            b'WAVE' in raw[:16] or
            b'fmt ' in raw[:64] or
            b'data' in raw[:64]
        ),
        "entropy_range": (5.0, 8.0),
        "strategy": "Patch RIFF signature (52 49 46 46) + rebuild chunk size ở offset 4 (file_size - 8). 'WAVE' marker ở offset 8. fmt chunk ở offset 12 chứa audio format info.",
        "patchable": True,
        "patch_fn": "_patch_wav",
    },
    "mp4": {
        "label": "MP4 Video",
        "ext": "mp4",
        "category": "media",
        "magic": bytes([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70]),  # ftyp box
        "magic_len": 8,
        "footer": None,
        "min_size": 1024,
        "indicators": ["ftyp", "moov", "mdat", "mp4", "isom", "avc1", "mp41", "mp42"],
        "byte_hints": lambda raw: (
            b'ftyp' in raw[:32] or
            b'moov' in raw or
            b'mdat' in raw or
            b'isom' in raw[:64]

        ),
        "entropy_range": (6.5, 8.0),
        "strategy": "MP4 dùng box/atom structure. Nếu 'moov' atom còn nguyên → file có thể play được sau khi patch ftyp. Rebuild ftyp box (20 bytes) ở đầu file.",
        "patchable": True,
        "patch_fn": "_patch_mp4",

    },
    # ── Text/Scripts ──────────────────────────────────────────

    "xml": {
        "label": "XML Document",
        "ext": "xml",
        "category": "text",
        "magic": b"<?xml",
        "magic_len": 5,
        "footer": None,
        "min_size": 10,
        "indicators": ["xml", "<?xml", "xmlns", "<root", "</", "/>", "encoding"],
        "byte_hints": lambda raw: (
            b'<?xml' in raw[:64] or
            b'xmlns' in raw[:512] or
            b'</' in raw

        ),
        "entropy_range": (3.5, 6.0),
        "strategy": "Patch XML declaration header (<?xml version=\"1.0\"?>). Body là text nên thường còn readable. Verify well-formedness bằng XML parser sau khi patch.",
        "patchable": True,
        "patch_fn": "_patch_xml",
    },
    "html": {
        "label": "HTML Document",
        "ext": "html",
        "category": "text",
        "magic": b"<!DOCTYPE html>",
        "magic_len": 15,
        "footer": b"</html>",
        "min_size": 20,
        "indicators": ["html", "doctype", "<head", "<body", "<div", "<html", "charset", "http-equiv"],
        "byte_hints": lambda raw: (
            b'<html' in raw[:256] or
            b'<head' in raw[:256] or

            b'<body' in raw[:512] or
            b'DOCTYPE' in raw[:64]
        ),
        "entropy_range": (3.5, 6.5),
        "strategy": "Prepend DOCTYPE declaration. HTML parser tolerant với malformed input, nên recovery thường thành công. Append </html> nếu thiếu.",
        "patchable": True,

        "patch_fn": "_patch_html",
    },
    "sqlite": {
        "label": "SQLite Database",
        "ext": "db",

        "category": "data",
        "magic": b"SQLite format 3\x00",
        "magic_len": 16,
        "footer": None,
        "min_size": 100,
        "indicators": ["sqlite", "sql", "table", "create", "insert", "select", "database"],
        "byte_hints": lambda raw: (
            b'SQLite' in raw[:20] or

            b'CREATE TABLE' in raw or
            b'sqlite_master' in raw
        ),

        "entropy_range": (2.0, 7.0),
        "strategy": "Patch SQLite3 header (16 bytes: 'SQLite format 3\\x00'). Page size ở offset 16, format versions ở 18-19. Sau khi patch header, dùng 'sqlite3 .recover' để extract data.",
        "patchable": True,

        "patch_fn": "_patch_sqlite",
    },
}

# ── Scoring weights cho từng hint ──────────────────────────
def _score_recovery_candidate(raw: bytes, size: int, ext: str, profile: dict) -> float:

    """
    Tính confidence score (0.0–1.0) cho một recovery candidate.
    Kết hợp nhiều signal: byte hints, string indicators, entropy, size, extension match.
    """
    score = 0.0
    total_weight = 0.0


    # 1. Byte-level structural hints (weight: 40%)
    if profile.get("byte_hints"):

        try:

            if profile["byte_hints"](raw):
                score += 0.40
        except Exception:
            pass
    total_weight += 0.40

    # 2. String indicators trong file body (weight: 25%)
    raw_lower = raw.lower()
    indicators = profile.get("indicators", [])
    if indicators:
        matches = sum(1 for ind in indicators if ind.encode() in raw_lower)
        indicator_score = min(matches / max(len(indicators) * 0.4, 1), 1.0) * 0.25
        score += indicator_score

    total_weight += 0.25


    # 3. Entropy range (weight: 15%)
    entropy = shannon_entropy(raw[:4096])
    lo, hi = profile.get("entropy_range", (0, 8))

    if lo <= entropy <= hi:
        # Bonus nếu entropy nằm gần giữa range
        mid = (lo + hi) / 2
        closeness = 1.0 - abs(entropy - mid) / max((hi - lo) / 2, 0.1)
        score += closeness * 0.15
    total_weight += 0.15

    # 4. File size minimum (weight: 10%)
    if size >= profile.get("min_size", 0):
        score += 0.10

    total_weight += 0.10


    # 5. Extension match (weight: 10%)
    if ext and ext in profile.get("indicators", []):
        score += 0.10
    elif ext and profile.get("ext") == ext:
        score += 0.10

    total_weight += 0.10


    # Normalize về 0–1
    return min(score / total_weight if total_weight > 0 else 0, 1.0)


def suggest_recovery(filepath: str) -> list[dict]:

    """
    Phân tích corrupted file và trả về list các recovery candidates
    được sắp xếp theo confidence score (cao → thấp).
    Chỉ trả về candidates có confidence >= 5%.
    """
    path = pathlib.Path(filepath)
    if not path.exists():
        return []


    size = path.stat().st_size
    raw = read_bytes(filepath, min(size, 65536))
    ext = path.suffix.lstrip('.').lower()

    candidates = []

    for type_key, profile in RECOVERY_PROFILES.items():
        conf = _score_recovery_candidate(raw, size, ext, profile)

        if conf >= 0.05:  # threshold: 5%
            candidates.append({
                "type_key": type_key,
                "label": profile["label"],
                "ext": profile["ext"],
                "category": profile["category"],
                "confidence": conf,
                "confidence_pct": round(conf * 100, 1),
                "strategy": profile["strategy"],
                "patchable": profile.get("patchable", False),
                "magic_hex": profile["magic"].hex(' ').upper()[:47],
            })

    candidates.sort(key=lambda x: x["confidence"], reverse=True)
    return candidates



# ── PATCH FUNCTIONS — mỗi format có cách repair riêng ──────

def _patch_jpeg(data: bytes, size: int) -> bytes:
    """Patch JPEG: replace/insert SOI + APP0 JFIF header."""
    # Tìm xem body có JPEG data không (FF DB, FF C0, FF DA...)
    body = data
    # Strip garbage prefix nếu có
    for i in range(min(len(data), 512)):
        if data[i:i+2] == b'\xFF\xDB' or data[i:i+2] == b'\xFF\xC0':

            body = data[i:]
            break
    header = bytes([
        0xFF, 0xD8,  # SOI
        0xFF, 0xE0,  # APP0 marker
        0x00, 0x10,  # APP0 length = 16
        0x4A, 0x46, 0x49, 0x46, 0x00,  # "JFIF\0"
        0x01, 0x01,  # version 1.1
        0x00,        # aspect ratio units = 0
        0x00, 0x01,  # X density
        0x00, 0x01,  # Y density
        0x00, 0x00,  # thumbnail size
    ])
    # Ensure EOI at end
    result = header + body
    if not result.endswith(b'\xFF\xD9'):
        result += b'\xFF\xD9'
    return result


def _patch_png(data: bytes, size: int) -> bytes:

    """Patch PNG: replace first 8 bytes với PNG signature."""
    PNG_SIG = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
    body = data[8:] if len(data) >= 8 else data
    result = PNG_SIG + body
    if b'IEND' not in result[-32:]:
        # Append minimal IEND chunk (12 bytes)
        import zlib
        iend_crc = zlib.crc32(b'IEND') & 0xFFFFFFFF
        result += struct.pack('>I', 0) + b'IEND' + struct.pack('>I', iend_crc)
    return result


def _patch_gif(data: bytes, size: int) -> bytes:
    """Patch GIF: replace header + minimal logical screen descriptor."""
    header = b'GIF89a'
    # Try to preserve LSD if it's there
    body = data[6:] if len(data) > 6 else b'\x00' * 7
    result = header + body
    if not result.endswith(b'\x3B'):
        result += b'\x3B'
    return result


def _patch_bmp(data: bytes, size: int) -> bytes:
    """Patch BMP: fix BM signature và file size field."""
    file_size = len(data)
    result = bytearray(data)
    result[0] = 0x42  # 'B'
    result[1] = 0x4D  # 'M'
    # File size at offset 2, little-endian 4 bytes
    if len(result) >= 6:
        struct.pack_into('<I', result, 2, file_size)
    return bytes(result)


def _patch_pdf(data: bytes, size: int) -> bytes:
    """Patch PDF: fix %PDF header, detect version từ body, ensure %%EOF."""
    # Try to detect PDF version from body

    version = b"1.4"
    for v in [b"1.0", b"1.1", b"1.2", b"1.3", b"1.4", b"1.5", b"1.6", b"1.7", b"2.0"]:
        if v in data[:256]:
            version = v
            break
    header = b"%PDF-" + version + b"\n%\xe2\xe3\xcf\xd3\n"
    # Strip old header if present
    body = data
    if data.startswith(b'%PDF'):
        nl = data.find(b'\n')
        body = data[nl+1:] if nl > 0 else data[8:]

    result = header + body
    if not result.rstrip().endswith(b'%%EOF'):
        result += b'\n%%EOF\n'

    return result


def _patch_zip(data: bytes, size: int) -> bytes:
    """Patch ZIP: fix Local File Header signature."""
    result = bytearray(data)
    result[0] = 0x50  # 'P'
    result[1] = 0x4B  # 'K'
    result[2] = 0x03
    result[3] = 0x04
    return bytes(result)



def _patch_gz(data: bytes, size: int) -> bytes:

    """Patch GZIP: fix magic bytes + CM byte."""
    result = bytearray(data)
    result[0] = 0x1F
    result[1] = 0x8B
    if len(result) > 2:
        result[2] = 0x08  # CM = deflate
    return bytes(result)


def _patch_mp3(data: bytes, size: int) -> bytes:
    """Patch MP3: add ID3v2 header or find sync word."""
    # Check if ID3 tag exists somewhere in first 512 bytes
    idx = data.find(b'ID3')
    if idx > 0:
        return data[idx:]  # Strip garbage before ID3

    # Look for MPEG sync word (FF FB, FF FA, FF F3, etc.)
    for i in range(min(len(data) - 1, 8192)):
        if data[i] == 0xFF and (data[i+1] & 0xE0) == 0xE0:
            return data[i:]  # Strip garbage prefix
    # Fallback: prepend minimal ID3v2 header
    id3_header = bytearray([
        0x49, 0x44, 0x33,  # "ID3"
        0x03, 0x00,         # version 2.3.0
        0x00,               # flags
        0x00, 0x00, 0x00, 0x00,  # size (syncsafe int) = 0
    ])
    return bytes(id3_header) + data


def _patch_wav(data: bytes, size: int) -> bytes:
    """Patch WAV: fix RIFF header + file size + WAVE marker."""
    result = bytearray(data)
    result[0] = 0x52  # 'R'
    result[1] = 0x49  # 'I'
    result[2] = 0x46  # 'F'
    result[3] = 0x46  # 'F'
    # Chunk size = file_size - 8
    if len(result) >= 8:
        struct.pack_into('<I', result, 4, max(0, len(result) - 8))
    # WAVE marker at offset 8
    if len(result) >= 12:
        result[8] = 0x57   # 'W'
        result[9] = 0x41   # 'A'
        result[10] = 0x56  # 'V'
        result[11] = 0x45  # 'E'
    return bytes(result)



def _patch_mp4(data: bytes, size: int) -> bytes:
    """Patch MP4: prepend/fix ftyp box."""

    # Check if ftyp exists somewhere early
    idx = data.find(b'ftyp')

    if 0 < idx <= 8:
        # Fix box size
        result = bytearray(data)
        ftyp_size = struct.unpack_from('>I', data, idx - 4)[0] if idx >= 4 else 20
        return bytes(result)
    # Prepend minimal ftyp box
    ftyp_box = struct.pack('>I', 20) + b'ftyp' + b'isom' + struct.pack('>I', 0) + b'isom'
    return ftyp_box + data



def _patch_xml(data: bytes, size: int) -> bytes:
    """Patch XML: prepend declaration."""
    if data.lstrip().startswith(b'<?xml'):
        return data
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + data


def _patch_html(data: bytes, size: int) -> bytes:
    """Patch HTML: prepend DOCTYPE, append </html> if missing."""
    result = data
    if not data.lstrip().lower().startswith(b'<!doctype'):
        result = b'<!DOCTYPE html>\n' + result
    if b'</html>' not in result[-64:].lower():
        result += b'\n</html>'
    return result


def _patch_sqlite(data: bytes, size: int) -> bytes:
    """Patch SQLite3: fix 16-byte header magic."""
    result = bytearray(data)
    header = b'SQLite format 3\x00'
    for i, b in enumerate(header):
        if i < len(result):

            result[i] = b
    return bytes(result)


# Dispatch table
PATCH_DISPATCH = {

    "jpg": _patch_jpeg, "png": _patch_png, "gif": _patch_gif,
    "bmp": _patch_bmp, "pdf": _patch_pdf, "zip": _patch_zip,
    "gz": _patch_gz, "mp3": _patch_mp3, "wav": _patch_wav,
    "mp4": _patch_mp4, "xml": _patch_xml, "html": _patch_html,
    "sqlite": _patch_sqlite,
}



def do_recover(filepath: str, target_type: str, output_path: str) -> dict:
    """
    Thực hiện recovery: đọc file corrupt, apply patch function,

    ghi ra output_path. Trả về kết quả với status và stats.

    """
    profile = RECOVERY_PROFILES.get(target_type)
    if not profile:
        return {"success": False, "error": f"Unknown recovery type: {target_type}"}

    patch_fn = PATCH_DISPATCH.get(target_type)
    if not patch_fn:

        return {"success": False, "error": f"No patch function for type: {target_type}"}

    path = pathlib.Path(filepath)
    size = path.stat().st_size
    raw = path.read_bytes()

    try:
        patched = patch_fn(raw, size)
    except Exception as e:
        return {"success": False, "error": f"Patch failed: {e}"}


    out_path = pathlib.Path(output_path)

    out_path.write_bytes(patched)


    # Verify: check if new magic bytes match expected
    expected_magic = profile["magic"][:min(8, len(profile["magic"]))]

    actual_magic = patched[:len(expected_magic)]

    magic_ok = actual_magic == expected_magic

    return {
        "success": True,
        "output_path": str(out_path),
        "original_size": size,
        "patched_size": len(patched),
        "size_delta": len(patched) - size,
        "magic_verified": magic_ok,
        "expected_magic": expected_magic.hex(' ').upper(),
        "actual_magic": actual_magic.hex(' ').upper(),
        "profile": profile["label"],
    }



# ── DISPLAY: Recovery ───────────────────────────────────────

def print_recovery_suggestions(filepath: str, candidates: list):

    """Hiển thị danh sách recovery possibilities đẹp."""
    print()
    hr('═')
    print(c(f"  ◈ CORRUPTED FILE RECOVERY ANALYZER", C.CYAN + C.BOLD))
    print(c(f"  File: {filepath}", C.GRAY))
    hr('─')

    if not candidates:
        print(c("\n  ✗ Không thể xác định loại file. File có thể bị corrupt hoàn toàn hoặc bị encrypt.", C.RED))
        print(c("  Thử: hexdump -C file | head -20   để xem raw bytes\n", C.GRAY))
        return

    path = pathlib.Path(filepath)
    size = path.stat().st_size
    raw = read_bytes(filepath, min(size, 4096))
    entropy = shannon_entropy(raw)

    print(c(f"\n  File size: {fmt_size(size)}  |  Entropy: {entropy:.3f} bits/byte\n", C.GRAY))
    print(c(f"  Tìm thấy {len(candidates)} khả năng recovery (sắp xếp theo độ chính xác):\n", C.WHITE))

    # Confidence bar helper
    def conf_bar(pct, width=20):
        filled = int(pct / 100 * width)
        bar = '█' * filled + '░' * (width - filled)
        col = C.GREEN if pct >= 60 else C.YELLOW if pct >= 30 else C.ORANGE
        return c(bar, col) + c(f" {pct:5.1f}%", col + C.BOLD)

    for i, cand in enumerate(candidates, 1):
        pct = cand["confidence_pct"]
        col = C.GREEN if pct >= 60 else C.YELLOW if pct >= 30 else C.ORANGE

        rank_icon = "◆" if i == 1 else "◇"
        rank_col  = C.CYAN if i == 1 else C.GRAY

        print(f"  {c(rank_icon, rank_col + C.BOLD)} {c(str(i) + '.', C.WHITE + C.BOLD)} "
              f"{c(cand['label'], C.WHITE + C.BOLD):<35}"
              f"  [{cand['category'].upper():<10}]")


        print(f"       Confidence:  {conf_bar(pct)}")
        print(f"       Extension:   {c('.' + cand['ext'], C.YELLOW)}")
        print(f"       Magic Bytes: {c(cand['magic_hex'], C.CYAN)}")
        patchable = c("✓ YES", C.GREEN) if cand["patchable"] else c("✗ NO (manual needed)", C.RED)
        print(f"       Auto-patch:  {patchable}")
        print()

        # Show strategy indented
        strat_lines = cand["strategy"].split('. ')

        for line in strat_lines:
            if line.strip():
                print(f"       {c('▸', C.GRAY)} {c(line.strip().rstrip('.') + '.', C.GRAY)}")
        print()

        if i < len(candidates):
            print(f"  {c('·' * (TERM_WIDTH - 4), C.GRAY)}")
            print()

    hr('─')
    print(c(f"\n  Để thực hiện recovery, chạy lại với flag --as:\n", C.WHITE))


    best = candidates[0]
    fname = pathlib.Path(filepath).stem
    print(f"  {c('# Best guess (highest confidence):', C.GRAY)}")
    print(f"  {c('python3 fileshield.py', C.CYAN)} --recover {c(filepath, C.WHITE)} "
          f"--as {c(best['ext'], C.YELLOW + C.BOLD)}")
    print()
    print(f"  {c('# Chỉ định output path:', C.GRAY)}")
    print(f"  {c('python3 fileshield.py', C.CYAN)} --recover {c(filepath, C.WHITE)} "
          f"--as {c(best['ext'], C.YELLOW + C.BOLD)} --output {c(fname + '_recovered.' + best['ext'], C.GREEN)}")

    print()


    if len(candidates) > 1:
        print(f"  {c('# Thử lựa chọn khác:', C.GRAY)}")
        for cand in candidates[1:3]:

            comment = f"# {cand['label']} ({cand['confidence_pct']}%)"
            print(f"  {c('python3 fileshield.py', C.CYAN)} --recover {c(filepath, C.WHITE)} "
                  f"--as {c(cand['ext'], C.YELLOW)}"
                  f"  {c(comment, C.GRAY)}")
    print()
    hr('═')


def print_recovery_result(result: dict, output_path: str):
    """Hiển thị kết quả sau khi patch."""
    print()
    hr('═')
    if not result["success"]:
        print(c(f"\n  ✗ RECOVERY FAILED: {result['error']}", C.RED + C.BOLD))
        hr('═')
        return


    print(c(f"  ✓ RECOVERY COMPLETE", C.GREEN + C.BOLD))

    hr('─')

    print()

    label_val("Profile used:", c(result["profile"], C.CYAN))
    label_val("Output file:", c(result["output_path"], C.WHITE + C.BOLD))
    label_val("Original size:", c(fmt_size(result["original_size"]), C.GRAY))
    label_val("Patched size:", c(fmt_size(result["patched_size"]), C.WHITE))
    delta = result["size_delta"]
    delta_str = (f"+{delta}" if delta >= 0 else str(delta)) + " bytes"

    label_val("Size delta:", c(delta_str, C.GREEN if delta >= 0 else C.YELLOW))
    print()

    magic_ok = result["magic_verified"]
    label_val("Magic verified:", c("✓ PASS — Header patched correctly", C.GREEN + C.BOLD) if magic_ok
                                else c("⚠ WARN — Magic mismatch, check manually", C.YELLOW))
    label_val("Expected magic:", c(result["expected_magic"], C.CYAN))

    label_val("Actual magic:", c(result["actual_magic"], C.CYAN if magic_ok else C.RED))
    print()
    hr('─')
    print(c("\n  NEXT STEPS:\n", C.WHITE + C.BOLD))
    print(f"  {c('1.', C.CYAN)} Mở file bằng ứng dụng phù hợp để kiểm tra xem có mở được không")
    print(f"  {c('2.', C.CYAN)} Nếu file vẫn lỗi: body data có thể bị corrupt, không chỉ header")
    print(f"  {c('3.', C.CYAN)} Thử tool chuyên biệt: PhotoRec, Recuva, TestDisk cho deep recovery")
    print(f"  {c('4.', C.CYAN)} Scan file đã recover: {c('python3 fileshield.py ' + result['output_path'], C.GRAY)}")
    print()
    hr('═')


# ─────────────────────────────────────────────────────────────
#  MAIN CLI
# ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        prog='fileshield',
        description='FileShield — Cybersecurity File Type Identifier & Threat Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,

        epilog="""

── SCAN MODE ──────────────────────────────────────────────────────
  python3 fileshield.py photo.jpg
  python3 fileshield.py malware.exe.jpg shell.php
  python3 fileshield.py -d /var/www/uploads
  python3 fileshield.py document.pdf --export report.json

  python3 fileshield.py *.* --no-color --quiet

── RECOVERY MODE ──────────────────────────────────────────────────

  python3 fileshield.py --recover broken.dat
      → Analyze & list all possible file types with confidence %


  python3 fileshield.py --recover broken.dat --as jpg

      → Auto-patch header to recover as JPEG

  python3 fileshield.py --recover broken.dat --as pdf --output fixed.pdf
      → Patch & save to specific output path

  python3 fileshield.py --list-types
      → Show all supported recovery types
        """
    )
    parser.add_argument('files', nargs='*', help='File(s) to analyze')
    parser.add_argument('-d', '--dir', help='Scan entire directory recursively')
    parser.add_argument('--export', metavar='OUTPUT.json', help='Export results to JSON file')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output (for piping)')
    parser.add_argument('--quiet', '-q', action='store_true', help='Show only verdict (minimal output)')
    parser.add_argument('--dangerous-only', action='store_true', help='Only show files with risk score >= 40')

    # Recovery mode args
    parser.add_argument('--recover', metavar='FILE',

                        help='Analyze corrupted file and suggest recovery options')

    parser.add_argument('--as', dest='recover_as', metavar='TYPE',
                        help='Recovery type to apply (jpg, png, pdf, zip, mp3, wav, mp4, gif, bmp, gz, xml, html, sqlite)')
    parser.add_argument('--output', metavar='OUTPUT_FILE',

                        help='Output path for recovered file (default: <original>_recovered.<ext>)')
    parser.add_argument('--list-types', action='store_true',
                        help='List all supported recovery types and their magic bytes')

    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():

        C.disable()

    print_banner()

    # ── --list-types mode ─────────────────────────────────
    if args.list_types:
        print(c("  SUPPORTED RECOVERY TYPES\n", C.CYAN + C.BOLD))
        hr('─')
        header = f"  {'KEY':<10} {'LABEL':<30} {'EXT':<6} {'CATEGORY':<12} {'MAGIC (HEX)'}"
        print(c(header, C.GRAY))
        hr('─')
        for key, p in RECOVERY_PROFILES.items():

            magic_hex = p['magic'].hex(' ').upper()[:32]
            print(f"  {c(key, C.YELLOW + C.BOLD):<10} {c(p['label'], C.WHITE):<30} "
                  f"{c('.' + p['ext'], C.GREEN):<6} {c(p['category'], C.GRAY):<12} "
                  f"{c(magic_hex, C.CYAN)}")
        print()
        hr('─')
        print(c(f"\n  Usage: python3 fileshield.py --recover <file> --as <KEY>\n", C.GRAY))
        sys.exit(0)

    # ── --recover mode ────────────────────────────────────
    if args.recover:
        fp = args.recover

        if not pathlib.Path(fp).exists():
            print(c(f"\n  [ERROR] File không tồn tại: {fp}", C.RED))
            sys.exit(1)


        # If user specified --as → do the actual recovery
        if args.recover_as:
            target_type = args.recover_as.lower().lstrip('.')
            if target_type not in RECOVERY_PROFILES:
                print(c(f"\n  [ERROR] Unknown type: '{target_type}'. Dùng --list-types để xem danh sách.", C.RED))
                print(c(f"  Supported: {', '.join(RECOVERY_PROFILES.keys())}", C.GRAY))
                sys.exit(1)

            profile = RECOVERY_PROFILES[target_type]
            # Determine output path
            if args.output:
                out_path = args.output
            else:
                stem = pathlib.Path(fp).stem
                out_path = f"{stem}_recovered.{profile['ext']}"

            print(c(f"\n  Recovering '{fp}' as {profile['label']}...", C.CYAN))
            print(c(f"  Output: {out_path}", C.GRAY))
            print()

            result = do_recover(fp, target_type, out_path)
            print_recovery_result(result, out_path)
            sys.exit(0 if result["success"] else 1)

        # No --as → analyze and suggest
        else:
            candidates = suggest_recovery(fp)
            print_recovery_suggestions(fp, candidates)

            # If there are candidates, also run security scan on original file
            if candidates:
                print(c("\n  ── SECURITY SCAN (original file) ──────────────────────────────", C.GRAY))
                r = analyze(fp)
                print_result(r, 1, 1)
            sys.exit(0)


    # Collect files
    targets = []
    if args.dir:
        d = pathlib.Path(args.dir)
        if not d.is_dir():
            print(c(f"  [ERROR] Không tìm thấy directory: {args.dir}", C.RED))
            sys.exit(1)
        targets = [str(f) for f in sorted(d.rglob('*')) if f.is_file()]
        print(c(f"  Scanning directory: {args.dir} ({len(targets)} files found)\n", C.GRAY))
    elif args.files:
        targets = args.files
    else:
        parser.print_help()

        sys.exit(0)


    if not targets:
        print(c("  Không tìm thấy file nào để scan.", C.YELLOW))
        sys.exit(0)

    # Analyze

    results = []
    for i, fp in enumerate(targets, 1):

        if args.quiet:
            r = analyze(fp)
            if not args.dangerous_only or r.get('risk_score', 0) >= 40:
                score = r.get('risk_score', 0)
                col = C.RED if score >= 40 else C.YELLOW if score >= 15 else C.GREEN
                fn = r.get('filename', fp)
                print(f"  {c(fn, C.WHITE):<50} {risk_badge(score)}")
            results.append(r)
        else:
            r = analyze(fp)
            if not args.dangerous_only or r.get('risk_score', 0) >= 40:
                print_result(r, i, len(targets))
            results.append(r)


    # Summary
    if not args.quiet:
        print_summary(results)

    # Export JSON

    if args.export:
        out = []
        for r in results:
            rec = dict(r)
            rec['first_bytes'] = r['first_bytes'].hex() if isinstance(r.get('first_bytes'), bytes) else ''
            if rec.get('detected') and rec['detected'].get('magic'):
                rec['detected'] = dict(rec['detected'])
                rec['detected']['magic'] = rec['detected']['magic'].hex()
            out.append(rec)
        with open(args.export, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(c(f"\n  [✓] Report exported → {args.export}", C.GREEN + C.BOLD))

    # Exit code: non-zero if any high-risk file
    high_risk = any(r.get('risk_score', 0) >= 40 for r in results if 'error' not in r)
    sys.exit(1 if high_risk else 0)


if __name__ == '__main__':
    main()
