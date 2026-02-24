<div align="center">

<img src="https://img.shields.io/badge/FileShield-v2.0-00e5ff?style=for-the-badge&labelColor=020508" alt="FileShield">

# ⬡ FileShield


### Fast and accurate **magic-byte file type detection** & **security threat analysis** — no external dependencies

<br>

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-00e5ff?style=flat-square)](LICENSE)

[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-00ff9d?style=flat-square)](#installation)
[![Platforms](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-gray?style=flat-square)](#installation)
[![Security](https://img.shields.io/badge/Focus-CyberSecurity-ff3d71?style=flat-square)](#threat-detection)
[![Recovery](https://img.shields.io/badge/Feature-File%20Recovery-ffaa00?style=flat-square)](#file-recovery)

<br>

**FileShield** is a cybersecurity-focused file type identifier that analyzes files based on their **magic bytes** and binary structure — not their extension. It detects extension spoofing, polyglot webshells, hidden executables, null byte injections, packed malware, and more. It also features an intelligent **corrupted file recovery engine** that suggests and applies header patches to repair broken files.

<br>

> FileShield is used to validate file uploads, scan untrusted content, and recover corrupted assets in security-sensitive workflows.

<br>

[**Try it now**](#quick-start) · [**Features**](#features) · [**Recovery Engine**](#file-recovery) · [**How it works**](#how-it-works) · [**Threat Reference**](#threat-reference)

</div>

---

## Overview

Attackers routinely exploit file extension trust to bypass server-side upload filters — renaming `shell.php` as `shell.jpg`, injecting PHP code into PNG headers (polyglot webshells), or hiding Windows executables inside seemingly harmless files. **FileShield** counters this by reading the first bytes of every file and matching them against a database of binary signatures, independently of the declared extension.

```
$ python3 fileshield.py webshell.png malware.exe.jpg suspicious.dat

  FILE 1/3: webshell.png
  Detected Type:   Plain Text / ASCII
  Category:        TEXT
  Ext vs Content:  ⚠ MISMATCH — Extension does NOT match content!
  PHP Polyglot:    ☠ PHP CODE DETECTED IN BINARY FILE!

  [☠ CRITICAL] RISK: 85/99 — DO NOT PROCESS THIS FILE


  FILE 2/3: malware.exe.jpg
  Detected Type:   Windows PE Executable (MZ)
  Double Extension: ⚠ YES (.exe → .jpg)

  Dangerous Ext:   ☠ YES (.exe is executable/script)

  [☠ CRITICAL] RISK: 95/99 — DO NOT PROCESS THIS FILE
```

---

## Features

- **Magic byte detection** — Identifies file types from binary signatures (30+ formats), ignoring declared extensions
- **Extension mismatch detection** — Flags files whose extension doesn't match their actual binary content
- **PHP polyglot / webshell detection** — Finds `<?php` code embedded inside binary files (images, archives, etc.)
- **Hidden PE detection** — Detects Windows `MZ` executables masquerading as other file types
- **Double extension detection** — Catches `malware.php.jpg`, `virus.exe.png` patterns

- **Null byte injection detection** — Identifies `shell.php%00.jpg` truncation attacks

- **Shannon entropy analysis** — Flags packed, encrypted, or obfuscated files (entropy > 7.2 bits/byte)
- **Cryptographic hashing** — Computes MD5, SHA-1, SHA-256 for VirusTotal lookup
- **Corrupted file recovery** — Suggests probable file type from partial content, then patches headers to restore them
- **Directory scanning** — Recursively scan entire upload directories
- **JSON export** — Machine-readable reports for SIEM / pipeline integration
- **Zero dependencies** — Pure Python 3 stdlib only. No `pip install` required.

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/yourname/fileshield.git
cd fileshield

# Run immediately — no installation needed
python3 fileshield.py <file>
```

**Requirements:** Python 3.8 or later. No external packages.


---

## Installation

FileShield is a single-file tool. You can use it directly:

```bash
# Direct usage
python3 fileshield.py photo.jpg

# Make it executable (Linux/macOS)
chmod +x fileshield.py
./fileshield.py photo.jpg

# Optional: add to PATH
sudo cp fileshield.py /usr/local/bin/fileshield
fileshield photo.jpg
```

Want to use FileShield inside a Docker container?


```bash
git clone https://github.com/yourname/fileshield.git
cd fileshield
docker build -t fileshield .
docker run -it --rm -v $(pwd):/data fileshield /data/suspicious.jpg
```

---


## Usage

### Scan Mode

```bash
# Scan a single file
python3 fileshield.py photo.jpg

# Scan multiple files
python3 fileshield.py shell.php image.png document.pdf archive.zip


# Scan an entire directory (recursive)

python3 fileshield.py -d /var/www/uploads/


# Show only high-risk files (score ≥ 40)
python3 fileshield.py -d /uploads/ --dangerous-only


# Minimal output: one line per file
python3 fileshield.py -d /uploads/ --quiet

# Export results to JSON (for SIEM/automation)
python3 fileshield.py malware.exe --export report.json

# Disable color output (for logging/piping)
python3 fileshield.py *.* --no-color | grep CRITICAL
```

### Recovery Mode


```bash
# Analyze a corrupted file → list possible types with confidence %
python3 fileshield.py --recover broken.dat

# Patch header to recover as a specific type
python3 fileshield.py --recover broken.dat --as pdf

# Specify output path
python3 fileshield.py --recover broken.dat --as pdf --output fixed.pdf

# List all supported recovery types and their magic bytes
python3 fileshield.py --list-types

```

---

## Output Example

Below is an example of FileShield scanning a PHP webshell disguised as a PNG image.

```
════════════════════════════════════════════════════════════════════════════════


 ═══ FILE INFORMATION ══════════════════════════════════════════════════════════
  Name:               webshell.png
  Size:               4.2 KB
  Extension:          .png
  Detected Type:      Plain Text / ASCII
  Category:           TEXT
  Inherent Risk:      ✓ LOW
  Ext vs Content:     ⚠ MISMATCH — Extension does NOT match content!
  PHP Polyglot:       ☠ PHP CODE DETECTED IN BINARY FILE!

 ═══ MAGIC BYTES — FIRST 16 BYTES ══════════════════════════════════════════════

  0000  89 50 4E 47 0D 0A 1A 0A 3C 3F 70 68 70 20 73 79  .PNG....<?php sy


 ═══ ENTROPY ANALYSIS ══════════════════════════════════════════════════════════
  █████████████████████░░░░░░░░░░░░░░░░░░░  4.887 bits/byte

 ═══ THREAT ANALYSIS ════════════════════════════════════════════════════════════


  [☠ CRITICAL] EXTENSION MISMATCH

  Extension '.png' (image) does not match actual content: Plain Text / ASCII (text).
  Attacker renamed an executable/script with an image extension to bypass upload validation.

  [☠ CRITICAL] PHP POLYGLOT / WEBSHELL DETECTED
  PHP code (<?php or <?=) found inside a binary/image file.
  This is the most common webshell technique — passes image validation but executes as PHP.


 ═══ VERDICT ══════════════════════════════════════════════════════════════════

   ☠ CRITICAL  RISK: 85/99

  ☠ DO NOT PROCESS THIS FILE — Immediate threat detected.
    Isolate the file and report to your security team.

════════════════════════════════════════════════════════════════════════════════
```


---

## Threat Detection

FileShield detects the following attack patterns:


| Attack Technique | How FileShield Detects It | Risk Level |

|---|---|---|
| **Extension Spoofing** | Magic bytes vs declared extension mismatch | 🔴 CRITICAL |
| **PHP Webshell / Polyglot** | `<?php` or `<?=` inside binary content | 🔴 CRITICAL |
| **Hidden PE Executable** | `MZ` signature in non-executable file | 🔴 CRITICAL |
| **Double Extension** | `malware.php.jpg`, `virus.exe.png` | 🟠 HIGH |
| **Null Byte Injection** | `%00` in text/script filename body | 🟠 HIGH |
| **Packed / Encrypted Malware** | Shannon entropy > 7.2 bits/byte | 🟠 HIGH |
| **Dangerous Extension** | Executable/script extensions (exe, php, sh, ps1…) | 🔴 CRITICAL |

| **Inherently Unsafe Format** | PDF JavaScript, OLE2 macro, RTF exploit, SWF | 🟡 MEDIUM–HIGH |
| **LNK Shortcut** | Windows Shell Link triggering code exec | 🔴 CRITICAL |
| **SVG / XML with payload** | XXE injection, embedded JavaScript | 🟡 MEDIUM |

### Risk Score


Every file is assigned a **risk score from 0 to 99** based on the weighted combination of detected threats:

```

0–14    ✓ LOW       No significant threats detected
15–39   ! MEDIUM    Suspicious — review recommended

40–69   ⚠ HIGH      Dangerous indicators found
70–99   ☠ CRITICAL  Immediate threat — do not process
```


The exit code is `1` if any file scores ≥ 40, making it easy to integrate into CI/CD pipelines and upload handlers.

---

## File Recovery

FileShield includes a recovery engine for corrupted files. It analyzes the remaining binary content, assigns a **confidence score** to each possible file type, and can automatically patch the file header to restore it.

### How recovery scoring works


The confidence score (0–100%) is computed from five independent signals:


| Signal | Weight | Description |
|---|---|---|
| **Byte-level structural hints** | 40% | Format-specific binary patterns in the body (e.g. `xref`, `%%EOF`, `obj` in a PDF body) |
| **String indicators** | 25% | Keywords specific to the format found in the file content |
| **Shannon entropy** | 15% | Each format has a characteristic entropy range (text: 3.5–6, JPEG: 4.5–8, packed: >7.2) |
| **Minimum file size** | 10% | Files smaller than the minimum valid size are penalized |
| **Extension hint** | 10% | Bonus if the declared extension matches the predicted type |

### Example recovery session

```bash
$ python3 fileshield.py --recover broken.dat

  ◈ CORRUPTED FILE RECOVERY ANALYZER
  File: broken.dat
  Size: 278 B  |  Entropy: 4.857 bits/byte

  Found 5 recovery candidates (sorted by confidence):

  ◆ 1. PDF Document              [DOCUMENT]
       Confidence:  █████████████████░░░░  86.1%
       Extension:   .pdf
       Magic Bytes: 25 50 44 46 2D 31 2E
       Auto-patch:  ✓ YES
       ▸ Patch %PDF-1.x header.
       ▸ If xref table and trailer are intact → file is parseable.
       ▸ Append %%EOF if missing.

  ◇ 2. XML Document              [TEXT]
       Confidence:  ████░░░░░░░░░░░░░░░░░  23.7%
       ...

  To recover, run with --as:
  python3 fileshield.py --recover broken.dat --as pdf
  python3 fileshield.py --recover broken.dat --as pdf --output fixed.pdf
```

```bash

$ python3 fileshield.py --recover broken.dat --as pdf --output fixed.pdf

  ✓ RECOVERY COMPLETE
  Profile used:     PDF Document

  Output file:      fixed.pdf
  Original size:    278 B
  Patched size:     293 B (+15 bytes)
  Magic verified:   ✓ PASS — Header patched correctly
  Expected magic:   25 50 44 46 2D 31 2E
  Actual magic:     25 50 44 46 2D 31 2E
```

### Supported recovery types


| Key | Format | Extension | Patch Strategy |
|---|---|---|---|
| `jpg` | JPEG Image | `.jpg` | Patch SOI `FF D8` + JFIF APP0 header, append EOI |
| `png` | PNG Image | `.png` | Patch 8-byte signature, append IEND chunk if missing |
| `gif` | GIF Image | `.gif` | Patch `GIF89a` header, append trailer `0x3B` |
| `bmp` | BMP Bitmap | `.bmp` | Patch `BM` signature, rebuild file size field |
| `pdf` | PDF Document | `.pdf` | Patch `%PDF-1.x`, detect version from body, append `%%EOF` |
| `zip` | ZIP Archive | `.zip` | Patch `PK 03 04` Local File Header |
| `gz` | GZIP | `.gz` | Patch `1F 8B` + CM byte |
| `mp3` | MP3 Audio | `.mp3` | Find ID3 tag or MPEG sync word, strip garbage prefix |
| `wav` | WAV Audio | `.wav` | Patch `RIFF` + rebuild chunk size + `WAVE` marker |
| `mp4` | MP4 Video | `.mp4` | Prepend/fix `ftyp` box |
| `xml` | XML Document | `.xml` | Prepend `<?xml>` declaration |
| `html` | HTML Document | `.html` | Prepend DOCTYPE, append `</html>` |
| `sqlite` | SQLite Database | `.db` | Patch 16-byte `SQLite format 3\x00` header |

> **Note:** Header patching restores the magic bytes and minimal structure. If the file body is also corrupted, additional specialized tools (PhotoRec, TestDisk, `sqlite3 .recover`) may be needed.


---

## How It Works


### Magic byte detection

Every file format has a unique byte sequence at a specific offset — usually the very beginning. This is called a **magic number** or **file signature**. FileShield reads the first 512–4096 bytes of the file and matches them against a signature database of 30+ formats.

```
JPEG:   FF D8 FF
PNG:    89 50 4E 47 0D 0A 1A 0A
PDF:    25 50 44 46  (%PDF)
ZIP:    50 4B 03 04  (PK..)
ELF:    7F 45 4C 46  (.ELF)
MZ/PE:  4D 5A        (MZ)
```

The declared file extension is compared against the detected binary format. A mismatch is a strong indicator of an extension spoofing attack.

### Entropy analysis

Shannon entropy measures the randomness of a byte sequence on a scale of 0–8 bits/byte:

- **0–4**: Plain text, structured data (source code, HTML, JSON)
- **4–6**: Lightly compressed or mixed content
- **6–7.2**: Binary files, media (JPEG, MP4, compiled code)
- **>7.2**: Packed, encrypted, or obfuscated content → **malware indicator**

Legitimate files like JPEG images rarely exceed 7.8 bits/byte. Malware packers like UPX or custom crypters push entropy to near-maximum values.

### Attack vector reference

```

Extension Spoofing:
  shell.php → shell.jpg
  Upload filter checks ".jpg" → passes
  Web server executes .php → Remote Code Execution


Null Byte Injection:
  shell.php%00.jpg
  PHP strlen() stops at null byte → filename = "shell.php"
  Bypasses regex extension check → RCE


Double Extension:
  malware.php.jpg
  Apache mod_php may execute both extensions
  Simple last-extension check is bypassed

PHP Polyglot (GIFAR technique):
  GIF89a;<?php system($_GET['cmd']); ?>
  Magic bytes = GIF (passes image validation)

  PHP engine sees <?php → executes as webshell
```

---


## Integration

### Python


```python
import subprocess
import json

result = subprocess.run(

    ['python3', 'fileshield.py', '--no-color', '--export', '/tmp/report.json', 'upload.jpg'],

    capture_output=True
)

with open('/tmp/report.json') as f:
    report = json.load(f)

if report[0]['risk_score'] >= 40:
    raise ValueError(f"Upload rejected: {report[0]['threats'][0]['name']}")
```

### Django / Flask upload handler

```python
import subprocess, json, tempfile, os

def validate_upload(file_obj):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp:
        tmp.write(file_obj.read())
        tmp_path = tmp.name

    result = subprocess.run(
        ['python3', 'fileshield.py', '--no-color', '--export', '/tmp/fs_report.json', tmp_path],
        capture_output=True
    )
    os.unlink(tmp_path)

    with open('/tmp/fs_report.json') as f:
        report = json.load(f)

    risk = report[0]['risk_score']

    if risk >= 40:
        threats = [t['name'] for t in report[0]['threats']]
        raise PermissionError(f"File rejected (risk={risk}): {', '.join(threats)}")

    return report[0]['detected']['label'] if report[0].get('detected') else 'unknown'

```

### CI/CD pipeline (GitHub Actions)

```yaml

- name: Scan uploaded artifacts
  run: |
    python3 fileshield.py -d ./artifacts/ --dangerous-only --no-color
    if [ $? -ne 0 ]; then
      echo "SECURITY: High-risk files detected in artifacts"
      exit 1
    fi
```


### Shell script

```bash
# Scan and reject if any file scores >= 40 (exit code 1)
python3 fileshield.py "$UPLOAD_PATH" --no-color --quiet
if [ $? -ne 0 ]; then
    echo "Upload rejected by FileShield"
    rm -f "$UPLOAD_PATH"
    exit 1
fi
```

---

## Security Recommendations


FileShield will flag threats and explain them. Here is the broader guidance for building a secure file upload system:

1. **Validate by magic bytes, not extension** — Use FileShield or `python-magic` server-side. Never trust `Content-Type` from the HTTP request.

2. **Store uploads outside webroot** — Files in `/var/www/uploads/` can be requested directly. Store in `/opt/uploads/` and serve via a controller that sets proper headers.

3. **Rename files on save** — Generate a UUID filename with no extension, or only the safe whitelisted extension. Never preserve the original filename.

4. **Serve with `Content-Disposition: attachment`** — Prevents the browser from rendering or executing the file inline.

5. **Whitelist, don't blacklist** — Instead of blocking `.php`, `.exe`, etc., only allow explicitly known-safe types (`jpg`, `png`, `pdf`, `mp4`).

6. **Scan with antivirus** — Integrate ClamAV or VirusTotal API for signature-based malware detection.

7. **Limit file size and rate** — Prevent zip bombs and DoS via upload flooding.

8. **Re-encode images after upload** — Use PIL/Pillow to re-encode JPEG/PNG. This strips any embedded PHP code, EXIF exploits, and polyglot payloads.

---

## Supported Formats


FileShield detects the following file formats via magic byte analysis:

| Category | Formats |
|---|---|
| **Executables** | Windows PE (MZ), ELF (Linux/Android), Mach-O (macOS 32/64-bit), Java Class |
| **Scripts** | PHP, Shebang scripts (sh/py/rb/pl), Windows LNK |
| **Documents** | PDF, Microsoft Office OLE2 (doc/xls/ppt), OOXML/ZIP (docx/xlsx/pptx), RTF |
| **Archives** | ZIP, RAR, 7-Zip, GZIP |

| **Images** | JPEG, PNG, GIF, BMP, WebP/RIFF |
| **Media** | MP3, WAV, RIFF container (AVI) |
| **Text / Markup** | XML, SVG, HTML |

| **Data** | SQLite, PCAP, PCAPNG |
| **Dangerous/Legacy** | Adobe Flash SWF (compressed & uncompressed) |


---

## Command Reference

```
usage: fileshield [-h] [-d DIR] [--export OUTPUT.json] [--no-color] [-q]
                  [--dangerous-only] [--recover FILE] [--as TYPE]
                  [--output OUTPUT_FILE] [--list-types]
                  [files ...]

── SCAN MODE ──────────────────────────────────────────────────────
  fileshield photo.jpg
  fileshield malware.exe.jpg shell.php
  fileshield -d /var/www/uploads
  fileshield document.pdf --export report.json
  fileshield *.* --no-color --quiet

── RECOVERY MODE ──────────────────────────────────────────────────
  fileshield --recover broken.dat
  fileshield --recover broken.dat --as pdf

  fileshield --recover broken.dat --as pdf --output fixed.pdf

  fileshield --list-types

positional arguments:
  files                 File(s) to analyze


options:
  -h, --help            Show this help message and exit
  -d DIR, --dir DIR     Scan entire directory recursively
  --export OUTPUT.json  Export results to JSON file
  --no-color            Disable colored output (for piping/logging)
  -q, --quiet           Show only verdict (one line per file)
  --dangerous-only      Only show files with risk score ≥ 40
  --recover FILE        Analyze corrupted file and suggest recovery options
  --as TYPE             Recovery type to apply (jpg, png, pdf, zip…)
  --output FILE         Output path for recovered file
  --list-types          List all supported recovery types and magic bytes
```

---


## JSON Output Format


When using `--export`, FileShield writes a JSON array where each entry follows this schema:

```json
[
  {
    "filepath": "/uploads/suspicious.jpg",
    "filename": "suspicious.jpg",
    "extension": "jpg",
    "size": 4312,
    "detected": {
      "label": "Plain Text / ASCII",
      "category": "text",
      "risk": "LOW"
    },
    "hashes": {
      "md5": "c729e398ebdfa8a8f6fb9b7c307302e9",
      "sha1": "8d5da007f332cf02a9c9a1df04e7e5484c32038e",
      "sha256": "a6203c0d6cb54770b323548828e0907a..."
    },
    "entropy": 5.0049,

    "mismatch": true,
    "double_ext": false,
    "dangerous_ext": false,
    "php_polyglot": true,
    "pe_hidden": false,
    "null_bytes": 0,
    "risk_score": 85,
    "threats": [
      {
        "level": "CRITICAL",
        "name": "EXTENSION MISMATCH",
        "detail": "Extension '.jpg' (image) does not match actual content..."
      },

      {
        "level": "CRITICAL",
        "name": "PHP POLYGLOT / WEBSHELL DETECTED",
        "detail": "PHP code (<?php or <?=) found inside a binary/image file..."
      }

    ],
    "timestamp": "2026-02-24T10:30:00Z"
  }
]
```


---

## Comparison

| Feature | `file` (Unix) | `python-magic` | **FileShield** |
|---|---|---|---|
| Magic byte detection | ✓ | ✓ | ✓ |
| Extension mismatch detection | ✗ | ✗ | ✓ |
| PHP polyglot detection | ✗ | ✗ | ✓ |
| Hidden PE detection | ✗ | ✗ | ✓ |

| Null byte injection detection | ✗ | ✗ | ✓ |
| Entropy analysis | ✗ | ✗ | ✓ |
| Risk scoring | ✗ | ✗ | ✓ |
| Attack vector documentation | ✗ | ✗ | ✓ |

| Corrupted file recovery | ✗ | ✗ | ✓ |

| Zero dependencies | ✓ | ✗ | ✓ |
| JSON export | ✗ | ✗ | ✓ |
| CI/CD integration (exit codes) | ✗ | ✗ | ✓ |


---

## Contributing

Contributions are welcome. Areas where help is most appreciated:

- **New magic byte signatures** — Adding more formats to the detection database
- **Recovery profiles** — More format-specific patch functions (DOCX, MP4 container repair, etc.)
- **Test cases** — Real-world samples of each attack technique
- **Language bindings** — Rust CLI wrapper, Node.js module, Go package

To add a new signature, edit the `SIGNATURES` list in `fileshield.py`:

```python
{
    "magic": b"\x1A\x45\xDF\xA3",        # EBML magic (MKV/WebM)
    "label": "Matroska Video (MKV/WebM)",
    "ext_hints": ["mkv", "webm"],
    "category": "media",
    "risk": "LOW",
    "description": "Matroska container using EBML encoding.",

    "attack_vectors": ["Malformed EBML → parser crash"],
},
```

---

## Research & References

- [OWASP: Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CVE-2016-3714 — ImageTragick (ImageMagick RCE)](https://imagetragick.com/)
- [CVE-2010-2568 — Windows Shell LNK vulnerability (Stuxnet)](https://nvd.nist.gov/vuln/detail/CVE-2010-2568)
- [CVE-2017-11882 — Microsoft Equation Editor RCE in RTF](https://nvd.nist.gov/vuln/detail/CVE-2017-11882)
- [GIFAR Attack — GIF+JAR polyglot](https://en.wikipedia.org/wiki/Gifar)
- [File Magic Numbers — Gary Kessler](https://www.garykessler.net/library/file_sigs.html)
- [Shannon Entropy in Malware Analysis](https://resources.infosecinstitute.com/topic/malware-analysis-basics-static-analysis/)

---

## License

FileShield is released under the [MIT License](LICENSE).

```
MIT License — Copyright (c) 2026 FileShield Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software [...] to deal in the Software without restriction.
```

---

<div align="center">


Made for security engineers, developers, and anyone who uploads files to a server.

**[⬆ Back to top](#-fileshield)**


</div>
