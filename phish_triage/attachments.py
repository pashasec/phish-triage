"""Hash attachments and flag suspicious file types."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .parser import Attachment


# File extensions that should never appear in a legitimate email attachment
# without strong justification (executables, scripts, macro-laden docs).
DANGEROUS_EXTS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".cpl",
    ".msi", ".jar", ".reg", ".lnk", ".iso", ".img",
}

# Document types that commonly carry macros -- risky but not always malicious
MACRO_EXTS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".potm"}

# Containers that frequently smuggle one of the above past mail filters
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".iso", ".img", ".tar", ".gz"}

# HTML attachments are a classic credential-phish technique
PHISH_KIT_EXTS = {".html", ".htm", ".shtml"}


@dataclass
class HashedAttachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str
    risk_flags: list[str]


def _ext(filename: str) -> str:
    name = filename.lower()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[1]


def _flags(filename: str, content_type: str) -> list[str]:
    flags: list[str] = []
    ext = _ext(filename)
    if ext in DANGEROUS_EXTS:
        flags.append(f"dangerous executable type ({ext})")
    if ext in MACRO_EXTS:
        flags.append(f"macro-enabled document ({ext})")
    if ext in ARCHIVE_EXTS:
        flags.append(f"archive may contain hidden payload ({ext})")
    if ext in PHISH_KIT_EXTS:
        flags.append("HTML attachment -- classic credential-phish vector")
    if "." in filename and filename.lower().count(".") >= 2:
        parts = filename.lower().split(".")
        # double-extension trick like invoice.pdf.exe
        if parts[-1] in {e.strip(".") for e in DANGEROUS_EXTS}:
            flags.append("double extension -- disguised executable")
    return flags


def hash_attachments(attachments: list[Attachment]) -> list[HashedAttachment]:
    out: list[HashedAttachment] = []
    for a in attachments:
        out.append(
            HashedAttachment(
                filename=a.filename,
                content_type=a.content_type,
                size=a.size,
                md5=hashlib.md5(a.payload).hexdigest(),
                sha1=hashlib.sha1(a.payload).hexdigest(),
                sha256=hashlib.sha256(a.payload).hexdigest(),
                risk_flags=_flags(a.filename, a.content_type),
            )
        )
    return out
