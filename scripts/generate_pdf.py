#!/usr/bin/env python3
"""Genera docs/InfraAudit.pdf a partir de los manuales Markdown (stdlib only)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
SOURCES = [
    DOCS / "manual.md",
    DOCS / "architecture.md",
    DOCS / "creating-checks.md",
    DOCS / "installation.md",
]
OUTPUT = DOCS / "InfraAudit.pdf"


def _escape_pdf(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def markdown_to_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            lines.append("")
            continue
        if line.startswith("# "):
            lines.append(line[2:].strip().upper())
            lines.append("=" * min(60, len(line)))
            continue
        if line.startswith("## "):
            lines.append("")
            lines.append(line[3:].strip())
            lines.append("-" * min(40, len(line)))
            continue
        if line.startswith("### "):
            lines.append(line[4:].strip())
            continue
        if line.startswith("```"):
            lines.append(line)
            continue
        # Strip simple markdown markers
        cleaned = re.sub(r"[*`]", "", line)
        cleaned = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", cleaned)
        lines.append(cleaned)
    return lines


def wrap(text: str, width: int = 90) -> list[str]:
    if len(text) <= width:
        return [text]
    words = text.split()
    rows: list[str] = []
    current = ""
    for word in words:
        trial = f"{current} {word}".strip()
        if len(trial) <= width:
            current = trial
        else:
            if current:
                rows.append(current)
            current = word
    if current:
        rows.append(current)
    return rows or [""]


def build_pdf(pages: list[list[str]]) -> bytes:
    """Construye un PDF mínimo (Type1 Helvetica) con varias páginas."""
    objects: list[bytes] = []
    # 1: Catalog
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    # 2: Pages (placeholder, filled later)
    objects.append(b"<< /Type /Pages /Kids [] /Count 0 >>")

    page_ids: list[int] = []
    for page_lines in pages:
        content_lines = ["BT /F1 10 Tf 50 780 Td 14 TL"]
        first = True
        for line in page_lines:
            safe = _escape_pdf(line)
            if first:
                content_lines.append(f"({safe}) Tj")
                first = False
            else:
                content_lines.append(f"T* ({safe}) Tj")
        content_lines.append("ET")
        stream = "\n".join(content_lines).encode("latin-1", errors="replace")
        objects.append(
            b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        )
        content_id = len(objects)
        objects.append(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                f"/Contents {content_id} 0 R /Resources << /Font << "
                f"/F1 {len(objects) + 2} 0 R >> >> >>"
            ).encode()
        )
        page_ids.append(len(objects))
        objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")

    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[1] = (
        f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode()
    )

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for idx, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{idx} 0 obj\n".encode())
        out.extend(obj)
        out.extend(b"\nendobj\n")
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n".encode())
    out.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        out.extend(f"{offset:010d} 00000 n \n".encode())
    out.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF\n"
        ).encode()
    )
    return bytes(out)


def main() -> None:
    all_lines: list[str] = []
    for path in SOURCES:
        all_lines.extend(markdown_to_lines(path.read_text(encoding="utf-8")))
        all_lines.extend(["", ""])

    # Paginate ~50 lines/page
    pages: list[list[str]] = []
    current: list[str] = []
    for line in all_lines:
        for wrapped in wrap(line):
            current.append(wrapped)
            if len(current) >= 50:
                pages.append(current)
                current = []
    if current:
        pages.append(current)
    if not pages:
        pages = [["InfraAudit documentation"]]

    OUTPUT.write_bytes(build_pdf(pages))
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
