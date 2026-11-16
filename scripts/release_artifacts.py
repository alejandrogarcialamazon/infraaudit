#!/usr/bin/env python3
"""Construir sdist/wheel, calcular checksums; no publica ni crea tags."""

from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path


def main() -> None:
    subprocess.run([sys.executable, "-m", "build", "--no-isolation"], check=True)
    files = sorted(path for path in Path("dist").iterdir() if path.suffix in {".whl", ".gz"})
    rows = [hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name for path in files]
    Path("dist/SHA256SUMS").write_text("\n".join(rows) + "\n")
    print("Artefactos y SHA256SUMS preparados. Revisar antes de publicar una release.")


if __name__ == "__main__":
    main()
