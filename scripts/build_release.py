"""Reproducible source ZIP and SHA-256 checksum for GitHub releases."""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.0"
EXCLUDED = {
    ".git", ".venv", ".pytest_cache", ".ruff_cache", "__pycache__", "dist",
    "build", "demo-local", "_demo", ".mypy_cache", "venv", ".idea", ".vscode",
}
IGNORED_EXTENSIONS = {".pyc", ".pyo", ".key", ".pfx", ".p12", ".jks", ".keystore"}


def allowed(file: Path) -> bool:
    relative = file.relative_to(ROOT)
    if any(p in EXCLUDED or p.endswith(".egg-info") for p in relative.parts):
        return False
    if file.is_symlink() or not file.is_file():
        return False
    if file.name.startswith(".env") or file.suffix.lower() in IGNORED_EXTENSIONS:
        return False
    if file.name in {"certdelta-results.sarif", ".coverage", ".DS_Store"}:
        return False
    return True


def main() -> None:
    out = ROOT / "dist"
    out.mkdir(parents=True, exist_ok=True)
    zip_path = out / f"certdelta-v{VERSION}.zip"
    files = sorted((f for f in ROOT.rglob("*") if allowed(f)), key=lambda f: f.as_posix())
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for file in files:
            rel = file.relative_to(ROOT).as_posix()
            meta = zipfile.ZipInfo(f"certdelta/{rel}", date_time=(2026, 1, 1, 0, 0, 0))
            meta.compress_type = zipfile.ZIP_DEFLATED
            meta.external_attr = 0o100644 << 16
            zf.writestr(meta, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    digest = hashlib.sha256(zip_path.read_bytes()).hexdigest()
    (out / "SHA256SUMS").write_text(f"{digest}  {zip_path.name}\n", encoding="utf-8")
    print(f"Created {zip_path} ({len(files)} files)")
    print(f"SHA-256: {digest}")


if __name__ == "__main__":
    main()
