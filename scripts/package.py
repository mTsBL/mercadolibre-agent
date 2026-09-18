#!/usr/bin/env python3
"""Build a source delivery ZIP with executable entrypoints and no local/private state."""
from pathlib import Path
import zipfile


def main():
    root = Path(__file__).resolve().parents[1]
    destination = root / "dist" / "mercadolibre-agent.zip"
    destination.parent.mkdir(exist_ok=True)
    directories = ("scanner", "schemas", "tests", "demo", "scripts", "docs")
    files = [root / name for name in ("README.md", "requirements.txt", "run.sh", "setup.sh", ".env.example", ".gitignore")]
    for directory in directories:
        files.extend(path for path in (root / directory).rglob("*") if path.is_file()
                     and "__pycache__" not in path.parts and path.suffix not in (".pyc", ".pyo"))
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(files):
            archive.write(path, "mercadolibre-agent/" + path.relative_to(root).as_posix())
    print(destination)
    print(f"{len(files)} files; {destination.stat().st_size:,} bytes")


if __name__ == "__main__":
    main()
