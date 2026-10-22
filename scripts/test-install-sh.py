#!/usr/bin/env python3

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
INSTALLER = ROOT / "install.sh"
BUNDLE = "authos-sqlite-linux-amd64"
ARCHIVE = f"{BUNDLE}.tar.gz"
REQUIRED_FILES = {
    "authos": b"binary\n",
    "authos.config.example.json": b"{}\n",
    "LICENSE": b"map\n",
    "AGPL-3.0.txt": b"license\n",
    "install.sh": b"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" > "$AUTHOS_TEST_MARKER"
""",
    "README.txt": b"readme\n",
    "standalone/authos_standalone.py": b"#!/usr/bin/env python3\n",
}


class InstallerArchiveSafetyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = self.root / "fixture"
        self.bin_dir = self.root / "bin"
        self.marker = self.root / "marker"
        self.fixture.mkdir()
        self.bin_dir.mkdir()
        fake_curl = self.bin_dir / "curl"
        fake_curl.write_text(
            """#!/usr/bin/env bash
set -euo pipefail
output=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --*) shift ;;
    *) url="$1"; shift ;;
  esac
done
cp "$AUTHOS_TEST_FIXTURE/$(basename "$url")" "$output"
""",
            encoding="utf-8",
        )
        fake_curl.chmod(0o755)

        # The installer targets Linux and uses GNU sha256sum flags. Provide a
        # deterministic GNU-compatible implementation so this test also runs
        # on macOS/BSD development hosts without depending on coreutils.
        fake_sha256sum = self.bin_dir / "sha256sum"
        fake_sha256sum.write_text(
            """#!/usr/bin/env python3
import hashlib
import pathlib
import sys

args = [arg for arg in sys.argv[1:] if not arg.startswith("-")]
check = "--check" in sys.argv[1:] or "-c" in sys.argv[1:]

if check:
    ok = True
    for line in sys.stdin:
        line = line.rstrip("\\n")
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            print("invalid checksum line", file=sys.stderr)
            ok = False
            continue
        expected, filename = parts
        filename = filename.lstrip("*")
        try:
            actual = hashlib.sha256(pathlib.Path(filename).read_bytes()).hexdigest()
        except OSError as error:
            print(f"{filename}: FAILED ({error})", file=sys.stderr)
            ok = False
            continue
        if actual == expected:
            print(f"{filename}: OK")
        else:
            print(f"{filename}: FAILED", file=sys.stderr)
            ok = False
    sys.exit(0 if ok else 1)

for filename in args:
    try:
        digest = hashlib.sha256(pathlib.Path(filename).read_bytes()).hexdigest()
    except OSError as error:
        print(f"sha256sum: {filename}: {error}", file=sys.stderr)
        sys.exit(1)
    print(f"{digest}  {filename}")
""",
            encoding="utf-8",
        )
        fake_sha256sum.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build_archive(self, extras: list[tarfile.TarInfo] | None = None) -> None:
        archive_path = self.fixture / ARCHIVE
        with tarfile.open(archive_path, "w:gz") as archive:
            for relative, payload in REQUIRED_FILES.items():
                info = tarfile.TarInfo(f"{BUNDLE}/{relative}")
                info.size = len(payload)
                info.mode = 0o755 if relative in {"authos", "install.sh"} else 0o644
                archive.addfile(info, io.BytesIO(payload))
            for info in extras or []:
                payload = b"duplicate\n" if info.isfile() else None
                if payload is not None:
                    info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload) if payload is not None else None)
        digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        (self.fixture / "SHA256SUMS.txt").write_text(
            f"{digest}  {ARCHIVE}\n", encoding="utf-8"
        )

    def run_installer(self, *, tag: str = "v1.2.3") -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.bin_dir}:{env['PATH']}",
                "AUTHOS_TEST_FIXTURE": str(self.fixture),
                "AUTHOS_TEST_MARKER": str(self.marker),
                "AUTHOS_ARCH": "amd64",
                "AUTHOS_RELEASE_TAG": tag,
            }
        )
        return subprocess.run(
            ["bash", str(INSTALLER)],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_verified_install_cleans_temporary_bundle(self) -> None:
        self.build_archive()

        result = self.run_installer()

        self.assertEqual(result.returncode, 0, result.stderr)
        extracted_bundle = Path(self.marker.read_text(encoding="utf-8").strip())
        self.assertFalse(extracted_bundle.exists())

    def test_rejects_traversal_link_and_duplicate_members(self) -> None:
        cases = []
        traversal = tarfile.TarInfo(f"{BUNDLE}/../escape")
        cases.append(traversal)
        symlink = tarfile.TarInfo(f"{BUNDLE}/linked")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "/etc/passwd"
        cases.append(symlink)
        duplicate = tarfile.TarInfo(f"{BUNDLE}/authos")
        cases.append(duplicate)

        for unsafe in cases:
            with self.subTest(member=unsafe.name, type=unsafe.type):
                self.build_archive([unsafe])
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())

    def test_rejects_mismatched_archive_checksum(self) -> None:
        self.build_archive()
        archive = self.fixture / ARCHIVE
        archive.write_bytes(archive.read_bytes() + b"tampered")

        result = self.run_installer()

        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.marker.exists())

    def test_rejects_duplicate_checksum_entry_and_invalid_tag(self) -> None:
        self.build_archive()
        checksum_path = self.fixture / "SHA256SUMS.txt"
        checksum_path.write_text(
            checksum_path.read_text(encoding="utf-8") * 2, encoding="utf-8"
        )
        self.assertNotEqual(self.run_installer().returncode, 0)

        self.assertNotEqual(self.run_installer(tag="v1.2.3-rc.1").returncode, 0)


if __name__ == "__main__":
    unittest.main()
