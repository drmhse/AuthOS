#!/usr/bin/env python3

import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).parent / "authos-standalone" / "authos_standalone.py"
SPEC = importlib.util.spec_from_file_location("authos_standalone", SCRIPT)
assert SPEC and SPEC.loader
standalone = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(standalone)


class AtomicStandaloneWritesTest(unittest.TestCase):
    def test_bundle_install_atomically_retains_license_and_source_notices(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bundle = root / "bundle"
            install_root = root / "installed"
            binary = root / "bin" / "authos"
            (bundle / "standalone").mkdir(parents=True)
            (bundle / "authos").write_bytes(b"binary")
            (bundle / "authos.config.example.json").write_text("{}\n", encoding="utf-8")
            (bundle / "standalone" / "authos_standalone.py").write_text(
                "#!/usr/bin/env python3\n", encoding="utf-8"
            )
            notices = {
                "LICENSE": "license map\n",
                "AGPL-3.0.txt": "full AGPL\n",
                "README.txt": "Corresponding source: https://example.test/v1.2.3\n",
            }
            for name, content in notices.items():
                (bundle / name).write_text(content, encoding="utf-8")

            with (
                mock.patch.object(standalone, "INSTALL_ROOT", install_root),
                mock.patch.object(standalone, "INSTALL_BINARY", binary),
                mock.patch.object(
                    standalone,
                    "_owner_ids",
                    return_value=(os.geteuid(), os.getegid()),
                ),
            ):
                standalone.copy_bundle(bundle)

            for name, content in notices.items():
                installed = install_root / name
                self.assertEqual(installed.read_text(encoding="utf-8"), content)
                self.assertEqual(stat.S_IMODE(installed.stat().st_mode), 0o644)

    def test_api_key_output_is_confined_to_managed_data_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary) / "managed"
            data_dir.mkdir()

            expected = data_dir / ".authos" / "service.env"
            self.assertEqual(
                standalone.resolve_output_path(data_dir, ".authos/service.env"),
                expected,
            )

            for unsafe in (
                "",
                "/etc/authos.env",
                "../authos.env",
                ".authos/../../authos.env",
                ".authos//authos.env",
                ".authos/./authos.env",
                " .authos/authos.env",
                ".authos/authos.env ",
                ".authos/authos.env\0suffix",
                ".authos/authos.env\nINJECTED=value",
            ):
                with self.subTest(unsafe=unsafe):
                    with self.assertRaisesRegex(RuntimeError, "writeTo"):
                        standalone.resolve_output_path(data_dir, unsafe)

    def test_api_key_output_rejects_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            data_dir = root / "managed"
            outside = root / "outside"
            data_dir.mkdir()
            outside.mkdir()
            (data_dir / "link").symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(RuntimeError, "symlink"):
                parent_fd, _, _ = standalone.open_managed_output_parent(
                    data_dir, "link/service.env"
                )
                os.close(parent_fd)

    def test_api_key_output_rejects_final_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            data_dir = root / "managed"
            data_dir.mkdir()
            outside = root / "outside.env"
            outside.write_text("DO_NOT_CHANGE\n", encoding="utf-8")

            symlink_target = data_dir / "symlink.env"
            symlink_target.symlink_to(outside)
            parent_fd, filename, _ = standalone.open_managed_output_parent(
                data_dir, "symlink.env"
            )
            try:
                with self.assertRaisesRegex(RuntimeError, "regular file"):
                    standalone.atomic_write_text_at(
                        parent_fd, filename, "SECRET=value\n", mode=0o600
                    )
            finally:
                os.close(parent_fd)
            self.assertEqual(outside.read_text(encoding="utf-8"), "DO_NOT_CHANGE\n")

            hardlink_target = data_dir / "hardlink.env"
            os.link(outside, hardlink_target)
            parent_fd, filename, _ = standalone.open_managed_output_parent(
                data_dir, "hardlink.env"
            )
            try:
                with self.assertRaisesRegex(RuntimeError, "hard-linked"):
                    standalone.atomic_write_text_at(
                        parent_fd, filename, "SECRET=value\n", mode=0o600
                    )
            finally:
                os.close(parent_fd)
            self.assertEqual(outside.read_text(encoding="utf-8"), "DO_NOT_CHANGE\n")

    def test_api_key_output_detects_parent_swap_before_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            data_dir = root / "managed"
            safe_parent = data_dir / "keys"
            outside = root / "outside"
            safe_parent.mkdir(parents=True)
            outside.mkdir()

            parent_fd, _, identity = standalone.open_managed_output_parent(
                data_dir, "keys/service.env"
            )
            try:
                safe_parent.rename(data_dir / "keys-moved")
                safe_parent.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(RuntimeError, "symlink|changed"):
                    standalone.assert_managed_output_parent_unchanged(
                        data_dir, "keys/service.env", identity
                    )
            finally:
                os.close(parent_fd)
            self.assertEqual(list(outside.iterdir()), [])

    def test_api_key_output_writes_atomically_through_retained_directory_fd(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary).resolve() / "managed"
            data_dir.mkdir()
            parent_fd, filename, identity = standalone.open_managed_output_parent(
                data_dir, "keys/service.env"
            )
            try:
                standalone.assert_managed_output_parent_unchanged(
                    data_dir, "keys/service.env", identity
                )
                standalone.atomic_write_text_at(
                    parent_fd, filename, "AUTHOS_API_KEY=secret\n", mode=0o600
                )
            finally:
                os.close(parent_fd)

            target = data_dir / "keys" / "service.env"
            self.assertEqual(target.read_text(encoding="utf-8"), "AUTHOS_API_KEY=secret\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_api_key_output_detects_final_target_swap(self):
        with tempfile.TemporaryDirectory() as temporary:
            data_dir = Path(temporary).resolve() / "managed"
            keys_dir = data_dir / "keys"
            keys_dir.mkdir(parents=True)
            target = keys_dir / "service.env"
            replacement = keys_dir / "replacement.env"
            target.write_text("OLD=value\n", encoding="utf-8")
            replacement.write_text("RACED=value\n", encoding="utf-8")

            parent_fd, filename, _ = standalone.open_managed_output_parent(
                data_dir, "keys/service.env"
            )
            real_stat = os.stat
            destination_stats = 0

            def swap_before_second_destination_stat(path, *args, **kwargs):
                nonlocal destination_stats
                if path == filename and kwargs.get("dir_fd") == parent_fd:
                    destination_stats += 1
                    if destination_stats == 2:
                        os.replace(replacement, target)
                return real_stat(path, *args, **kwargs)

            try:
                with mock.patch.object(
                    standalone.os, "stat", side_effect=swap_before_second_destination_stat
                ):
                    with self.assertRaisesRegex(RuntimeError, "changed"):
                        standalone.atomic_write_text_at(
                            parent_fd, filename, "SECRET=value\n", mode=0o600
                        )
            finally:
                os.close(parent_fd)

            self.assertEqual(target.read_text(encoding="utf-8"), "RACED=value\n")

    def test_json_write_is_restrictive_and_preserves_parent_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary) / "managed"
            parent.mkdir(mode=0o750)
            target = parent / "state.json"
            target.write_text('{"old": true}\n', encoding="utf-8")
            os.chmod(target, 0o644)

            standalone.write_json(target, {"new": True}, mode=0o600)

            self.assertEqual(target.read_text(encoding="utf-8"), '{\n  "new": true\n}\n')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o750)

    def test_replace_failure_preserves_live_file_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            target = parent / "authos.env"
            target.write_text("LIVE=old\n", encoding="utf-8")
            os.chmod(target, 0o640)

            with mock.patch.object(
                standalone.os,
                "replace",
                side_effect=OSError("injected replace failure"),
            ):
                with self.assertRaisesRegex(OSError, "injected replace failure"):
                    standalone.write_env(target, {"LIVE": "new"}, mode=0o600)

            self.assertEqual(target.read_text(encoding="utf-8"), "LIVE=old\n")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o640)
            self.assertEqual(list(parent.glob(f".{target.name}.*.tmp")), [])

    def test_binary_copy_stages_mode_before_atomic_replace(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            source = parent / "new-authos"
            target = parent / "authos"
            source.write_bytes(b"new-binary")
            target.write_bytes(b"old-binary")
            observations = []
            real_replace = os.replace

            def inspect_then_replace(staged, live):
                observations.append(
                    (
                        Path(live).read_bytes(),
                        Path(staged).read_bytes(),
                        stat.S_IMODE(Path(staged).stat().st_mode),
                    )
                )
                real_replace(staged, live)

            with mock.patch.object(standalone.os, "replace", side_effect=inspect_then_replace):
                standalone.atomic_copy_file(source, target, mode=0o755)

            self.assertEqual(observations, [(b"old-binary", b"new-binary", 0o755)])
            self.assertEqual(target.read_bytes(), b"new-binary")
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
            self.assertEqual(list(parent.glob(f".{target.name}.*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
