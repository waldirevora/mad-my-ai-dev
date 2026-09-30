from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from madctl.canonical import atomic_write_bytes


class ExclusiveAtomicWriteTests(unittest.TestCase):
    def test_exclusive_creation_syncs_file_and_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "record.json"
            calls = []
            real_fsync = os.fsync

            def observe_fsync(fd):
                mode = os.fstat(fd).st_mode
                calls.append("directory" if stat.S_ISDIR(mode) else "file")
                return real_fsync(fd)

            with patch("madctl.canonical.os.fsync", side_effect=observe_fsync):
                atomic_write_bytes(target, b'{"ok":true}\n', exclusive=True)

            self.assertEqual(target.read_bytes(), b'{"ok":true}\n')
            self.assertIn("file", calls)
            self.assertIn("directory", calls)
            self.assertLess(calls.index("file"), calls.index("directory"))

    def test_sync_failure_before_publication_leaves_no_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "record.json"

            with patch(
                "madctl.canonical.os.fsync",
                side_effect=OSError("simulated file sync failure"),
            ):
                with self.assertRaises(OSError):
                    atomic_write_bytes(target, b'{"ok":true}\n', exclusive=True)

            self.assertFalse(target.exists())

    def test_directory_sync_failure_after_publication_blocks_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "record.json"
            first = b"first\n"
            real_fsync = os.fsync
            directory_sync_attempts = []

            def fail_directory_sync(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    directory_sync_attempts.append(True)
                    raise OSError("simulated directory sync failure")
                return real_fsync(fd)

            with patch("madctl.canonical.os.fsync", side_effect=fail_directory_sync):
                with self.assertRaisesRegex(
                    OSError, "simulated directory sync failure"
                ):
                    atomic_write_bytes(target, first, exclusive=True)

            self.assertEqual(len(directory_sync_attempts), 1)
            self.assertEqual(target.read_bytes(), first)
            self.assertEqual(
                list(Path(directory).glob(".record.json.tmp-*")), []
            )

            with self.assertRaises(FileExistsError):
                atomic_write_bytes(target, b"second\n", exclusive=True)

            self.assertEqual(target.read_bytes(), first)

    def test_exclusive_creation_does_not_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "record.json"
            atomic_write_bytes(target, b"first\n", exclusive=True)

            with self.assertRaises(FileExistsError):
                atomic_write_bytes(target, b"second\n", exclusive=True)

            self.assertEqual(target.read_bytes(), b"first\n")


if __name__ == "__main__":
    unittest.main()
