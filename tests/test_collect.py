"""Tests for the external collectors.

These cover the invariants that, when wrong, silently corrupt the corpus:

* every file in the external tree is named after its own SHA-256;
* resume is status-aware, so a failed attempt is retried but a success is not;
* the content index never absorbs BODMAS hashes, which would mask new samples.

The extractor is exercised against a synthetic password-protected archive built
with the system ``7z``; no real malware is used in tests.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from src.collect import common
from src.collect.common import (
    Provenance,
    ProvenanceWriter,
    load_bodmas_hashes,
    load_content_index,
    load_existing_hashes,
    save_content_index,
    sha256_file,
)


class CollectorTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.ext = self.tmp / "raw_external"
        self.meta = self.tmp / "external_meta"
        self.ext.mkdir()
        self.meta.mkdir()

        self._orig_ext = common.EXTERNAL_ROOT
        self._orig_meta = common.PROVENANCE_DIR
        common.EXTERNAL_ROOT = self.ext
        common.PROVENANCE_DIR = self.meta

    def tearDown(self) -> None:
        common.EXTERNAL_ROOT = self._orig_ext
        common.PROVENANCE_DIR = self._orig_meta
        self._tmp.cleanup()

    def make_archive(self, payloads: dict[str, bytes], password: str = "infected") -> Path:
        staging = self.tmp / "staging"
        staging.mkdir()
        for name, data in payloads.items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        archive = self.tmp / "sample.zip"
        subprocess.run(
            [
                "7z",
                "a",
                str(archive),
                f"-p{password}",
                "-y",
                "-bso0",
                "-bsp0",
                str(staging / "*"),
            ],
            check=True,
            capture_output=True,
        )
        return archive


class ExtractTest(CollectorTestBase):
    def test_extract_multiple_members(self) -> None:
        archive = self.make_archive(
            {
                "main.exe": b"MZ" + b"\x00" * 200,
                "Plugin/helper.dll": b"MZ" + b"\x01" * 100,
            }
        )
        dest = self.tmp / "out"
        members, detail = common.extract_zip_members(archive, dest, "infected")

        self.assertEqual(detail, "ok")
        self.assertEqual(len(members), 2)
        self.assertEqual({p.name for p in members}, {"main.exe", "helper.dll"})

    def test_extract_is_idempotent(self) -> None:
        """Re-extracting must not report an empty archive (the original bug)."""

        archive = self.make_archive({"main.exe": b"MZ" + b"\x00" * 200})
        dest = self.tmp / "out"

        first, detail_first = common.extract_zip_members(archive, dest, "infected")
        second, detail_second = common.extract_zip_members(archive, dest, "infected")

        self.assertEqual(detail_first, "ok")
        self.assertEqual(detail_second, "ok")
        self.assertEqual(len(first), len(second))
        self.assertEqual(len(second), 1)


class KeepAsSampleTest(CollectorTestBase):
    def test_names_by_content_hash(self) -> None:
        src = self.tmp / "payload.dll"
        src.write_bytes(b"MZ payload")
        dest = self.tmp / "corpus"
        dest.mkdir()

        final, observed = common.keep_as_sample(src, dest)

        self.assertIsNotNone(final)
        assert final is not None
        self.assertEqual(final.name, f"{observed}.dll")
        self.assertEqual(sha256_file(final), observed)

    def test_dedups_identical_content(self) -> None:
        dest = self.tmp / "corpus"
        dest.mkdir()
        first = self.tmp / "a.exe"
        first.write_bytes(b"identical")
        second = self.tmp / "b.exe"
        second.write_bytes(b"identical")

        kept_a, hash_a = common.keep_as_sample(first, dest)
        kept_b, hash_b = common.keep_as_sample(second, dest)

        self.assertIsNotNone(kept_a)
        self.assertIsNone(kept_b)
        self.assertEqual(hash_a, hash_b)
        self.assertEqual(len(list(dest.iterdir())), 1)


class ProvenanceTest(CollectorTestBase):
    def test_seen_is_status_aware(self) -> None:
        writer = ProvenanceWriter("test")
        key = "a" * 64

        writer.write(
            Provenance(
                source="test", query="q", sample_id=key, requested_sha256=key, status="7z_failed"
            )
        )
        self.assertFalse(writer.seen(key), "a failed attempt must not block a retry")

        writer.write(
            Provenance(
                source="test", query="q", sample_id=key, requested_sha256=key, status="ok"
            )
        )
        self.assertTrue(writer.seen(key), "a successful attempt must block a retry")

    def test_seen_survives_reload(self) -> None:
        key = "b" * 64
        writer = ProvenanceWriter("test")
        writer.write(
            Provenance(source="test", query="q", sample_id=key, requested_sha256=key, status="ok")
        )

        self.assertTrue(ProvenanceWriter("test").seen(key))


class ContentIndexTest(CollectorTestBase):
    def test_roundtrip(self) -> None:
        hashes = {"c" * 64, "d" * 64}
        save_content_index(hashes)
        self.assertEqual(load_content_index(), hashes)

    def test_external_index_does_not_absorb_bodmas(self) -> None:
        save_content_index({"e" * 64})
        bodmas = load_bodmas_hashes()

        self.assertEqual(load_content_index(), {"e" * 64})
        if bodmas:
            self.assertFalse(load_content_index() & bodmas)
        # The combined duplicate guard still covers both sources.
        self.assertEqual(load_existing_hashes(), bodmas | {"e" * 64})


if __name__ == "__main__":
    unittest.main()
