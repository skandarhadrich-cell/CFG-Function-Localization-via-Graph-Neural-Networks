"""Shared helpers for external sample collectors.

External collection is deliberately separate from the frozen BODMAS pipeline:
nothing here writes under ``data/raw/`` or ``data/versions/v2/``.  Every
download is verified against the hash that was requested from the source, then
extracted with the well-known archive password and renamed to its true SHA-256.

Hard rules enforced here:

* Nothing is ever executed.  Only hashing, archive extraction, and file moves.
* A download whose content hash does not match the requested hash is discarded.
* Downloads are resumable: a sample already present and hash-verified is skipped.
* Provenance is appended as JSONL, so every file can be traced to its query.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

EXTERNAL_ROOT = ROOT / "data" / "raw_external"
PROVENANCE_DIR = ROOT / "data" / "external_meta"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            digest.update(block)
    return digest.hexdigest()


@dataclass
class Provenance:
    """One collected candidate, whether or not it survived extraction."""

    source: str
    query: str
    sample_id: str
    family_hint: str = ""
    requested_sha256: str = ""
    observed_sha256: str = ""
    filepath: str = ""
    size: int = 0
    status: str = "ok"
    detail: str = ""
    first_seen: str = ""
    file_type: str = ""
    signature: str = ""
    tags: list[str] = field(default_factory=list)
    collected_utc: str = field(default_factory=utc_now)

    def as_line(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


class ProvenanceWriter:
    """Append-only JSONL writer, one file per source.

    Tracks which requested hashes were *successfully* collected, so a failed or
    rejected attempt is retried on the next run instead of being permanently
    blocked.
    """

    def __init__(self, source: str) -> None:
        PROVENANCE_DIR.mkdir(parents=True, exist_ok=True)
        self.path = PROVENANCE_DIR / f"{source}.jsonl"
        self._ok: set[str] = set()
        if self.path.exists():
            with self.path.open() as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("status") not in {"ok", "already_present"}:
                        continue
                    key = record.get("requested_sha256") or record.get("sample_id", "")
                    if key:
                        self._ok.add(key)

    def seen(self, key: str) -> bool:
        """True only if this hash was already collected successfully."""

        return key.lower() in self._ok

    def write(self, record: Provenance) -> None:
        with self.path.open("a") as fh:
            fh.write(record.as_line() + "\n")
        if record.status in {"ok", "already_present"}:
            key = record.requested_sha256 or record.sample_id
            if key:
                self._ok.add(key.lower())


def _index_path() -> Path:
    return PROVENANCE_DIR / "content_index.json"


def load_content_index() -> set[str]:
    """All SHA-256s already present in the external corpus, any extension.

    A small sidecar index is maintained alongside the corpus so resume does not
    depend on filename extensions or on re-hashing thousands of files.
    """

    path = _index_path()
    if not path.exists():
        return set()
    try:
        return set(json.loads(path.read_text()).get("sha256", []))
    except json.JSONDecodeError:
        return set()


def save_content_index(hashes: set[str]) -> None:
    PROVENANCE_DIR.mkdir(parents=True, exist_ok=True)
    tmp = _index_path().with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"sha256": sorted(hashes)}, indent=2) + "\n")
    os.replace(tmp, _index_path())


def load_bodmas_hashes() -> set[str]:
    """SHA-256s of the frozen BODMAS corpus (v2 manifest content hashes)."""

    hashes: set[str] = set()
    manifest = ROOT / "data" / "versions" / "v2" / "manifest.csv"
    if manifest.exists():
        import csv

        with manifest.open(newline="") as fh:
            for row in csv.DictReader(fh):
                value = (row.get("content_sha256") or "").strip()
                if value:
                    hashes.add(value.lower())
    return hashes


def load_existing_hashes() -> set[str]:
    """All SHA-256s that must not be re-collected: BODMAS plus external corpus.

    Used as a cross-source duplicate guard so the same binary can never enter
    the dataset twice under two different provenances.
    """

    return load_bodmas_hashes() | load_content_index()


def extract_zip_members(
    zip_path: Path,
    dest_dir: Path,
    password: str,
) -> tuple[list[Path], str]:
    """Extract a password-protected malware archive into ``dest_dir``.

    Returns ``(extracted_paths, detail)``.  Extraction happens directly into
    ``dest_dir`` because an archive may legitimately carry several PE files
    (a RAT plus its plugin DLLs), and each is a separate sample.  Nothing is
    executed; extraction is a pure unpack.

    Existing files are overwritten (``-aoa``), and NTFS attribute restoration
    is disabled (``-snl``): archives built on Windows make 7z exit non-zero
    while still extracting the payload correctly.  Both settings are required
    for reliable resume.
    """

    dest_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        "7z",
        "x",
        str(zip_path),
        f"-p{password}",
        f"-o{dest_dir}",
        "-y",
        "-aoa",
        "-snl",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if result.returncode != 0 and "Cannot set file attribute" not in result.stderr:
        return [], f"7z_failed: {result.stderr.strip()[:200]}"

    members = [
        p
        for p in dest_dir.rglob("*")
        if p.is_file() and not p.name.startswith(".")
    ]
    if not members:
        return [], "empty_archive"
    return sorted(members), "ok"


def download_to_file(response_content: bytes, suffix: str = ".zip") -> Path:
    PROVENANCE_DIR.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(suffix=suffix, dir=str(PROVENANCE_DIR))
    with os.fdopen(fd, "wb") as fh:
        fh.write(response_content)
    return Path(name)


def keep_as_sample(src: Path, dest_dir: Path) -> tuple[Path | None, str]:
    """Move one extracted file into the corpus under its SHA-256.

    The original extension is preserved (``.exe``, ``.dll``, ``.bin``); PE-ness
    is decided later by the Phase 0 gate, never by this collector.  Returns
    ``(final_path, observed_sha256)`` or ``(None, observed_sha256)`` when a
    file with that content hash is already present.
    """

    observed = sha256_file(src)
    suffix = src.suffix.lower() or ".bin"
    target = dest_dir / f"{observed.lower()}{suffix}"
    if target.exists():
        src.unlink(missing_ok=True)
        return None, observed
    tmp_target = dest_dir / f".{observed.lower()}{suffix}.tmp"
    os.replace(src, tmp_target)
    os.replace(tmp_target, target)
    return target, observed


def polite_sleep(seconds: float = 0.25) -> None:
    time.sleep(seconds)
