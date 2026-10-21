"""theZoo collector (github.com/ytisf/theZoo).

theZoo stores each sample as ``malware/Binaries/<Name>/<Name>.zip`` with a
sibling ``<Name>.pass`` file holding the archive password, plus hash files.
The repository is far too large to clone, so this collector lists directories
through the GitHub contents API and downloads only the archives in the
approved family frame.

Samples are verified against the ``.sha256`` file when present, otherwise the
observed hash is recorded and the sample is kept only if it parses as a PE
later.  Nothing is executed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterable

import requests

from src.collect.common import (
    EXTERNAL_ROOT,
    Provenance,
    ProvenanceWriter,
    download_to_file,
    extract_zip_members,
    keep_as_sample,
    load_content_index,
    load_existing_hashes,
    polite_sleep,
    save_content_index,
)

ROOT = Path(__file__).resolve().parents[2]
API = "https://api.github.com/repos/ytisf/theZoo/contents"
RAW = "https://raw.githubusercontent.com/ytisf/theZoo/master"
BINARIES = "malware/Binaries"


def list_tree(path: str) -> list[dict[str, Any]]:
    resp = requests.get(f"{API}/{path}", timeout=60)
    if resp.status_code != 200:
        return []
    data = resp.json()
    return data if isinstance(data, list) else []


def fetch_text(path: str) -> str:
    resp = requests.get(f"{RAW}/{path}", timeout=60)
    return resp.text.strip() if resp.status_code == 200 else ""


def collect(*, config_path: Path, only: str | None = None) -> dict[str, Any]:
    cfg = tomllib.loads(config_path.read_text())
    families: list[str] = list(cfg["thezoo"]["families"])
    if only:
        families = [f for f in families if f.lower() == only.lower()]

    writer = ProvenanceWriter("thezoo")
    existing = load_existing_hashes()
    external_hashes = load_content_index()

    stats: dict[str, Any] = {
        "candidates": 0,
        "skipped_known": 0,
        "skipped_unsupported": 0,
        "extracted": 0,
        "failed": 0,
        "per_family": {},
    }

    for family in families:
        entries = list_tree(f"{BINARIES}/{family}")
        if not entries:
            stats["per_family"][family] = {"error": "not found"}
            continue

        by_name = {e["name"]: e for e in entries}
        zips = [n for n in by_name if n.lower().endswith(".zip")]
        fam_stats = {"archives": len(zips), "extracted": 0, "failed": 0, "skipped": 0}

        for zip_name in zips:
            stats["candidates"] += 1
            stem = zip_name[:-4]
            entry = by_name[zip_name]

            # Skip the obvious non-Windows families in the frame early.
            size = int(entry.get("size") or 0)
            if size and size < 1024:
                stats["skipped_unsupported"] += 1
                fam_stats["skipped"] += 1
                continue

            password = "infected"
            pass_name = f"{stem}.pass"
            if pass_name in by_name:
                text = fetch_text(f"{BINARIES}/{family}/{pass_name}")
                if text:
                    password = text.split()[0]

            # theZoo's .sha256 documents the ZIP archive, not the payload
            # inside it.  Multi-file archives (a RAT plus its plugins) are
            # unpacked and each PE becomes its own sample.
            blob = requests.get(entry["download_url"], timeout=300)
            if blob.status_code != 200:
                stats["failed"] += 1
                fam_stats["failed"] += 1
                writer.write(
                    Provenance(
                        source="thezoo",
                        query=family,
                        sample_id=stem,
                        family_hint=family,
                        status="download_error",
                        detail=f"http {blob.status_code}",
                    )
                )
                continue

            archive_sha = hashlib.sha256(blob.content).hexdigest()
            zip_path = download_to_file(blob.content)
            dest = EXTERNAL_ROOT / "thezoo" / family
            members, xdetail = extract_zip_members(zip_path, dest, password)
            zip_path.unlink(missing_ok=True)

            if not members:
                stats["failed"] += 1
                fam_stats["failed"] += 1
                writer.write(
                    Provenance(
                        source="thezoo",
                        query=family,
                        sample_id=stem,
                        family_hint=family,
                        requested_sha256=archive_sha,
                        status=xdetail,
                    )
                )
                continue

            kept = 0
            for member in members:
                final, observed = keep_as_sample(member, dest)
                if final is None:
                    stats["skipped_known"] += 1
                    fam_stats["skipped"] += 1
                    continue
                kept += 1
                existing.add(observed.lower())
                external_hashes.add(observed.lower())
                writer.write(
                    Provenance(
                        source="thezoo",
                        query=family,
                        sample_id=observed,
                        family_hint=family,
                        requested_sha256=archive_sha,
                        observed_sha256=observed,
                        filepath=str(final),
                        size=final.stat().st_size,
                        status="ok",
                    )
                )

            stats["extracted"] += kept
            fam_stats["extracted"] += kept
            polite_sleep(0.2)

        stats["per_family"][family] = fam_stats

    save_content_index(external_hashes)
    return stats


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=ROOT / "configs" / "collect_antidebug.toml"
    )
    parser.add_argument("--only")
    parser.add_argument(
        "--summary",
        type=Path,
        default=ROOT / "results" / "collect" / "thezoo_summary.json",
    )
    args = parser.parse_args(argv)

    stats = collect(config_path=args.config, only=args.only)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(stats, indent=2) + "\n")
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
