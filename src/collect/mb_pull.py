"""Hardened MalwareBazaar collector.

Query plan (see ``configs/collect_antidebug.toml``):

* targeted families via ``get_siginfo`` -- chosen because they are known to
  implement anti-debug / anti-VM behaviour;
* targeted tags via ``get_taginfo``;
* a control slice from families with no published anti-debug behaviour, so the
  positive rate is not purely an artefact of collector choice.

Every candidate is downloaded by SHA-256, hash-verified, and recorded in
``data/external_meta/malwarebazaar.jsonl``.  Nothing is executed.
"""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import Any, Iterable

import requests
from dotenv import load_dotenv

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
API_URL = "https://mb-api.abuse.ch/api/v1/"

load_dotenv(ROOT / ".env")

PE_TYPES = {"exe", "dll", "sys"}


def _headers() -> dict[str, str]:
    import os

    key = os.environ.get("MB_API_KEY", "")
    if not key:
        raise SystemExit("MB_API_KEY is not set (expected in .env)")
    return {"Auth-Key": key}


def _post(payload: dict[str, Any], retries: int = 3) -> dict[str, Any]:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            resp = requests.post(API_URL, headers=_headers(), data=payload, timeout=60)
            if resp.status_code == 200:
                return resp.json()
            last = RuntimeError(f"http {resp.status_code}")
        except Exception as exc:  # noqa: BLE001
            last = exc
        polite_sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"MalwareBazaar request failed: {last}")


def query_signature(signature: str, limit: int) -> list[dict[str, Any]]:
    data = _post({"query": "get_siginfo", "signature": signature, "limit": limit})
    if data.get("query_status") != "ok":
        return []
    return data.get("data", []) or []


def query_tag(tag: str, limit: int) -> list[dict[str, Any]]:
    data = _post({"query": "get_taginfo", "tag": tag, "limit": limit})
    if data.get("query_status") != "ok":
        return []
    return data.get("data", []) or []


def query_hash(sha256: str) -> dict[str, Any] | None:
    data = _post({"query": "get_info", "hash": sha256})
    if data.get("query_status") != "ok":
        return None
    rows = data.get("data", [])
    return rows[0] if rows else None


def download_sample(sha256: str) -> bytes | None:
    resp = requests.post(
        API_URL,
        headers=_headers(),
        data={"query": "get_file", "sha256_hash": sha256},
        timeout=120,
    )
    if resp.status_code != 200 or len(resp.content) < 128:
        return None
    if resp.headers.get("content-type", "").startswith("application/json"):
        return None
    return resp.content


def _is_pe(row: dict[str, Any]) -> bool:
    return (row.get("file_type") or "").lower() in PE_TYPES


def collect(
    *,
    config_path: Path,
    probe: bool,
    only: str | None = None,
) -> dict[str, Any]:
    cfg = tomllib.loads(config_path.read_text())
    per_family = cfg["limits"]["probe_per_family" if probe else "per_family"]
    per_tag = cfg["limits"]["probe_per_tag" if probe else "per_tag"]

    writer = ProvenanceWriter("malwarebazaar")
    existing = load_existing_hashes()
    external_hashes = load_content_index()

    targets: list[tuple[str, str, str]] = []  # (kind, value, family_hint)
    for family in cfg["targeted"]["signatures"]:
        targets.append(("signature", family, family))
    for tag in cfg["targeted"]["tags"]:
        targets.append(("tag", tag, f"tag_{tag}"))
    for family in cfg["control"]["signatures"]:
        targets.append(("signature", family, f"control_{family}"))

    if only:
        targets = [t for t in targets if t[1].lower() == only.lower()]

    stats: dict[str, Any] = {
        "candidates": 0,
        "skipped_known": 0,
        "skipped_non_pe": 0,
        "downloaded": 0,
        "extracted": 0,
        "failed": 0,
        "per_query": {},
    }

    for kind, value, family_hint in targets:
        limit = per_tag if kind == "tag" else per_family
        try:
            rows = query_signature(value, limit) if kind == "signature" else query_tag(value, limit)
        except Exception as exc:  # noqa: BLE001
            stats["per_query"][f"{kind}:{value}"] = {"error": str(exc)}
            continue

        query_stats = {"returned": len(rows), "downloaded": 0, "skipped": 0, "failed": 0}
        for row in rows:
            sha256 = (row.get("sha256_hash") or "").lower()
            if not sha256:
                continue
            stats["candidates"] += 1
            if not _is_pe(row):
                stats["skipped_non_pe"] += 1
                continue
            if sha256 in existing or writer.seen(sha256):
                stats["skipped_known"] += 1
                query_stats["skipped"] += 1
                continue

            try:
                blob = download_sample(sha256)
            except Exception as exc:  # noqa: BLE001
                stats["failed"] += 1
                query_stats["failed"] += 1
                writer.write(
                    Provenance(
                        source="malwarebazaar",
                        query=f"{kind}:{value}",
                        sample_id=sha256,
                        family_hint=family_hint,
                        requested_sha256=sha256,
                        status="download_error",
                        detail=str(exc)[:200],
                        first_seen=row.get("first_seen", ""),
                        file_type=row.get("file_type", ""),
                        signature=row.get("signature", ""),
                        tags=row.get("tags") or [],
                    )
                )
                continue

            stats["downloaded"] += 1
            if blob is None:
                stats["failed"] += 1
                query_stats["failed"] += 1
                writer.write(
                    Provenance(
                        source="malwarebazaar",
                        query=f"{kind}:{value}",
                        sample_id=sha256,
                        family_hint=family_hint,
                        requested_sha256=sha256,
                        status="download_empty",
                        first_seen=row.get("first_seen", ""),
                        file_type=row.get("file_type", ""),
                        signature=row.get("signature", ""),
                        tags=row.get("tags") or [],
                    )
                )
                continue

            zip_path = download_to_file(blob)
            dest = EXTERNAL_ROOT / "malwarebazaar" / family_hint
            members, detail = extract_zip_members(
                zip_path, dest, cfg["limits"]["archive_password"]
            )
            zip_path.unlink(missing_ok=True)

            extracted = None
            observed = ""
            if members:
                # MalwareBazaar ships a single payload per archive; keep the
                # largest member (readme stubs are occasionally bundled).
                member = max(members, key=lambda p: p.stat().st_size)
                extracted, observed = keep_as_sample(member, dest)
                for extra in members:
                    if extra != member:
                        extra.unlink(missing_ok=True)

            if extracted is not None:
                stats["extracted"] += 1
                query_stats["downloaded"] += 1
                existing.add(observed.lower())
                external_hashes.add(observed.lower())
                status = "ok"
            elif observed:
                # Content already present under this hash: a true duplicate.
                stats["skipped_known"] += 1
                query_stats["skipped"] += 1
                status = "already_present"
            else:
                stats["failed"] += 1
                query_stats["failed"] += 1
                status = detail

            writer.write(
                Provenance(
                    source="malwarebazaar",
                    query=f"{kind}:{value}",
                    sample_id=observed or sha256,
                    family_hint=family_hint,
                    requested_sha256=sha256,
                    observed_sha256=observed,
                    filepath=str(extracted) if extracted else "",
                    size=extracted.stat().st_size if extracted else 0,
                    status=status,
                    detail=detail if extracted is None else "",
                    first_seen=row.get("first_seen", ""),
                    file_type=row.get("file_type", ""),
                    signature=row.get("signature", ""),
                    tags=row.get("tags") or [],
                )
            )
            polite_sleep(0.2)

        stats["per_query"][f"{kind}:{value}"] = query_stats

    save_content_index(external_hashes)
    return stats


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config", type=Path, default=ROOT / "configs" / "collect_antidebug.toml"
    )
    parser.add_argument("--probe", action="store_true", help="small per-query limits")
    parser.add_argument("--only", help="run a single signature/tag")
    parser.add_argument(
        "--summary", type=Path, default=ROOT / "results" / "collect" / "mb_summary.json"
    )
    args = parser.parse_args(argv)

    stats = collect(config_path=args.config, probe=args.probe, only=args.only)
    args.summary.parent.mkdir(parents=True, exist_ok=True)
    args.summary.write_text(json.dumps(stats, indent=2) + "\n")
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
