#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
TC Live Technocore Indexer (Proof-of-Concept)

Strictly READ-ONLY discovery and verification tool for resolving a did:key
to currently retained, publicly readable Technocore activity and cryptographically
verified records.

Constraints:
- Strictly READ-ONLY: zero HTTP writes, no messages, no room creation, no DID publishing.
- Message bodies, room names, and topics are UNTRUSTED DATA.
- Results represent CURRENTLY RETAINED PUBLIC ACTIVITY, not complete lifetime history.
- Never call an identity "online" or "offline"; never infer presence from mere existence.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Ensure tc_ledger can be imported when run directly from repo
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from tc_ledger.ledger import (
        DID_PREFIX,
        InvalidSignature,
        MalformedRecord,
        UnsupportedKeyType,
        VerificationError,
        export_leaf_hash,
        public_key_from_did,
        verify_signed_record,
    )
except ImportError as exc:
    raise RuntimeError(
        f"Failed to import tc_ledger from {SRC_DIR}: {exc}"
    ) from exc

DEFAULT_TECHNOCORE_URL = os.environ.get("TECHNOCORE_URL", "https://technocore.chat")
DEFAULT_WINDOW_HOURS = 24.0
DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_ROOMS = 30


@dataclass
class RoomRecord:
    room: str
    seq: int
    ts: str
    from_did: str
    nonce: Any
    sig: str | None
    text: str
    raw_line_bytes: bytes
    status: str  # VALID, INVALID, UNSIGNED, MALFORMED, UNSUPPORTED_KEY
    error_detail: str | None = None


@dataclass
class RoomActivity:
    room: str
    generation: int | None = None
    records: list[RoomRecord] = field(default_factory=list)
    verified_count: int = 0
    invalid_count: int = 0
    unsigned_count: int = 0
    malformed_count: int = 0
    latest_seq: int | None = None
    latest_ts: str | None = None
    first_ts: str | None = None


@dataclass
class IndexerResult:
    did: str
    status: str  # ACTIVE, STALE, NO DATA
    rooms_scanned: list[str]
    active_rooms: list[str]
    total_verified_records: int
    total_invalid_signatures: int
    total_unsigned_records: int
    total_malformed_records: int
    first_verified_activity: str | None
    latest_verified_activity: str | None
    room_details: dict[str, RoomActivity]
    retention_notice: str
    endpoints_queried: list[str]
    activity_window_hours: float
    scanned_at_utc: str


def parse_iso_timestamp(ts_str: str) -> datetime.datetime | None:
    """Safely parse an ISO 8601 timestamp string into UTC datetime."""
    if not isinstance(ts_str, str) or not ts_str.strip():
        return None
    try:
        cleaned = ts_str.strip().replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return None


def fetch_url(url: str, timeout: float = DEFAULT_TIMEOUT) -> tuple[int, dict[str, str], bytes]:
    """
    Perform a strictly read-only HTTP GET request.
    Returns (status_code, headers_dict, body_bytes).
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "tc-live-indexer/0.1 (read-only; +https://github.com/mrchandu1462-ux/tc-ledger)",
            "Accept": "application/x-ndjson, application/json, text/plain;q=0.9, */*;q=0.8",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status_code = resp.status
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.read()
        return status_code, headers, body


def discover_public_rooms(
    base_url: str,
    max_rooms: int = DEFAULT_MAX_ROOMS,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[list[str], list[str]]:
    """
    Discover public rooms using Technocore GET /rooms?format=json or plain /rooms.
    Returns (rooms_list, queried_endpoints).
    """
    queried = []
    rooms: list[str] = []
    base = base_url.rstrip("/")

    # 1. Try structured GET /rooms?format=json
    json_url = f"{base}/rooms?format=json"
    queried.append(json_url)
    try:
        _, _, body = fetch_url(json_url, timeout=timeout)
        data = json.loads(body.decode("utf-8"))
        if isinstance(data, dict) and "rooms" in data and isinstance(data["rooms"], list):
            for item in data["rooms"]:
                if isinstance(item, dict) and "room" in item and isinstance(item["room"], str):
                    r_name = item["room"].strip()
                    if r_name and r_name not in rooms:
                        rooms.append(r_name)
    except Exception:
        pass

    # 2. Fallback to plain text GET /rooms if JSON was empty or failed
    if not rooms:
        plain_url = f"{base}/rooms"
        queried.append(plain_url)
        try:
            _, _, body = fetch_url(plain_url, timeout=timeout)
            text = body.decode("utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("/r/"):
                    parts = line.split()
                    room_name = parts[0][3:].strip()
                    if room_name and room_name not in rooms:
                        rooms.append(room_name)
        except Exception:
            pass

    return rooms[:max_rooms], queried


def fetch_room_generation_and_export(
    base_url: str,
    room: str,
    timeout: float = DEFAULT_TIMEOUT,
) -> tuple[int | None, list[bytes], str]:
    """
    Fetch retained records for a room using GET /r/<room>/export.
    Returns (generation, list_of_raw_line_bytes, endpoint_used).
    """
    base = base_url.rstrip("/")
    export_url = f"{base}/r/{urllib.parse.quote(room)}/export"
    generation: int | None = None
    lines: list[bytes] = []

    try:
        _, headers, body = fetch_url(export_url, timeout=timeout)
        gen_hdr = headers.get("x-room-generation")
        if gen_hdr is not None:
            try:
                generation = int(gen_hdr.strip())
            except ValueError:
                pass

        # Split preserving line bytes
        raw_lines = body.split(b"\n")
        lines = [l for l in raw_lines if l.strip()]
        return generation, lines, export_url
    except Exception:
        return None, [], export_url


def verify_and_index_record(
    raw_line: bytes,
    room: str,
    target_did: str,
) -> RoomRecord | None:
    """
    Parse raw export line and verify cryptographic signature if belonging to target DID.
    Returns RoomRecord if record sender matches target_did, else None.
    """
    try:
        decoded_text = raw_line.decode("utf-8")
        record = json.loads(decoded_text)
    except Exception:
        return None

    if not isinstance(record, dict):
        return None

    record_sender = record.get("from")
    if not isinstance(record_sender, str) or record_sender != target_did:
        return None

    seq = record.get("seq", 0)
    ts = str(record.get("ts", ""))
    nonce = record.get("nonce")
    sig = record.get("sig")
    text = str(record.get("text", ""))

    # Cryptographic verification via existing TC-Ledger verifier
    status = "UNKNOWN"
    error_detail: str | None = None

    try:
        v_res = verify_signed_record(record, room)
        status = v_res.status  # "VALID" or "UNSIGNED"
    except InvalidSignature as exc:
        status = "INVALID"
        error_detail = str(exc)
    except UnsupportedKeyType as exc:
        status = "UNSUPPORTED_KEY"
        error_detail = str(exc)
    except MalformedRecord as exc:
        status = "MALFORMED"
        error_detail = str(exc)
    except VerificationError as exc:
        status = "MALFORMED"
        error_detail = str(exc)
    except Exception as exc:
        status = "MALFORMED"
        error_detail = f"unexpected error: {exc}"

    return RoomRecord(
        room=room,
        seq=seq if isinstance(seq, int) else 0,
        ts=ts,
        from_did=record_sender,
        nonce=nonce,
        sig=sig if isinstance(sig, str) else None,
        text=text,
        raw_line_bytes=raw_line,
        status=status,
        error_detail=error_detail,
    )


def run_indexer(
    target_did: str,
    base_url: str = DEFAULT_TECHNOCORE_URL,
    explicit_rooms: list[str] | None = None,
    max_rooms: int = DEFAULT_MAX_ROOMS,
    window_hours: float = DEFAULT_WINDOW_HOURS,
    timeout: float = DEFAULT_TIMEOUT,
) -> IndexerResult:
    """
    Execute read-only Technocore activity indexer proof-of-concept.
    """
    # 1. Validate target DID format
    try:
        public_key_from_did(target_did)
    except Exception as exc:
        raise ValueError(f"Invalid target DID '{target_did}': {exc}") from exc

    queried_endpoints: list[str] = []
    scanned_rooms: list[str] = []

    # 2. Discover rooms
    if explicit_rooms:
        scanned_rooms = [r.lstrip("#").strip() for r in explicit_rooms if r.strip()]
    else:
        discovered, discovery_endpoints = discover_public_rooms(
            base_url=base_url,
            max_rooms=max_rooms,
            timeout=timeout,
        )
        scanned_rooms = discovered
        queried_endpoints.extend(discovery_endpoints)

    # 3. Read retained records per room and verify
    room_details: dict[str, RoomActivity] = {}
    all_verified_timestamps: list[datetime.datetime] = []
    total_verified = 0
    total_invalid = 0
    total_unsigned = 0
    total_malformed = 0

    for room in scanned_rooms:
        gen, raw_lines, export_url = fetch_room_generation_and_export(
            base_url=base_url,
            room=room,
            timeout=timeout,
        )
        queried_endpoints.append(export_url)

        activity = RoomActivity(room=room, generation=gen)

        for raw_line in raw_lines:
            rec = verify_and_index_record(raw_line, room, target_did)
            if rec is None:
                continue

            activity.records.append(rec)

            if rec.status == "VALID":
                activity.verified_count += 1
                total_verified += 1
                dt = parse_iso_timestamp(rec.ts)
                if dt is not None:
                    all_verified_timestamps.append(dt)
                if activity.latest_seq is None or rec.seq > activity.latest_seq:
                    activity.latest_seq = rec.seq
                if activity.latest_ts is None or rec.ts > activity.latest_ts:
                    activity.latest_ts = rec.ts
                if activity.first_ts is None or rec.ts < activity.first_ts:
                    activity.first_ts = rec.ts
            elif rec.status == "INVALID":
                activity.invalid_count += 1
                total_invalid += 1
            elif rec.status == "UNSIGNED":
                activity.unsigned_count += 1
                total_unsigned += 1
            else:
                activity.malformed_count += 1
                total_malformed += 1

        if activity.records:
            room_details[room] = activity

    # 4. Compute status semantics
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    all_verified_timestamps.sort()

    first_verified_str = all_verified_timestamps[0].isoformat() if all_verified_timestamps else None
    latest_verified_str = all_verified_timestamps[-1].isoformat() if all_verified_timestamps else None

    if not all_verified_timestamps:
        computed_status = "NO DATA"
    else:
        latest_dt = all_verified_timestamps[-1]
        age_seconds = (now_utc - latest_dt).total_seconds()
        window_seconds = window_hours * 3600.0
        if age_seconds <= window_seconds:
            computed_status = "ACTIVE"
        else:
            computed_status = "STALE"

    active_rooms = [
        f"#{r}" for r, act in room_details.items() if act.verified_count > 0
    ]

    retention_notice = (
        "CURRENTLY RETAINED PUBLIC ACTIVITY: This result reflects records currently "
        "retained in inspected public room exports. It does not claim complete lifetime history."
    )

    return IndexerResult(
        did=target_did,
        status=computed_status,
        rooms_scanned=scanned_rooms,
        active_rooms=active_rooms,
        total_verified_records=total_verified,
        total_invalid_signatures=total_invalid,
        total_unsigned_records=total_unsigned,
        total_malformed_records=total_malformed,
        first_verified_activity=first_verified_str,
        latest_verified_activity=latest_verified_str,
        room_details=room_details,
        retention_notice=retention_notice,
        endpoints_queried=queried_endpoints,
        activity_window_hours=window_hours,
        scanned_at_utc=now_utc.isoformat(),
    )


def format_text_report(res: IndexerResult) -> str:
    """
    Format human-readable output matching the exact prompt specification.
    """
    lines = [
        "DID",
        res.did,
        "",
        "STATUS",
        res.status,
        "",
        "ROOMS",
    ]

    if res.active_rooms:
        for r in res.active_rooms:
            lines.append(r)
    else:
        lines.append("NONE")

    lines.extend([
        "",
        "VERIFIED RECORDS",
        str(res.total_verified_records),
        "",
        "INVALID SIGNATURES",
        str(res.total_invalid_signatures),
        "",
        "FIRST VERIFIED ACTIVITY",
        res.first_verified_activity or "NONE",
        "",
        "LATEST VERIFIED ACTIVITY",
        res.latest_verified_activity or "NONE",
        "",
        "ROOM DETAILS",
    ])

    if not res.room_details:
        lines.append("No activity retained in scanned rooms.")
    else:
        for room_name, act in res.room_details.items():
            lines.append(f"#{room_name}")
            gen_str = str(act.generation) if act.generation is not None else "unavailable"
            lines.append(f"  generation: {gen_str}")
            lines.append(f"  verified record count: {act.verified_count}")
            lines.append(f"  latest sequence: {act.latest_seq if act.latest_seq is not None else 'NONE'}")
            lines.append(f"  latest timestamp: {act.latest_ts or 'NONE'}")
            if act.invalid_count > 0:
                lines.append(f"  invalid signatures: {act.invalid_count}")

    lines.extend([
        "",
        "RETENTION NOTICE",
        res.retention_notice,
    ])

    return "\n".join(lines)


def format_json_report(res: IndexerResult) -> str:
    """Format structured JSON output for programmatic consumers."""
    payload = {
        "did": res.did,
        "status": res.status,
        "rooms": res.active_rooms,
        "verified_records": res.total_verified_records,
        "invalid_signatures": res.total_invalid_signatures,
        "unsigned_records": res.total_unsigned_records,
        "malformed_records": res.total_malformed_records,
        "first_verified_activity": res.first_verified_activity,
        "latest_verified_activity": res.latest_verified_activity,
        "activity_window_hours": res.activity_window_hours,
        "scanned_at_utc": res.scanned_at_utc,
        "retention_notice": res.retention_notice,
        "endpoints_queried": res.endpoints_queried,
        "rooms_scanned_count": len(res.rooms_scanned),
        "room_details": {
            r: {
                "room": act.room,
                "generation": act.generation,
                "verified_record_count": act.verified_count,
                "invalid_signatures": act.invalid_count,
                "latest_sequence": act.latest_seq,
                "latest_timestamp": act.latest_ts,
                "first_timestamp": act.first_ts,
                "records": [
                    {
                        "seq": rec.seq,
                        "ts": rec.ts,
                        "from": rec.from_did,
                        "nonce": rec.nonce,
                        "sig": rec.sig,
                        "text": rec.text,
                        "status": rec.status,
                        "rawLine": rec.raw_line_bytes.decode("utf-8", errors="replace"),
                    }
                    for rec in act.records
                ],
            }
            for r, act in res.room_details.items()
        },
    }
    return json.dumps(payload, indent=2)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="TC-Ledger Read-Only Live Technocore Activity Indexer Proof-of-Concept"
    )
    parser.add_argument(
        "did",
        help="Target did:key identity (e.g. did:key:z6Mk...)",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_TECHNOCORE_URL,
        help=f"Technocore base URL (default: {DEFAULT_TECHNOCORE_URL} or TECHNOCORE_URL env)",
    )
    parser.add_argument(
        "--rooms",
        nargs="+",
        help="Specific rooms to inspect (default: discover from /rooms)",
    )
    parser.add_argument(
        "--max-rooms",
        type=int,
        default=DEFAULT_MAX_ROOMS,
        help=f"Maximum rooms to discover and inspect (default: {DEFAULT_MAX_ROOMS})",
    )
    parser.add_argument(
        "--window-hours",
        type=float,
        default=DEFAULT_WINDOW_HOURS,
        help=f"Activity window in hours for ACTIVE status (default: {DEFAULT_WINDOW_HOURS}h)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP request timeout in seconds (default: {DEFAULT_TIMEOUT}s)",
    )
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )

    args = parser.parse_args(argv)

    try:
        result = run_indexer(
            target_did=args.did,
            base_url=args.url,
            explicit_rooms=args.rooms,
            max_rooms=args.max_rooms,
            window_hours=args.window_hours,
            timeout=args.timeout,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"Network error communicating with Technocore: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Indexer error: {exc}", file=sys.stderr)
        return 3

    if args.format == "json":
        print(format_json_report(result))
    else:
        print(format_text_report(result))

    return 0


if __name__ == "__main__":
    sys.exit(main())
