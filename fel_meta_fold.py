# fel_meta_fold.py
"""
META_FOLD Attestation Executor (FEL v1.1)
- Deterministic, replayable attestation chain
- Canonical JSON hashing rules
- ABI + policy pinning (no drift)
"""

from __future__ import annotations

import hashlib
import json
import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

# -----------------------------
# Canonicalization (verifier law)
# -----------------------------

TOP_LEVEL_ORDER = [
    "v",
    "tick",
    "type",
    "fold",
    "id",
    "ref",
    "payload",
    "key",
    "value",
    "patch",
    "lane",
    "root",
    "source",
    "policy_hash",
    "meta_hash",
    "abi_hash",
    "prev",
]

EXCLUDED_FROM_HASH = {"timestamp"}  # observational only, never hashed


def _strip_observational(x: Any) -> Any:
    """Remove observational keys recursively (e.g., timestamp)."""
    if isinstance(x, dict):
        return {k: _strip_observational(v) for k, v in x.items() if k not in EXCLUDED_FROM_HASH}
    if isinstance(x, list):
        return [_strip_observational(v) for v in x]
    return x


def canon_json(obj: Dict[str, Any]) -> bytes:
    """
    Canonical JSON bytes:
    - removes observational keys (timestamp)
    - stable key order (top-level per TOP_LEVEL_ORDER, then remaining sorted)
    - nested dict keys sorted
    - minimal separators
    """
    obj = _strip_observational(obj)

    def order_top(d: Dict[str, Any]) -> Dict[str, Any]:
        ordered: Dict[str, Any] = {}
        # top-level prioritized keys
        for k in TOP_LEVEL_ORDER:
            if k in d:
                ordered[k] = d[k]
        # remaining keys sorted
        for k in sorted(d.keys()):
            if k not in ordered:
                ordered[k] = d[k]
        return ordered

    def normalize(x: Any, top: bool = False) -> Any:
        if isinstance(x, dict):
            if top:
                d = order_top(x)
            else:
                d = {k: x[k] for k in sorted(x.keys())}
            return {k: normalize(v, top=False) for k, v in d.items()}
        if isinstance(x, list):
            return [normalize(v, top=False) for v in x]
        return x

    norm = normalize(obj, top=True)
    return json.dumps(norm, ensure_ascii=False, separators=(",", ":"), sort_keys=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# -----------------------------
# META_FOLD stream + pinning
# -----------------------------


@dataclass(frozen=True)
class AttestationRecord:
    tick: int
    att_hash: str
    prev: Optional[str]
    policy_hash: str
    meta_hash: str
    abi_hash: str
    canon_bytes: bytes


class MetaFoldExecutor:
    """
    A deterministic attestation engine for one stream.
    """

    def __init__(self, stream_id: str, policy_hash: str, abi_hash: str):
        self.stream_id = stream_id
        self._pinned_policy = policy_hash
        self._pinned_abi = abi_hash
        self._head: Optional[str] = None
        self._records: List[AttestationRecord] = []

    @property
    def head(self) -> Optional[str]:
        return self._head

    @property
    def records(self) -> List[AttestationRecord]:
        return list(self._records)

    def _enforce_pinning(self, policy_hash: str, abi_hash: str) -> None:
        if policy_hash != self._pinned_policy:
            raise ValueError("policy_hash drift (forbidden in FEL v1.1 stream)")
        if abi_hash != self._pinned_abi:
            raise ValueError("abi_hash drift (forbidden in FEL v1.1 stream)")

    def attest(
        self,
        tick: int,
        meta_hash: str,
        prev: Optional[str] = None,
        *,
        v: str = "fel.v1.1",
    ) -> AttestationRecord:
        """
        Create and append an attestation line and compute its deterministic hash.
        Chain rule:
          - if head is None: prev must be None or "0"*64 (genesis)
          - else: prev must equal current head
        """
        if not isinstance(tick, int) or tick < 0:
            raise ValueError("tick must be int >= 0")

        # Pinning
        self._enforce_pinning(self._pinned_policy, self._pinned_abi)

        # Chain enforcement
        if self._head is None:
            if prev in ("0" * 64, None):
                prev_norm = None
            else:
                raise ValueError("genesis prev must be null or 64x0")
        else:
            if prev != self._head:
                raise ValueError("prev must equal current head")
            prev_norm = prev

        line = {
            "v": v,
            "tick": tick,
            "type": "attest",
            "fold": "⟁META_FOLD⟁",
            "policy_hash": self._pinned_policy,
            "meta_hash": meta_hash,
            "abi_hash": self._pinned_abi,
        }
        if prev_norm is not None:
            line["prev"] = prev_norm

        cb = canon_json(line)
        ah = sha256_hex(cb)

        rec = AttestationRecord(
            tick=tick,
            att_hash=ah,
            prev=prev_norm,
            policy_hash=self._pinned_policy,
            meta_hash=meta_hash,
            abi_hash=self._pinned_abi,
            canon_bytes=cb,
        )

        self._records.append(rec)
        self._head = ah
        return rec

    # -----------------------------
    # Recommended meta-hash builder
    # -----------------------------

    def compute_meta_hash(
        self,
        *,
        state_root_sha256: str,
        lane_roots: Optional[Dict[str, str]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Domain-separated meta hash:
          meta_hash = sha256( canon({domain, stream_id, state_root, lane_roots, extra}) )
        """
        payload = {
            "domain": "fel.meta.v1.1",
            "stream_id": self.stream_id,
            "state_root_sha256": state_root_sha256,
            "lane_roots": lane_roots or {},
            "extra": extra or {},
        }
        return sha256_hex(canon_json(payload))


def main() -> int:
    """Build an attestation JSONL sidecar from caller-supplied state roots."""
    parser = argparse.ArgumentParser(description="Create a pinned FEL META_FOLD attestation sidecar.")
    parser.add_argument("--input", required=True, help="JSONL rows with tick and state_root_sha256")
    parser.add_argument("--output", required=True, help="attestation JSONL destination")
    parser.add_argument("--stream-id", required=True)
    parser.add_argument("--policy-hash", required=True)
    parser.add_argument("--abi-hash", required=True)
    args = parser.parse_args()
    digest_re = re.compile(r"^[0-9a-fA-F]{64}$")
    for name, value in (("policy-hash", args.policy_hash), ("abi-hash", args.abi_hash)):
        if not digest_re.fullmatch(value):
            parser.error(f"--{name} must be a 64-character hexadecimal SHA-256")

    executor = MetaFoldExecutor(args.stream_id, args.policy_hash.lower(), args.abi_hash.lower())
    output_rows: List[Dict[str, Any]] = []
    previous_tick = -1
    with Path(args.input).open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"input line {line_number}: invalid JSON: {exc}") from exc
            if not isinstance(item, dict) or not isinstance(item.get("tick"), int) or item["tick"] < 0:
                raise ValueError(f"input line {line_number}: tick must be an integer >= 0")
            if item["tick"] <= previous_tick:
                raise ValueError(f"input line {line_number}: ticks must be strictly increasing")
            state_root = item.get("state_root_sha256")
            if not isinstance(state_root, str) or not digest_re.fullmatch(state_root):
                raise ValueError(f"input line {line_number}: state_root_sha256 must be a 64-character SHA-256")
            lane_roots = item.get("lane_roots", {})
            extra = item.get("extra", {})
            if not isinstance(lane_roots, dict) or not isinstance(extra, dict):
                raise ValueError(f"input line {line_number}: lane_roots and extra must be JSON objects")
            meta_hash = executor.compute_meta_hash(
                state_root_sha256=state_root.lower(), lane_roots=lane_roots, extra=extra
            )
            record = executor.attest(item["tick"], meta_hash, prev=executor.head)
            output_rows.append({
                "schema": "kuhul.fel.meta-attestation.v1",
                "v": "fel.v1.1", "tick": record.tick, "type": "attest",
                "fold": "⟁META_FOLD⟁", "prev": record.prev,
                "policy_hash": record.policy_hash, "meta_hash": record.meta_hash,
                "abi_hash": record.abi_hash, "att_hash": record.att_hash,
                "canonical": record.canon_bytes.decode("utf-8"),
            })
            previous_tick = item["tick"]

    destination = Path(args.output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    contents = "".join(json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n" for row in output_rows)
    destination.write_text(contents, encoding="utf-8")
    print(f"Wrote {len(output_rows)} META_FOLD attestations to {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
