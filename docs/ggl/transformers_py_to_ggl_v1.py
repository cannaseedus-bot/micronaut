# transformers.py → GGL adapter (terminal-safe, easily fixable)
# FILE: transformers_py_to_ggl_v1.py
# Purpose:
# - Provide a sealed Plane-2 executor interface: pure JSON in/out
# - No shell, no filesystem writes by default, no network by default
# - Makes "GGL inference" callable from your sw.js / local REST bridge
#
# Design:
# - stdin: JSON request (matches xjson://contract/ggl.infer/v1 + pack refs)
# - stdout: JSON response with output + SCXQ2 frame stubs (start/end/pack/seed)
# - errors: stdout JSON with ok:false + fault
#
# Notes:
# - This file is intentionally "easy to fix": the only model-specific work
#   is inside `run_transformer_blackbox()`. Everything else is contract+proof.
#
# Constraints:
# - No async required. Deterministic ordering.
# - If randomness is used, it MUST be seeded and emitted in infer.seed frame.

import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

# Reference attention engine (pure Python, deterministic). Optional import keeps
# the adapter usable as a contract-only stub if the module is absent.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from ggl_attention_v1 import TinyTransformer
except Exception:  # pragma: no cover - fallback is intentional
    TinyTransformer = None

# ----------------------------
# FNV-1a 32-bit (matches ABR style)
# ----------------------------

def fnv1a32(data: bytes) -> int:
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) & 0xFFFFFFFF
    return h


def h32_hex(payload: str) -> str:
    return "h:" + format(fnv1a32(payload.encode("utf-8")), "08x")


def stable_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

# ----------------------------
# Frame helpers (JSON frames; binary is SW-side)
# ----------------------------

def frame(kind: str, payload: Dict[str, Any], tick: int = 0) -> Dict[str, Any]:
    """Build a deterministic GGL frame.

    ``tick`` is a logical sequence number, not wall-clock time. Sealed compute
    must replay identically, so this function never reads a clock.
    """
    return {
        "@type": "ggl.frame",
        "kind": kind,
        "t_ms": int(tick) & 0xFFFFFFFF,
        "payload": payload,
    }

# ----------------------------
# Contracts (minimal enforcement)
# ----------------------------

@dataclass(frozen=True)
class PackProofPayload:
    model_id: str
    weights_hash: str
    tensor_hash: str
    glyph_hash: str
    abi_id: str
    abi_hash: str
    runtime_device: str
    runtime_precision: str
    seed: Optional[int]
    policy_sealed: bool
    policy_no_network: bool
    policy_no_fs: bool
    policy_no_eval: bool


def pack_proof_hash(p: PackProofPayload) -> str:
    payload = {
        "@type": "ggltensors.pack.proof.payload",
        "@v": "1.0.0",
        "model_id": p.model_id,
        "weights_hash": p.weights_hash,
        "tensor_hash": p.tensor_hash,
        "glyph_hash": p.glyph_hash,
        "abi_id": p.abi_id,
        "abi_hash": p.abi_hash,
        "runtime_device": p.runtime_device,
        "runtime_precision": p.runtime_precision,
        "seed": p.seed,
        "policy_sealed": p.policy_sealed,
        "policy_no_network": p.policy_no_network,
        "policy_no_fs": p.policy_no_fs,
        "policy_no_eval": p.policy_no_eval,
    }
    return h32_hex(stable_json(payload))

# ----------------------------
# Black-box executor (replace this)
# ----------------------------

_MODEL_CACHE: Dict[int, Any] = {}


def _model_for(seed: Optional[int]) -> Any:
    key = 0 if seed is None else int(seed)
    if key not in _MODEL_CACHE:
        _MODEL_CACHE[key] = TinyTransformer(seed=key)
    return _MODEL_CACHE[key]


def run_transformer_blackbox(
    prompt: str,
    mode: str,
    max_tokens: int,
    seed: Optional[int],
) -> Tuple[str, int, Dict[str, Any]]:
    """
    Deterministic reference transformer (byte embedding + multi-head causal
    self-attention + feed-forward). Returns (text, tokens_used, trace).

    The trace carries per-layer activation hashes so the caller can emit them
    as replay evidence without changing the frame contract.
    """
    if TinyTransformer is None:
        text = f"[GGL_OUTPUT mode={mode} tokens={max_tokens}] " + prompt
        tokens_used = min(max_tokens, max(1, len(prompt) // 4))
        return text, tokens_used, {"engine": "placeholder"}

    result = _model_for(seed).generate(prompt, max_new_tokens=max_tokens, mode=mode)
    return result["text"], result["tokens_used"], result["trace"]

# ----------------------------
# Main request handler
# ----------------------------

def handle(req: Dict[str, Any]) -> Dict[str, Any]:
    # Basic shape
    if not isinstance(req, dict):
        return {"ok": False, "fault": "E_CONTRACT", "message": "request must be JSON object"}

    # Expect pack + infer
    pack = req.get("pack")
    infer = req.get("infer")
    if not isinstance(pack, dict) or not isinstance(infer, dict):
        return {"ok": False, "fault": "E_CONTRACT", "message": "missing pack/infer objects"}

    # Read pack fields
    model_id = str(pack.get("model_id", ""))
    weights_hash = str(pack.get("weights_hash", ""))
    tensor_hash = str(pack.get("tensor_hash", ""))
    glyph_hash = str(pack.get("glyph_hash", ""))
    abi_id = str(pack.get("abi_id", "transformers.py:v1"))
    abi_hash = str(pack.get("abi_hash", "h:00000000"))

    runtime_device = str(pack.get("runtime_device", "cpu"))
    runtime_precision = str(pack.get("runtime_precision", "fp32"))
    seed = pack.get("seed", None)
    seed_i = int(seed) if seed is not None else None

    # Policy (sealed by default)
    policy = pack.get("policy") or {}
    policy_sealed = bool(policy.get("sealed", True))
    policy_no_network = bool(policy.get("no_network", True))
    policy_no_fs = bool(policy.get("no_fs", True))
    policy_no_eval = bool(policy.get("no_eval", True))

    # Minimal required
    if not model_id or not weights_hash or not tensor_hash or not glyph_hash:
        return {
            "ok": False,
            "fault": "E_CONTRACT",
            "message": "pack requires model_id, weights_hash, tensor_hash, glyph_hash",
        }

    # Compute pack proof hash (locked contract)
    pp = PackProofPayload(
        model_id=model_id,
        weights_hash=weights_hash,
        tensor_hash=tensor_hash,
        glyph_hash=glyph_hash,
        abi_id=abi_id,
        abi_hash=abi_hash,
        runtime_device=runtime_device,
        runtime_precision=runtime_precision,
        seed=seed_i,
        policy_sealed=policy_sealed,
        policy_no_network=policy_no_network,
        policy_no_fs=policy_no_fs,
        policy_no_eval=policy_no_eval,
    )
    pack_hash = pack_proof_hash(pp)

    # Infer input
    prompt = str(infer.get("prompt", ""))
    mode = str(infer.get("mode", "chat"))
    max_tokens = infer.get("max_tokens", 1024)
    try:
        max_tokens_i = int(max_tokens)
    except Exception:
        max_tokens_i = 1024

    # Build SCXQ2 evidence frames (JSON form; SW packs to binary)
    frames = []
    tick = [0]

    def emit_frame(kind: str, payload: Dict[str, Any]) -> None:
        tick[0] += 1
        frames.append(frame(kind, payload, tick[0]))

    emit_frame(
        "infer.pack",
        {
            "pack_hash": pack_hash,
            "model_id": model_id,
            "tensor_hash": tensor_hash,
            "glyph_hash": glyph_hash,
            "abi_hash": abi_hash,
        },
    )

    if seed_i is not None:
        emit_frame("infer.seed", {"pack_hash": pack_hash, "seed": seed_i})

    input_payload = {"prompt": prompt, "mode": mode, "max_tokens": max_tokens_i}
    input_hash = h32_hex(stable_json(input_payload))
    emit_frame("infer.start", {"pack_hash": pack_hash, "input_hash": input_hash})

    # Execute sealed compute
    out_text, tokens_used, trace = run_transformer_blackbox(prompt, mode, max_tokens_i, seed_i)

    output_payload = {"text": out_text, "tokens_used": int(tokens_used)}
    output_hash = h32_hex(stable_json(output_payload))
    emit_frame(
        "infer.end",
        {
            "pack_hash": pack_hash,
            "output_hash": output_hash,
            "model_trace": trace,
        },
    )

    # Response (pure data)
    return {
        "ok": True,
        "pack": {
            "model_id": model_id,
            "pack_hash": pack_hash,
            "tensor_hash": tensor_hash,
            "glyph_hash": glyph_hash,
            "abi_id": abi_id,
            "abi_hash": abi_hash,
            "runtime_device": runtime_device,
            "runtime_precision": runtime_precision,
            "seed": seed_i,
        },
        "infer": {
            "input_hash": input_hash,
            "output_hash": output_hash,
            "output": output_payload,
            "model_trace": trace,
        },
        "frames": frames,
    }


def main() -> int:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.stdout.write(
                stable_json({"ok": False, "fault": "E_CONTRACT", "message": "empty stdin"})
            )
            return 2
        req = json.loads(raw)
        res = handle(req)
        sys.stdout.write(stable_json(res))
        return 0 if res.get("ok") else 1
    except json.JSONDecodeError as e:
        sys.stdout.write(stable_json({"ok": False, "fault": "E_JSON", "message": str(e)}))
        return 2
    except Exception as e:
        sys.stdout.write(stable_json({"ok": False, "fault": "E_RUNTIME", "message": str(e)}))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
