# fel_svg_replay.py
"""
FEL -> SVG Replay Generator (EVENTS + STATE)
- Deterministically applies set/delta into a canonical state
- Writes replay_0001.svg ... replay_N.svg
- Emits replay_manifest.json with state_root_sha256 + svg_sha256

Supported FEL types:
- emit (logged)
- set (STATE)
- delta (STATE) with patch{op,path,value?}

Notes:
- timestamps are ignored for hashing
- tick must be non-decreasing
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Tuple

try:
    from .fel_meta_fold import canon_json, sha256_hex
except ImportError:
    from fel_meta_fold import canon_json, sha256_hex


def apply_set(state: Dict[str, Any], key: str, value: Any) -> None:
    state[key] = value


def apply_delta(state: Dict[str, Any], patch: Dict[str, Any]) -> None:
    op = patch["op"]
    path = patch["path"]
    if not isinstance(path, str) or not path.startswith("/"):
        raise ValueError("patch.path must start with '/'")
    parts = [p for p in path.split("/") if p][:]
    if not parts:
        raise ValueError("patch.path must not be empty")

    def get_parent(root: Dict[str, Any], keys: List[str]) -> Tuple[Dict[str, Any], str]:
        cur = root
        for k in keys[:-1]:
            nxt = cur.get(k)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[k] = nxt
            cur = nxt
        return cur, keys[-1]

    parent, leaf = get_parent(state, parts)

    if op in ("add", "replace"):
        if "value" not in patch:
            raise ValueError("add/replace requires value")
        parent[leaf] = patch["value"]
    elif op == "remove":
        if "value" in patch:
            raise ValueError("remove must not include value")
        parent.pop(leaf, None)
    else:
        raise ValueError("patch.op must be add|replace|remove")


def state_root_sha256(state: Dict[str, Any]) -> str:
    return sha256_hex(canon_json(state))


def svg_hash_sha256(svg_text: str) -> str:
    return sha256_hex(svg_text.encode("utf-8"))


def render_svg(tick: int, events: List[Dict[str, Any]], state: Dict[str, Any]) -> str:
    """
    Deterministic SVG:
    - fixed layout
    - embeds tick, state_root, and compact event log
    """
    sroot = state_root_sha256(state)

    # Compact log lines (deterministic ordering = input order)
    log_lines: List[str] = []
    for e in events:
        typ = e.get("type", "unknown")
        fold = e.get("fold", "unknown")
        if typ == "set":
            log_lines.append(
                f"set {e.get('key')}={json.dumps(e.get('value'), separators=(',',':'))}"
            )
        elif typ == "delta":
            p = e.get("patch", {})
            log_lines.append(
                "delta "
                f"{p.get('op')} "
                f"{p.get('path')} "
                f"{json.dumps(p.get('value'), separators=(',',':')) if 'value' in p else ''}"
            )
        else:
            # emit or other
            payload = e.get("payload")
            if payload is not None:
                log_lines.append(f"{typ} {fold} {json.dumps(payload, separators=(',',':'))[:120]}")
            else:
                log_lines.append(f"{typ} {fold}")

    # State preview (bounded)
    state_preview = json.dumps(state, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    if len(state_preview) > 600:
        state_preview = state_preview[:600] + "…"

    # Render
    x0, y0 = 24, 32
    lh = 16

    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    lines_svg = ""
    for i, line in enumerate(log_lines[:32]):  # cap for readability
        lines_svg += (
            f'<text x="{x0}" y="{y0 + 80 + i*lh}" '
            f'font-family="monospace" font-size="12" fill="#c9f">{esc(line)}</text>\n'
        )

    svg = f"""<svg width="1200" height="800" xmlns="http://www.w3.org/2000/svg">
  <rect width="100%" height="100%" fill="#05060b"/>
  <text x="{x0}" y="{y0}" font-family="monospace" font-size="22" fill="#9ff">⟁ FEL REPLAY ⟁</text>

  <text x="{x0}" y="{y0+30}" font-family="monospace" font-size="14" fill="#7df">tick: {tick}</text>
  <text x="{x0}" y="{y0+50}" font-family="monospace" font-size="14" fill="#7df">state_root_sha256: {sroot}</text>

  <rect x="{x0-10}" y="{y0+66}" width="1150" height="280" fill="#0b1020" opacity="0.75" rx="10"/>
  <text x="{x0}" y="{y0+92}" font-family="monospace" font-size="14" fill="#fff">EVENTS (first 32):</text>
  {lines_svg}

  <rect x="{x0-10}" y="{y0+370}" width="1150" height="360" fill="#0b1020" opacity="0.75" rx="10"/>
  <text x="{x0}" y="{y0+396}" font-family="monospace" font-size="14" fill="#fff">STATE (preview):</text>
  <text x="{x0}" y="{y0+420}" font-family="monospace" font-size="12" fill="#bfb">{esc(state_preview)}</text>

  <text x="1180" y="780" text-anchor="end" font-family="monospace" font-size="10" fill="#666">
    projection-only · deterministic · no-exec
  </text>
</svg>"""
    return svg


def replay_fel_jsonl(
    fel_jsonl_path: str,
    out_dir: str = "replay_out",
) -> Dict[str, Any]:
    os.makedirs(out_dir, exist_ok=True)

    # tick -> list of FEL lines
    by_tick: Dict[int, List[Dict[str, Any]]] = {}
    last_tick = 0

    with open(fel_jsonl_path, "r", encoding="utf-8") as f:
        for ln, raw in enumerate(f, start=1):
            raw = raw.strip()
            if not raw:
                continue
            e = json.loads(raw)

            if e.get("v") not in ("fel.v1", "fel.v1.1"):
                raise ValueError(f"line {ln}: bad v")
            tick = e.get("tick")
            if not isinstance(tick, int) or tick < 0:
                raise ValueError(f"line {ln}: bad tick")
            if tick < last_tick:
                raise ValueError(f"line {ln}: tick not monotonic")
            last_tick = tick

            by_tick.setdefault(tick, []).append(e)

    state: Dict[str, Any] = {}
    manifest: Dict[str, Any] = {
        "v": "fel.replay.v1.1",
        "source": fel_jsonl_path,
        "ticks": [],
    }

    ticks_sorted = sorted(by_tick.keys())
    for idx, tick in enumerate(ticks_sorted, start=1):
        events = by_tick[tick]

        # Apply state transitions for this tick
        for e in events:
            typ = e.get("type")
            fold = e.get("fold")

            # Only STATE fold mutates state in replay
            if typ == "set":
                if fold != "⟁STATE_FOLD⟁":
                    raise ValueError("set must target STATE")
                apply_set(state, e["key"], e["value"])

            elif typ == "delta":
                if fold != "⟁STATE_FOLD⟁":
                    raise ValueError("delta must target STATE")
                apply_delta(state, e["patch"])

            else:
                # emit/seal/attest don't mutate STATE in renderer
                pass

        svg = render_svg(tick, events, state)
        svg_name = f"replay_{idx:04d}.svg"
        svg_path = os.path.join(out_dir, svg_name)

        with open(svg_path, "w", encoding="utf-8") as out:
            out.write(svg)

        tick_state_root = state_root_sha256(state)
        tick_svg_hash = svg_hash_sha256(svg)

        manifest["ticks"].append(
            {
                "tick": tick,
                "file": svg_name,
                "state_root_sha256": tick_state_root,
                "svg_sha256": tick_svg_hash,
                "event_count": len(events),
            }
        )

    manifest_path = os.path.join(out_dir, "replay_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as out:
        out.write(json.dumps(manifest, indent=2, ensure_ascii=False))

    return manifest


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("usage: python fel_svg_replay.py path/to/events.fel.jsonl [out_dir]")
        raise SystemExit(1)

    src = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else "replay_out"
    mf = replay_fel_jsonl(src, out_dir=out)
    print(f"wrote {len(mf['ticks'])} SVG frames to {out}/")
    print(f"manifest: {out}/replay_manifest.json")
