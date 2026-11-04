import argparse
import hashlib
import json
import struct
import zlib
from collections import OrderedDict

# Expected hashes for the GOLDEN VECTOR (v1)
EXPECTED_REPLAY_0001_SVG_SHA256 = "95aa74cb831b95fda9f1c9bd3c2feaf82a1eb282998ab00ab75ac452e500db11"
EXPECTED_SCX2_BIN_SHA256 = "76dc1d5e04eca1602ae5858a2042bd08c947d6c9ca972e15c9dd55fb96003ed3"

COMPLETE_FOLD_MAP = {
    "⟁DATA_FOLD⟁": "All data structures and values",
    "⟁CODE_FOLD⟁": "All execution logic and functions",
    "⟁STORAGE_FOLD⟁": "All persistence mechanisms",
    "⟁NETWORK_FOLD⟁": "All communication protocols",
    "⟁UI_FOLD⟁": "All user interface elements",
    "⟁AUTH_FOLD⟁": "All security and identity",
    "⟁DB_FOLD⟁": "All data organization",
    "⟁COMPUTE_FOLD⟁": "All processing operations",
    "⟁STATE_FOLD⟁": "All application state",
    "⟁EVENTS_FOLD⟁": "All event handling",
    "⟁TIME_FOLD⟁": "All temporal operations",
    "⟁SPACE_FOLD⟁": "All spatial relationships",
    "⟁META_FOLD⟁": "Fold operations themselves",
    "⟁CONTROL_FOLD⟁": "Execution flow control",
    "⟁PATTERN_FOLD⟁": "Pattern recognition operations",
}

FOLD_TO_LANE = {
    "⟁DATA_FOLD⟁": "DICT",
    "⟁CODE_FOLD⟁": "EDGE",
    "⟁STORAGE_FOLD⟁": "FIELD",
    "⟁NETWORK_FOLD⟁": "EDGE",
    "⟁UI_FOLD⟁": "LANE",
    "⟁AUTH_FOLD⟁": "DICT",
    "⟁DB_FOLD⟁": "FIELD",
    "⟁COMPUTE_FOLD⟁": "BATCH",
    "⟁STATE_FOLD⟁": "FIELD",
    "⟁EVENTS_FOLD⟁": "LANE",
    "⟁TIME_FOLD⟁": "LANE",
    "⟁SPACE_FOLD⟁": "EDGE",
    "⟁META_FOLD⟁": "DICT",
    "⟁CONTROL_FOLD⟁": "EDGE",
    "⟁PATTERN_FOLD⟁": "DICT",
}

CANON_KEY_ORDER = [
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
    "policy_hash",
    "meta_hash",
    "abi_hash",
]


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def die(msg: str):
    raise SystemExit(f"❌ VERIFY FAIL: {msg}")


def sort_nested(obj):
    if isinstance(obj, dict):
        return {k: sort_nested(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [sort_nested(x) for x in obj]
    return obj


def canon_fel_line(event):
    ordered = OrderedDict()
    for key in CANON_KEY_ORDER:
        if key in event:
            ordered[key] = sort_nested(event[key])
    extra = sorted([key for key in event.keys() if key not in ordered])
    for key in extra:
        ordered[key] = sort_nested(event[key])
    return json.dumps(ordered, ensure_ascii=False, separators=(",", ":"))


def read_events_jsonl(path):
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


# -----------------------------
# Legality / verifier rules (FEL v1)
# -----------------------------

def assert_invariants(events):
    # V: required keys + types
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            die(f"event[{i}] is not an object")
        if event.get("v") != "fel.v1":
            die(f"event[{i}] v must be fel.v1")
        if "tick" not in event or not isinstance(event["tick"], int):
            die(f"event[{i}] tick must be int")
        if "type" not in event or not isinstance(event["type"], str):
            die(f"event[{i}] type must be str")
        if "fold" not in event or not isinstance(event["fold"], str):
            die(f"event[{i}] fold must be str")

        fold = event["fold"]
        event_type = event["type"]

        # L1 fold membership
        if fold not in COMPLETE_FOLD_MAP:
            die(f"event[{i}] fold not in COMPLETE_FOLD_MAP: {fold}")

        # L3: no CONTROL fold target (agents never get it)
        if fold == "⟁CONTROL_FOLD⟁":
            die(f"event[{i}] illegally targets ⟁CONTROL_FOLD⟁")

        # L4: UI write forbidden (UI is derived projection)
        if fold == "⟁UI_FOLD⟁":
            die(f"event[{i}] illegally targets ⟁UI_FOLD⟁ (projection must be derived)")

        # L2 type↔fold constraints (v1)
        if event_type == "set" and fold != "⟁STATE_FOLD⟁":
            die(f"event[{i}] set must target ⟁STATE_FOLD⟁")
        if event_type == "seal" and fold != "⟁STORAGE_FOLD⟁":
            die(f"event[{i}] seal must target ⟁STORAGE_FOLD⟁")
        if event_type == "attest" and fold != "⟁META_FOLD⟁":
            die(f"event[{i}] attest must target ⟁META_FOLD⟁")

        # Lane binding must exist
        if fold not in FOLD_TO_LANE:
            die(f"event[{i}] missing fold→lane mapping: {fold}")

    # L5 tick monotone (stream-level)
    ticks = [event["tick"] for event in events]
    if ticks != sorted(ticks):
        die("ticks must be non-decreasing")


# -----------------------------
# Deterministic replay → SVG (frame 0001)
# -----------------------------

def build_snapshots(events):
    ticks = sorted({event["tick"] for event in events})
    tick_to_events = {tick: [] for tick in ticks}
    for event in events:
        tick_to_events[event["tick"]].append(event)

    state = {}
    snaps = []
    for tick in ticks:
        evs = tick_to_events[tick]
        for event in evs:
            if event["type"] == "set":
                state[event["key"]] = event["value"]
        snaps.append((tick, dict(state), evs))
    return snaps


def esc(s: str) -> str:
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def text_block(x, y, lines, line_h=18, color="#e8f5ff", size=14):
    t = [
        f'<text x="{x}" y="{y}" fill="{color}" '
        f'font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" '
        f'font-size="{size}">' 
    ]
    yy = y
    for line in lines:
        t.append(f'<tspan x="{x}" y="{yy}">{esc(line)}</tspan>')
        yy += line_h
    t.append("</text>")
    return "\n".join(t)


def svg_frame(tick, state, evs, width=1200, height=675):
    bg = "#060b14"
    fg = "#e8f5ff"
    accent = "#16f2aa"

    state_lines = []
    for key in sorted(state.keys()):
        state_lines.append(f"{key}: {json.dumps(state[key], ensure_ascii=False, separators=(',',':'))}")

    event_lines = []
    for event in evs[:40]:
        payload = event.get("payload", {})
        event_lines.append(
            f"[{event.get('type', '')}] {event.get('fold', '')} "
            f"{json.dumps(payload, ensure_ascii=False, separators=(',',':'))}"
        )

    meta = [
        f"tick: {tick}",
        "replay: svg.replay.v1",
        "projection: fold→svg (read-only)",
    ]

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
  <rect x="0" y="0" width="{width}" height="{height}" fill="{bg}"/>
  <rect x="24" y="18" width="{width-48}" height="60" rx="14" fill="rgba(22,242,170,0.08)" stroke="rgba(22,242,170,0.25)"/>
  {text_block(44, 44, meta, line_h=18, color=fg, size=14)}
  <rect x="24" y="96" width="{int(width*0.46)}" height="{height-120}" rx="16" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.10)"/>
  <rect x="{int(width*0.50)}" y="96" width="{width-int(width*0.50)-24}" height="{height-120}" rx="16" fill="rgba(255,255,255,0.03)" stroke="rgba(255,255,255,0.10)"/>
  <text x="44" y="128" fill="{accent}" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="16">STATE (⟁STATE_FOLD⟁)</text>
  <text x="{int(width*0.50)+20}" y="128" fill="{accent}" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="16">EVENTS (⟁EVENTS_FOLD⟁)</text>
  {text_block(44, 156, state_lines[:42], line_h=18, color=fg, size=13)}
  {text_block(int(width*0.50)+20, 156, event_lines[:42], line_h=18, color=fg, size=13)}
  <metadata>
    {esc(json.dumps({"tick": tick, "state_keys": sorted(state.keys())}, ensure_ascii=False, separators=(',',':')))}
  </metadata>
</svg>'''


# -----------------------------
# Deterministic FEL → SCX2 (same as felc core)
# -----------------------------

LANE_ID = {"DICT": 1, "FIELD": 2, "LANE": 3, "EDGE": 4, "BATCH": 5}
LANE_BIT = {"DICT": 1, "FIELD": 2, "LANE": 4, "EDGE": 8, "BATCH": 16}


def _u16(n):
    return struct.pack("<H", n)


def _u32(n):
    return struct.pack("<I", n)


def pack_dict(items):
    out = bytearray()
    for key in sorted(items.keys()):
        value = items[key]
        kb = key.encode("utf-8")
        vb = value.encode("utf-8")
        out += _u16(len(kb)) + kb + _u16(len(vb)) + vb
    return bytes(out)


def pack_lane(events_list):
    out = bytearray()
    for tick, kind, blob in events_list:
        out += _u32(tick) + _u16(kind) + _u32(len(blob)) + blob
    return bytes(out)


def scx2_pack(lanes, add_crc=True):
    bitmask = 0
    for name in lanes:
        bitmask |= LANE_BIT[name]
    header = bytearray(b"SCX2" + b"\x01" + bytes([bitmask]) + b"\x00\x00")
    body = bytearray()
    for name in ["DICT", "FIELD", "LANE", "EDGE", "BATCH"]:
        if name not in lanes:
            continue
        count, payload = lanes[name]
        body += struct.pack("<BBII", LANE_ID[name], 0, count, len(payload))
        body += payload
    data = bytes(header + body)
    crc = zlib.crc32(data) & 0xFFFFFFFF
    return data + (_u32(crc) if add_crc else _u32(0))


def compile_scx2(events):
    dict_payload = pack_dict(FOLD_TO_LANE)
    kind_map = {"emit": 100, "set": 101, "delta": 102, "seal": 200, "attest": 250}
    lane_events = []
    for event in events:
        if event.get("fold") == "⟁EVENTS_FOLD⟁":
            blob = canon_fel_line(event).encode("utf-8")
            lane_events.append((int(event["tick"]), kind_map.get(event["type"], 999), blob))
    lane_payload = pack_lane(lane_events)
    return scx2_pack(
        {
            "DICT": (len(FOLD_TO_LANE), dict_payload),
            "LANE": (len(lane_events), lane_payload),
        },
        add_crc=True,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("events_jsonl")
    ap.add_argument("--write-out", action="store_true")
    args = ap.parse_args()

    events = read_events_jsonl(args.events_jsonl)

    # 1) legality rules
    assert_invariants(events)

    # 2) replay_0001.svg hash
    snaps = build_snapshots(events)
    if not snaps:
        die("no snapshots built")
    tick0, state0, events0 = snaps[0]
    svg1 = svg_frame(tick0, state0, events0).encode("utf-8")
    svg_hash = sha256_hex(svg1)
    if svg_hash != EXPECTED_REPLAY_0001_SVG_SHA256:
        die(
            "replay_0001.svg sha256 mismatch\n"
            f"  got: {svg_hash}\n"
            f"  exp: {EXPECTED_REPLAY_0001_SVG_SHA256}"
        )

    # 3) scx2.bin hash
    scx2 = compile_scx2(events)
    scx_hash = sha256_hex(scx2)
    if scx_hash != EXPECTED_SCX2_BIN_SHA256:
        die(
            "scx2.bin sha256 mismatch\n"
            f"  got: {scx_hash}\n"
            f"  exp: {EXPECTED_SCX2_BIN_SHA256}"
        )

    if args.write_out:
        with open("replay_0001.svg", "wb") as f:
            f.write(svg1)
        with open("scx2.bin", "wb") as f:
            f.write(scx2)

    print("FEL PACK VERIFY PASS")
    print("replay_0001.svg sha256:", svg_hash)
    print("scx2.bin        sha256:", scx_hash)


if __name__ == "__main__":
    main()
