# FEL — Fold Event Language v1.1

Canonical ID: asx://language/fel/v1.1
Schema ID: kuhul://schema/fel/v1.1
ABI ID: asx://language/fel/v1.1 (pinned in `fel.abi.json`)
Schema authority: xjson://schema/core/v1 (offline, internal)

FEL v1.1 is a backward-compatible extension of FEL v1:

- canonical serialization (one true byte stream per meaning)
- legality rules (invalid programs rejected)
- deterministic replay (same input → same state)
- delta/patch semantics for state evolution
- storage seals with lane binding
- attestation chains for proof lineage

## Commands

### 1) Verify the full pack (invariants + golden hashes + ABI pin)

```bash
python tools/verify_fel_pack.py vectors/v1.1/events.jsonl --write-out
```

### 2) Regenerate golden hashes after an intentional output change

```bash
python tools/verify_fel_pack.py vectors/v1.1/events.jsonl --emit-golden
```

`--emit-golden` rewrites `vectors/v1.1/expected.json` from the current
canonical outputs and records the computed `fel.abi.json` pin. It does not
update `fel.abi.json` itself — run the plain verify command afterwards to
confirm the pin matches.

### 3) Compile FEL → SCX2 binary container

```bash
python tools/felc.py vectors/v1.1/events.jsonl --out scx2.bin
```

### 4) Project FEL → SVG replay frames

```bash
python tools/felp.py vectors/v1.1/events.jsonl --out replay_out
```

## Golden vector expectations (SHA-256)

See `vectors/v1.1/expected.json`.

- `replay_0001.svg`:
  `e8edaf215e90f554d0207f2228abf2afab3c96b002c76a8202cbcb5667ad3dff`
- `scx2.bin`:
  `2abe3abed92521b0404761638dc102dd151ef0dc85d5bd8938f6adbb3271b4bc`
- `fel.abi.json` pin:
  `sha256:973423e1784b17088e2d4a99eb9c42e526992ac6a96f3c6ec4c74cc81c65a7d2`

The ABI pin is SHA-256 over the canonical ABI document with the
`abi_hash_sha256` field removed. Any edit to `fel.abi.json` therefore requires
re-pinning; verification fails until the pin is updated.
