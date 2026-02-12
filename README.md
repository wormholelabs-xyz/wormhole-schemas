# wormhole-schemas

A CLI tool and Rust library for parsing and building binary Wormhole payloads using composable JSON schema definitions.

## Install

```sh
cargo install --git https://github.com/wormholelabs-xyz/wormhole-schemas.git

# With remote schema fetching enabled
cargo install --git https://github.com/wormholelabs-xyz/wormhole-schemas.git --features fetch

# From a local clone
cargo install --path .
```

## Quick start

Build a VAA containing a Token Bridge transfer:

```
$ wsch build -s 'vaa<transfer>' \
    guardian-set-index=4 signature-count=0 \
    timestamp=1700000000 nonce=0 emitter-chain=2 \
    emitter-address=0000000000000000000000000000000000000000000000000000000000000001 \
    sequence=1 consistency-level=32 \
    payload.amount=100000000 \
    payload.token-address=000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7 \
    payload.token-chain=2 \
    payload.to=0000000000000000000000009876543210abcdef9876543210abcdef98765432 \
    payload.to-chain=1 \
    payload.fee=0
0100000004006553f1000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000120010000000000000000000000000000000000000000000000000000000005f5e100000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700020000000000000000000000009876543210abcdef9876543210abcdef9876543200010000000000000000000000000000000000000000000000000000000000000000
```

Parse it back:

```
$ wsch parse 0100000004006553f1000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000120010000000000000000000000000000000000000000000000000000000005f5e100000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700020000000000000000000000009876543210abcdef9876543210abcdef9876543200010000000000000000000000000000000000000000000000000000000000000000

{
  "$schema": "vaa<transfer>",
  "guardian-set-index": "4",
  "signature-count": "0",
  "signatures": [],
  "timestamp": "1700000000",
  "nonce": "0",
  "emitter-chain": "2",
  "emitter-address": "0000000000000000000000000000000000000000000000000000000000000001",
  "sequence": "1",
  "consistency-level": "32",
  "payload": {
    "amount": "100000000",
    "token-address": "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7",
    "token-chain": "2",
    "to": "0000000000000000000000009876543210abcdef9876543210abcdef98765432",
    "to-chain": "1",
    "fee": "0"
  }
}
```

Sign it with a guardian key:

```
$ wsch sign --guardian-key cfb12303a19cde580bb4dd771639b0d26bc68353645571a8cff516ab2ee113a0 \
    --guardian-index 0 \
    0100000004006553f1000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000120010000000000000000000000000000000000000000000000000000000005f5e100000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700020000000000000000000000009876543210abcdef9876543210abcdef9876543200010000000000000000000000000000000000000000000000000000000000000000
010000000401003dfa507aa7e08271326835e0f644affb24a520d3ffe6ea72d0e910bd94facbe66b0b0357e6e484b0c3d50816325704201f56eb696a4bc6a493889368b760708d016553f1000000000000020000000000000000000000000000000000000000000000000000000000000001000000000000000120010000000000000000000000000000000000000000000000000000000005f5e100000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec700020000000000000000000000009876543210abcdef9876543210abcdef9876543200010000000000000000000000000000000000000000000000000000000000000000
```

List available schemas:

```
$ wsch schemas
@wormhole-foundation/native-token-transfers/ntt                NTT transceiver message wrapping a manager message with native token transfer
@wormhole-foundation/token-bridge/attest-meta                  Token Bridge asset metadata attestation (payload ID 2)
@wormhole-foundation/token-bridge/transfer                     Token Bridge transfer (payload ID 1)
@wormhole-foundation/token-bridge/transfer-with-payload        Token Bridge transfer with arbitrary payload (payload ID 3)
@wormhole-foundation/wormhole/vaa<A>                           Complete Wormhole VAA (header + body)
...
```

## Commands

| Command | Description |
|---------|-------------|
| `wsch parse [payload]` | Decode binary to JSON. Schema auto-detected or via `-s`. Reads hex arg, `@file`, or stdin. |
| `wsch build -s <schema> [overrides...]` | Encode JSON to binary. Values from `--json`, stdin, or `key=value` args. Dot notation for nesting. |
| `wsch schemas` | List all loaded schemas. |
| `wsch sign [vaa]` | Sign a VAA with `--guardian-key` (or `GUARDIAN_KEY` env). `--format base64` for base64 output. Additive: preserves existing signatures. |

## Schema references

Schemas are namespaced as `@org/repo/name` and can be composed with type parameters:

```
transfer                                          # short name (unique match required)
@wormhole-foundation/token-bridge/transfer        # fully qualified
vaa<transfer>                                     # parameterized (VAA wrapping transfer)
vaa<@wormhole-foundation/token-bridge/transfer>   # mixed short + qualified
```

## Custom schemas

Load additional schemas from a directory:

```sh
wsch --schemas ./my-schemas parse <hex>
```

Schemas are JSON files. The directory structure determines the scope: `schemas/@org/repo/name.json` registers as `@org/repo/name`.

A schema defines an ordered list of binary fields:

```json
{
  "about": "Token Bridge asset metadata attestation (payload ID 2)",
  "fields": [
    {"name": "payload-id",    "const": "02"},
    {"name": "token-address", "type": "address"},
    {"name": "token-chain",   "type": "u16"},
    {"name": "decimals",      "type": "u8"},
    {"name": "symbol",        "type": "string32"},
    {"name": "name",          "type": "string32"}
  ]
}
```

### Field types

| Type | Encoding |
|------|----------|
| `u8`, `u16`, `u32`, `u64` | Big-endian unsigned integer |
| `u256` | 32-byte big-endian unsigned integer (decimal string) |
| `address` | 32-byte Wormhole address (hex or base58 input) |
| `bytesN` | Fixed N-byte field |
| `string32` | UTF-8 string left-padded with zeros to 32 bytes |
| `hex` | Variable-length raw bytes (consumes remaining input) |

### Field variants

- **`{"name": "x", "type": "u32"}`** -- named typed field
- **`{"name": "x", "const": "DEADBEEF"}`** -- constant (verified on parse, auto-filled on build)
- **`{"ref": "@org/repo/schema"}`** -- inline another schema's fields
- **`{"name": "x", "ref": "@org/repo/schema"}`** -- nested schema under a named JSON key

### Parameterized schemas

Schemas can accept type parameters for composition:

```json
{
  "params": ["A"],
  "fields": [
    {"ref": "@this/header"},
    {"name": "payload", "ref": "A"}
  ]
}
```

`@this/` references resolve relative to the schema's own scope.

## Library usage

```rust
use wormhole_schemas::Registry;

let reg = Registry::builtin()?;

// Parse binary to JSON
let (schema, json) = reg.infer(&bytes)?;

// Or with a specific schema
let json = reg.parse("vaa<transfer>", &bytes)?;

// Build JSON to binary
let bytes = reg.serialize("transfer", &json_value)?;
```

## Features

| Feature | Default | Description |
|---------|---------|-------------|
| `sign` | yes | Guardian VAA signing (`wsch sign`) |
| `fetch` | no | Fetch remote schemas from GitHub at runtime |

### Remote schema fetching

With `--features fetch`, schemas that aren't bundled locally are fetched from GitHub on demand. Resolution order:

1. The source repo: `github.com/{org}/{repo}/main/schemas/{name}.json`
2. The central registry: `github.com/wormholelabs-xyz/wormhole-schemas/main/schemas/@{org}/{repo}/{name}.json`

Fetched schemas are cached in memory for the duration of the command.
