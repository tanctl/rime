# RIME – Privacy-Hardened Zcash Light Client

## Overview
RIME is a privacy-hardened Zcash Unified Address light client with configurable metadata resistance. It provides full-memo download (hide transaction interest), PIR with dummy cadence (oblivious retrieval), Tor circuit isolation (prevent session linking), constant-cost scanning (eliminate timing leaks), bucketing (obscure sync patterns), and ephemeral/stateless modes (prevents forensic analysis of persistent state). All defenses operate client-side on current lightwalletd infrastructure.

## Background: The Metadata Leaks in Current Zcash Light Clients
Current Zcash light clients leak metadata through multiple vectors:
- **Block range queries** reveal wallet age, sync frequency, and transaction density to lightwalletd.
- **Selective memo fetching** exposes exactly which transactions a wallet received.
- **Transaction broadcasting** reveals which transactions were sent with linkable timing.
- **Connection metadata** (IP addresses, timing patterns) enables correlation attacks by both compromised servers and passive network observers.

These metadata leaks allow transaction graph reconstruction and timing correlation attacks, revealing exactly what shielded transactions are designed to hide.

ZIP-314 (reserved) identified these issues, and community discussions around it proposed solutions. RIME implements the client-side subset: full memo download, PIR with dummy queries, and Tor integration, plus additional privacy defenses: circuit isolation, bucketing, note density smoothing, and ephemeral/stateless modes.

*Reference: [ZIP-314 Discussion](https://forum.zcashcommunity.com/t/zip-314-privacy-upgrades-to-the-zcash-light-client-protocol/38868)*

## Design Philosophy
RIME adopts a minimal, client-only approach: implement the privacy properties achievable today without protocol or lightwalletd changes.

### Core Principles
- **Shielded-only operation:** Restrict to Sapling and Orchard receivers to avoid transparent identifiers and reduce fingerprintable boundaries.
- **Receive-only, UFVK-based model:** Derive viewing keys for note detection only, spending and outbound flows are intentionally out of scope.
- **Client-side privacy hardening:** Apply PIR, dummy activity, smoothing, bucketing, and Tor isolation, ephemeral/stateless modes entirely in the client for deployability on current infrastructure.
- **Deterministic behaviour:** Aim for uniform observable network and trial-decryption activity across syncs, independent of wallet state.
- **Encrypted local state:** Persist metadata encrypted at rest, keep decrypted material in process memory only.
- **Explicit tradeoffs:** Accept added bandwidth, latency, and redundant computation to resist access-pattern, timing, and linkability attacks.

## Architecture

### Components
**Core library (`rime-core`)**
- Key derivation and unified viewing keys.
- Seed encryption (Argon2id + AES-256-GCM).
- Note models and commitment trees.
- SQLite storage with checkpoints and reorg detection.

**Light client engine (`rime-lightclient`)**
- gRPC layer and note sources (direct + PIR-backed).
- Sync engine with trial decryption.
- Memo hydration/cache and smoothing.
- Treestate validation and Tor manager.

**CLI (`rime-cli`)**
- Sync orchestration and privacy configuration.
- Key import/export and wallet interactions.

**PIR tooling (`rime-pir`, `rime-pir-server`)**
- XOR-PIR client/scheduler.
- HTTP server for bucketized compact outputs.

**State storage**
- Encrypted wallet metadata.
- SQLite for notes/witnesses/block hashes/checkpoints, full-memo cache is in-memory only.
- In-memory and stateless options.

### Data Flow
- **Block acquisition:** Compact blocks via gRPC. PIR mode reconstructs from bucket responses with bucket-aligned ranges.
- **Trial decryption:** UFVK-derived keys trial-decrypt Sapling/Orchard outputs. Full-memo hydrates all ciphertexts first to prevent selective fetch leakage.
- **Note acceptance:** Decrypted items become notes with witnesses/positions, nullifiers tracked to mark spends.
- **Checkpointing and reorg handling:** Merkle trees checkpointed periodically, stored block hashes detect divergence and trigger reset-to-birthday recovery.

### State Handling
- Seeds protected with Argon2id-derived keys and AES-256-GCM, salts and ciphertext stored alongside wallet metadata.
- Metadata persisted: network, birthday, last-synced height, UFVK, encrypted seed; last-synced corrected to birthday-1 on load when needed.
- In-memory operation: ephemeral/stateless modes keep decrypted material in process memory only, no plaintext seeds or notes are written to disk.

## Privacy Defenses Implemented
1. **Private Information Retrieval (PIR)**  
   XOR-PIR with two non-colluding servers over 256-byte records (Sapling/Orchard outputs). Random-share queries; bucket DBs built via `rime-pir-server`.  
   Defends against: Compromised server learning which transactions you received.

2. **Dummy Traffic**  
   Constant-rate PIR scheduler mixes real/dummy queries at `--pir-dummy-interval`; reports real/dummy ratios and MB/hour.  
   Defends against: Timing correlation attacks by observers.

3. **Full Memo Download**  
   `--sync-mode full-memo` fetches all memo ciphertexts in-range to avoid selective memo leaks; prints estimated bandwidth and memo stats.  
   Defends against: Selective memo fetch revealing which transactions matter to you.

4. **Note Density Smoothing (Constant-Cost)**  
   Optional dummy decryptions and minimum per-block processing time to reduce timing leakage during trial decryption.  
   Defends against: Trial-decryption timing revealing how many transactions you received.

5. **Bucketing**  
   Outputs indexed into fixed-size buckets; scan ranges rounded to bucket boundaries. Bucket size configurable (`--bucket-size` / `--pir-bucket-size`).  
   Defends against: Exact sync range revealing wallet birthday and activity patterns.

6. **Tor Integration**  
   Tor-only routing for RPC (and PIR when configured); rejects local endpoints under Tor requirements.  
   Defends against: IP address disclosure to lightwalletd/PIR servers.

7. **Tor Isolation (Hardened Mode)**  
   Separate isolation groups for RPC vs PIR, optional fresh Tor state/cache, jittered connect timing.  
   Defends against: Session correlation across queries.

8. **Ephemeral & Stateless Operation**  
   Ephemeral sync with UFVK and in-memory DB, stateless scan streams notes without persisting state or checkpoints.  
   Defends against: Forensic analysis of persisted wallet state.

## Technical Deep Dive
- `rime-core`: BIP-39 -> Sapling/Orchard UFVK, UA helpers, Merkle trees, SQLite wallet store, Argon2id + AES-256-GCM seed encryption, hardened derivation.
- `rime-lightclient`: gRPC RPC client, NoteSource abstraction, PIR reconstruction, sync engine (trial decryption, witnesses, reorg handling, smoothing), full-memo cache, stateless scan, Tor manager.
- `rime-pir`: XOR-PIR database/client/scheduler; `rime-pir-server`: axum builder/server for PIR DBs.
- `rime-cli`: init/import UFVK, sync modes, Tor controls, balance/history, key export, Orchard migration, seed export, stateless/ephemeral modes.

## Installation
```bash
cargo build
# optional PIR server tooling
cargo build -p rime-pir-server
```

## Build and Test
```bash
cargo test --workspace
# optional live RPC tests (require network)
LIGHTWALLETD_RPC_TESTS=1 cargo test -p rime-lightclient --test rpc_live
```

## Usage

### Getting Started
- Init new wallet:  
  `cargo run -p rime-cli -- init --network testnet --birthday-height 0`
- Import UFVK (receive-only):  
  `cargo run -p rime-cli -- import-ufvk --ufvk <uview> --birthday-height <h>`

### Sync Modes
- Default:  
  `cargo run -p rime-cli -- sync --endpoint https://testnet.zec.rocks:443 --batch 100`
- Full-memo (download all memos):  
  `cargo run -p rime-cli -- sync --sync-mode full-memo --endpoint https://testnet.zec.rocks:443`
- PIR (private retrieval with dummy queries):  
  `cargo run -p rime-cli -- sync --sync-mode pir --pir-server http://64.227.88.118:8080 --pir-server http://64.227.88.118:8081 --pir-bucket-size 1000 --pir-dummy-interval 60s --endpoint https://testnet.zec.rocks:443`

### Privacy Add-ons (Combinable)

These flags can be combined with any sync mode for layered defense:
- Tor routing: `--tor-only`
- Tor with isolation: `--tor-only --tor-isolate [--tor-state-dir <path> --tor-cache-dir <path>]`
- Constant-cost smoothing: `--const-cost --min-block-delay 50ms --dummy-decryptions 64`
- Bucket rounding: `--bucket-size 1000`
- RPC tuning: `--rpc-timeout 20s --rpc-retries 6`

Example (stacked privacy):
```bash
cargo run -p rime-cli -- sync --sync-mode full-memo \
  --tor-only --tor-isolate \
  --const-cost --min-block-delay 50ms --dummy-decryptions 64 \
  --bucket-size 1000 \
  --endpoint https://testnet.zec.rocks:443
```

### Special Modes
- Ephemeral (in-memory DB):  
  `cargo run -p rime-cli -- sync --ephemeral --ufvk <uview> --birthday-height <h> --endpoint https://testnet.zec.rocks:443`
- Stateless (stream-only, no DB):  
  `cargo run -p rime-cli -- sync --stateless --ufvk <uview> --birthday-height <h> --endpoint https://testnet.zec.rocks:443`

### Wallet Operations
- Balance: `cargo run -p rime-cli -- balance [--pool sapling|orchard] [--json]`
- History: `cargo run -p rime-cli -- history --limit 20 [--json]`
- Keys: `cargo run -p rime-cli -- keys [address|fvk|sapling|migrate-orchard]`
- Seed export (mnemonic-backed wallets): `cargo run -p rime-cli -- seed`

### PIR Server (Advanced)
- Build PIR DB:  
  `cargo run -p rime-pir-server -- --database deploy/pir-server/data1/pir.db build --lightwalletd https://testnet.zec.rocks:443 --start <h0> --end <h1> --bucket-size 1000 --network testnet`
- Serve PIR DB:  
  `cargo run -p rime-pir-server -- --database deploy/pir-server/data1/pir.db --listen 127.0.0.1:8080 serve`

## Threat Model

### Defenses Provided
- Passive observers cannot correlate block/memo/tx timing patterns (smoothing, dummy PIR cadence).
- Compromised lightwalletd cannot pinpoint which transactions belong to you (full-memo/PIR modes).
- IP address disclosure is prevented via Tor integration and isolation.
- Single PIR server compromise requires collusion between both servers.
- Session linkability reduced via Tor circuit isolation.

### Known Limitations
- Active network attackers can still attempt Tor Sybil/traffic correlation, global adversaries may correlate Tor entry/exit timing.
- PIR is trust-split: Colluding PIR servers can learn queries.
- Sender privacy and spending metadata are out of scope (receive-only).
- Orchard roots are trusted via lightwalletd treestate (TOFU) when headers are absent, header/PoW/Sapling-root checks are skipped when compact headers are missing.
- Constant-bandwidth containers or server-side padding require lightwalletd/protocol changes (not implementable client-side).
- Private transaction broadcast/mempool privacy (eg mixnets/Dandelion++) needs network-layer support beyond the client.
- Full-memo and PIR increase bandwidth/latency (full-memo ≈600 bytes per shielded output).
- Non-standard Sapling derivation (not ZIP-32 compatible).

## References
- ZIP-314: https://zips.z.cash/zip-0314
- ZIP-314 discussion: https://forum.zcashcommunity.com/t/zip-314-privacy-upgrades-to-the-zcash-light-client-protocol/38911
- ZIP-316 (Unified Addresses), ZIP-32 (derivation), ZIP-307 (compact blocks)

## License
GPLv3

## Acknowledgments
Thanks to Taylor Hornby for authoring the ZIP-314 discussion that identified these vulnerabilities and proposed solutions, and to the Zcash light client community for ongoing work on privacy-preserving infrastructure.
