# Phicoin Node Tracker

The **Node Tracker** is a lightweight Python utility that discovers, monitors and injects peers into a running Phicoin full node.

## Core Features
- **RPC‑based peer collection** – Uses the JSON‑RPC interface to retrieve `getpeerinfo` and build an initial set of known nodes.
- **P2P crawl** – Connects directly to discovered peers, performs a BIP‑0033‑style handshake, requests their address list (`addr`) and expands the network graph.
- **Automatic node injection** – Calls the RPC `addnode "onetry"` command for new addresses so that the local node learns them.
- **Persisted state** – Writes a JSON file containing known/connected/attempted nodes and statistics after each iteration.
- **Configurable loop** – Runs indefinitely (or until a duration is set) with user‑defined polling interval, batch sizes, timeouts and P2P parameters.

## Configuration
The tracker expects a `config.json` in the same directory.  Example:
```json
{
  "rpc_host": "127.0.0.1",
  "rpc_port": 18964,
  "rpc_user": "phi",
  "rpc_pass": "phi",
  "interval": 5,
  "batch_size": 50,
  "timeout": 10,
  "duration": 0,
  "output": "nodes.json",
  "use_addnode": true,
  "p2p": {
    "enabled": true,
    "batch_size": 20,
    "timeout": 5,
    "handshake_timeout": 8,
    "protocol_version": 80000,
    "services": 1,
    "user_agent": "/PHICOIN:2.0.0/",
    "start_height": 0,
    "relay": false,
    "max_addrs": 0,
    "magic": "50484958"
  }
}
```
All keys are optional; defaults are shown in the source.

## How It Works
1. **Collect RPC peers** – `collect_peers()` pulls `getpeerinfo`, extracts all addresses (`addr`, `addrlocal`, `addrbind`) and records which ones are currently connected.
2. **Add new nodes** – The tracker calls `addnode "onetry"` for a configurable batch of previously unseen addresses.
3. **P2P crawl** – For each node that hasn't been crawled, the script opens a raw TCP connection, performs the version/verack handshake, sends `getaddr`, and parses the returned list of peers via `parse_addr_payload()`. New addresses are merged into the known set.
4. **Persist state** – After every loop iteration the collected data is written to `nodes.json` using an atomic replace strategy (`write_json`).
5. **Loop** – The process repeats every *interval* seconds until a *duration* (in seconds) expires or the script is stopped.

## Usage
```bash
python node_tracker/node_tracker.py
```
Make sure `config.json` is present and the RPC credentials are correct.

---
© 2026 Phicoin team – All rights reserved.