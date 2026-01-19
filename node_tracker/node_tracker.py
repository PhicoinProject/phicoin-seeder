#!/usr/bin/env python3
import base64
import json
import logging
import os
import socket
import struct
import time
import urllib.request
from typing import Iterable, Optional, Set, Tuple


class RpcClient:
    def __init__(self, host: str, port: int, user: str, password: str, timeout: int):
        self.url = f"http://{host}:{port}/"
        auth = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
        self.auth_header = f"Basic {auth}"
        self.timeout = timeout

    def call(self, method: str, params: Optional[list] = None):
        payload = {
            "jsonrpc": "1.0",
            "id": "node-tracker",
            "method": method,
            "params": params or [],
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self.url, data=data)
        req.add_header("Authorization", self.auth_header)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = resp.read()
        result = json.loads(body)
        if result.get("error"):
            raise RuntimeError(result["error"])
        return result["result"]


def parse_addr(value: str) -> Optional[str]:
    if not value:
        return None
    value = value.strip()
    if value.startswith("[") and "]" in value:
        host, rest = value[1:].split("]", 1)
        if rest.startswith(":") and rest[1:].isdigit():
            return f"{host}:{rest[1:]}"
        return host
    if ":" in value:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return f"{host}:{port}"
    return value


def extract_addrs(peer: dict) -> Set[str]:
    addrs: Set[str] = set()
    for key in ("addr", "addrlocal", "addrbind"):
        value = peer.get(key)
        if not value:
            continue
        addr = parse_addr(value)
        if addr:
            addrs.add(addr)
    return addrs


def write_json(path: str, data: dict) -> None:
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=True, indent=2, sort_keys=True)
    os.replace(tmp_path, path)


def sha256d(data: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def pack_varint(value: int) -> bytes:
    if value < 0xFD:
        return struct.pack("<B", value)
    if value <= 0xFFFF:
        return b"\xFD" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xFE" + struct.pack("<I", value)
    return b"\xFF" + struct.pack("<Q", value)


def pack_varstr(value: str) -> bytes:
    data = value.encode("utf-8")
    return pack_varint(len(data)) + data


def ip_to_bytes(ip: str) -> bytes:
    try:
        return socket.inet_pton(socket.AF_INET6, ip)
    except OSError:
        ipv4 = socket.inet_pton(socket.AF_INET, ip)
        return b"\x00" * 10 + b"\xFF\xFF" + ipv4


def bytes_to_ip(data: bytes) -> str:
    if len(data) != 16:
        return ""
    if data[:12] == b"\x00" * 10 + b"\xFF\xFF":
        return socket.inet_ntop(socket.AF_INET, data[12:])
    return socket.inet_ntop(socket.AF_INET6, data)


def build_message(magic: bytes, command: str, payload: bytes) -> bytes:
    cmd = command.encode("ascii")
    cmd = cmd + b"\x00" * (12 - len(cmd))
    checksum = sha256d(payload)[:4]
    header = magic + cmd + struct.pack("<I", len(payload)) + checksum
    return header + payload


def recv_all(sock: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data += chunk
    return data


def read_message(sock: socket.socket, magic: bytes) -> Optional[Tuple[str, bytes]]:
    header = recv_all(sock, 24)
    if len(header) != 24:
        return None
    if header[:4] != magic:
        return None
    command = header[4:16].split(b"\x00", 1)[0].decode("ascii", "ignore")
    length = struct.unpack("<I", header[16:20])[0]
    checksum = header[20:24]
    payload = recv_all(sock, length)
    if len(payload) != length:
        return None
    if sha256d(payload)[:4] != checksum:
        return None
    return command, payload


def split_host_port(value: str, default_port: int) -> Tuple[str, int]:
    value = value.strip()
    if value.startswith("[") and "]" in value:
        host, rest = value[1:].split("]", 1)
        if rest.startswith(":") and rest[1:].isdigit():
            return host, int(rest[1:])
        return host, default_port
    if value.count(":") >= 2 and value.rsplit(":", 1)[-1].isdigit():
        host, port = value.rsplit(":", 1)
        return host, int(port)
    if ":" in value:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return value, default_port


def normalize_addr(host: str, port: int) -> str:
    return f"{host}:{port}"


def build_version_payload(
    addr_recv: Tuple[str, int],
    addr_from: Tuple[str, int],
    version: int,
    services: int,
    user_agent: str,
    start_height: int,
    relay: bool,
) -> bytes:
    payload = struct.pack("<iQQ", version, services, int(time.time()))
    payload += struct.pack("<Q", 0) + ip_to_bytes(addr_recv[0]) + struct.pack(">H", addr_recv[1])
    payload += struct.pack("<Q", 0) + ip_to_bytes(addr_from[0]) + struct.pack(">H", addr_from[1])
    payload += struct.pack("<Q", int.from_bytes(os.urandom(8), "little"))
    payload += pack_varstr(user_agent)
    payload += struct.pack("<i", start_height)
    payload += struct.pack("<?", relay)
    return payload


def parse_addr_payload(payload: bytes) -> Set[str]:
    addrs: Set[str] = set()
    if not payload:
        return addrs
    idx = 0
    first = payload[idx]
    if first < 0xFD:
        count = first
        idx += 1
    elif first == 0xFD:
        count = struct.unpack_from("<H", payload, idx + 1)[0]
        idx += 3
    elif first == 0xFE:
        count = struct.unpack_from("<I", payload, idx + 1)[0]
        idx += 5
    else:
        count = struct.unpack_from("<Q", payload, idx + 1)[0]
        idx += 9

    for _ in range(count):
        if idx + 30 > len(payload):
            break
        _time = struct.unpack_from("<I", payload, idx)[0]
        _services = struct.unpack_from("<Q", payload, idx + 4)[0]
        ip_bytes = payload[idx + 12: idx + 28]
        port = struct.unpack_from(">H", payload, idx + 28)[0]
        idx += 30
        ip = bytes_to_ip(ip_bytes)
        if ip:
            addrs.add(normalize_addr(ip, port))
    return addrs


def p2p_getaddr(
    target: str,
    default_port: int,
    magic: bytes,
    protocol_version: int,
    services: int,
    user_agent: str,
    start_height: int,
    relay: bool,
    timeout: int,
    handshake_timeout: int,
) -> Set[str]:
    host, port = split_host_port(target, default_port)
    addrs: Set[str] = set()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            payload = build_version_payload(
                (host, port),
                ("0.0.0.0", 0),
                protocol_version,
                services,
                user_agent,
                start_height,
                relay,
            )
            sock.sendall(build_message(magic, "version", payload))

            got_version = False
            got_verack = False
            sent_getaddr = False
            start = time.time()
            while time.time() - start < handshake_timeout:
                msg = read_message(sock, magic)
                if not msg:
                    break
                command, payload = msg
                if command == "version":
                    got_version = True
                    sock.sendall(build_message(magic, "verack", b""))
                elif command == "verack":
                    got_verack = True
                elif command == "ping":
                    sock.sendall(build_message(magic, "pong", payload))
                elif command == "addr":
                    addrs.update(parse_addr_payload(payload))
                    break

                if got_version and got_verack and not sent_getaddr:
                    sock.sendall(build_message(magic, "getaddr", b""))
                    sent_getaddr = True
    except Exception:
        return set()
    return addrs


def collect_peers(rpc: RpcClient) -> Tuple[Set[str], Set[str]]:
    peers = rpc.call("getpeerinfo")
    known: Set[str] = set()
    connected: Set[str] = set()
    for peer in peers:
        addrs = extract_addrs(peer)
        known.update(addrs)
        addr = parse_addr(peer.get("addr", ""))
        if addr:
            connected.add(addr)
    return known, connected


def render_progress(current: int, total: int, width: int = 30) -> str:
    if total <= 0:
        total = 1
    ratio = min(max(current / total, 0.0), 1.0)
    filled = int(ratio * width)
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}] {current}/{total}"


def add_nodes(rpc: RpcClient, addrs: Iterable[str]) -> int:
    count = 0
    addrs_list = list(addrs)
    total = len(addrs_list)
    for idx, addr in enumerate(addrs_list, 1):
        try:
            rpc.call("addnode", [addr, "onetry"])
        except Exception:
            logging.debug("addnode failed: %s", addr)
            continue
        count += 1
        print(f"\raddnode {render_progress(idx, total)}", end="", flush=True)
    if total:
        print()
    return count


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    return cfg


def get_config_path() -> str:
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "config.json")


def main() -> None:
    config_path = get_config_path()
    cfg = load_config(config_path)

    rpc_host = cfg.get("rpc_host", "127.0.0.1")
    rpc_port = int(cfg.get("rpc_port", 18964))
    rpc_user = cfg.get("rpc_user", "phi")
    rpc_pass = cfg.get("rpc_pass", "phi")
    interval = int(cfg.get("interval", 5))
    batch_size = int(cfg.get("batch_size", 50))
    timeout = int(cfg.get("timeout", 10))
    duration = int(cfg.get("duration", 0))

    base_dir = os.path.dirname(os.path.abspath(__file__))
    output = cfg.get("output", os.path.join(base_dir, "nodes.json"))

    use_addnode = bool(cfg.get("use_addnode", True))

    p2p_cfg = cfg.get("p2p", {})
    p2p_enabled = bool(p2p_cfg.get("enabled", True))
    p2p_batch_size = int(p2p_cfg.get("batch_size", 20))
    p2p_timeout = int(p2p_cfg.get("timeout", 5))
    p2p_handshake_timeout = int(p2p_cfg.get("handshake_timeout", 8))
    p2p_protocol_version = int(p2p_cfg.get("protocol_version", 80000))
    p2p_services = int(p2p_cfg.get("services", 1))
    p2p_user_agent = str(p2p_cfg.get("user_agent", "/PHICOIN:2.0.0/"))
    p2p_start_height = int(p2p_cfg.get("start_height", 0))
    p2p_relay = bool(p2p_cfg.get("relay", False))
    p2p_max_addrs = int(p2p_cfg.get("max_addrs", 0))
    p2p_magic_hex = str(p2p_cfg.get("magic", "50484958"))
    p2p_magic = bytes.fromhex(p2p_magic_hex)

    rpc = RpcClient(rpc_host, rpc_port, rpc_user, rpc_pass, timeout)

    known: Set[str] = set()
    attempted: Set[str] = set()
    p2p_attempted: Set[str] = set()
    p2p_discovered: Set[str] = set()
    connected: Set[str] = set()
    started = time.time()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    logging.info("node tracker started: rpc=%s:%s", rpc_host, rpc_port)

    while True:
        try:
            new_known, new_connected = collect_peers(rpc)
        except Exception as exc:
            logging.warning("rpc error: %s", exc)
            time.sleep(interval)
            continue

        known.update(new_known)
        connected = new_connected

        pending = list(known - attempted)
        if pending and use_addnode:
            batch = pending[:batch_size]
            logging.info("new peers=%d pending=%d addnode_batch=%d", len(new_known), len(pending), len(batch))
            added = add_nodes(rpc, batch)
            attempted.update(batch)
        else:
            added = 0

        p2p_new = 0
        if p2p_enabled:
            crawl_targets = list(known - p2p_attempted)
            if crawl_targets:
                crawl_batch = crawl_targets[:p2p_batch_size]
                logging.info("p2p crawl batch=%d", len(crawl_batch))
                for idx, target in enumerate(crawl_batch, 1):
                    found = p2p_getaddr(
                        target,
                        rpc_port,
                        p2p_magic,
                        p2p_protocol_version,
                        p2p_services,
                        p2p_user_agent,
                        p2p_start_height,
                        p2p_relay,
                        p2p_timeout,
                        p2p_handshake_timeout,
                    )
                    p2p_attempted.add(target)
                    if found:
                        new_set = found - known
                        if new_set:
                            if p2p_max_addrs > 0:
                                remaining = max(p2p_max_addrs - len(known), 0)
                                if remaining <= 0:
                                    new_set = set()
                                else:
                                    new_set = set(list(new_set)[:remaining])
                            if new_set:
                                p2p_new += len(new_set)
                                p2p_discovered.update(new_set)
                                known.update(new_set)
                    print(f"\rp2p crawl {render_progress(idx, len(crawl_batch))}", end="", flush=True)
                if crawl_batch:
                    print()

        write_json(
            output,
            {
                "updated_at": int(time.time()),
                "known_nodes": sorted(known),
                "connected_nodes": sorted(connected),
                "attempted_nodes": sorted(attempted),
                "p2p_attempted_count": len(p2p_attempted),
                "p2p_discovered_count": len(p2p_discovered),
                "p2p_last_new": p2p_new,
                "last_addnode_count": added,
            },
        )

        logging.info(
            "known=%d connected=%d attempted=%d added=%d p2p_new=%d",
            len(known),
            len(connected),
            len(attempted),
            added,
            p2p_new,
        )

        if duration and time.time() - started >= duration:
            break
        time.sleep(interval)


if __name__ == "__main__":
    main()
