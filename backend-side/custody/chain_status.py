"""
Chain / node status service.

Live-probes every enabled chain's RPC endpoint(s) and reports whether each
network node is ONLINE and reachable, with block height + latency.

Design:
  * Uses custody/indexer/rpc_nodes.probe_node(), which is chain-family aware:
      EVM  -> eth_blockNumber      TRON -> /wallet/getnowblock
      SOL  -> getSlot              TON  -> getMasterchainInfo
  * Probes run concurrently (ThreadPoolExecutor) so the endpoint stays fast
    even when some RPCs hang; per-probe timeout bounds worst case.
  * Never raises — every chain always yields a status row.
  * No secrets involved: RPC URLs are non-secret infra config, and we never
    include full URLs in responses (only the host) to avoid leaking internal
    topology to lower-privileged users.
"""
from __future__ import annotations

import logging
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Optional
from urllib.parse import urlparse

from django.utils import timezone

from .config import get_chains

logger = logging.getLogger("custody.chain_status")

# How many chains to probe at once (5 preset chains => all in parallel).
_MAX_WORKERS = 8


def _host_of(url: str) -> str:
    """Extract just the host[:port] from an RPC URL (no path/creds)."""
    try:
        p = urlparse(url)
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
        return host
    except Exception:  # noqa: BLE001 - defensive; never break status page
        return ""


def _tcp_reachable(url: str, timeout: float = 3.0) -> bool:
    """Cheap TCP-level reachability check of the RPC host (pre-DNS/TLS diag)."""
    try:
        p = urlparse(url)
        if not p.hostname or not p.port:
            return True  # nothing to check (e.g. default port scheme)
        sock = socket.create_connection((p.hostname, p.port), timeout=timeout)
        sock.close()
        return True
    except OSError:
        return False


def _probe_chain(chain_id: str, timeout: float = 6.0) -> dict:
    """Probe one chain: primary RPC + TCP fallback diagnostics."""
    from .chain_registry import ChainUnavailable
    from .indexer.rpc_nodes import probe_node as _probe, rpc_urls

    cfg = get_chains()[chain_id]
    try:
        urls = rpc_urls(chain_id)
    except ChainUnavailable:
        urls = []
    primary = urls[0] if urls else ""

    result = {
        "chain_id": chain_id,
        "display_name": cfg.display_name,
        "kind": cfg.kind.value,
        "enabled": cfg.enabled,
        "memo_required": cfg.memo_required,
        "node_host": _host_of(primary),
        "endpoint_count": len(urls),
        "online": False,
        "latency_ms": None,
        "block_height": None,
        "sync_status": "unconfigured",
        "last_error": "",
        "checked_at": timezone.now().isoformat(),
    }

    if not urls:
        result["last_error"] = "no RPC endpoint configured"
        return result

    # Probe the best-first list until one answers.
    last = {}
    for url in urls[:3]:  # cap fan-out to first 3 endpoints
        last = _probe(url, chain_id, timeout=timeout)
        if last.get("healthy"):
            break

    result["online"] = bool(last.get("healthy"))
    result["latency_ms"] = last.get("latency_ms")
    result["block_height"] = last.get("block_height")
    result["sync_status"] = last.get("sync_status", "unknown")
    result["last_error"] = (last.get("last_error") or "")[:300]

    # Extra diagnostic when RPC-level probe failed but TCP might still work.
    if not result["online"] and primary:
        tcp_ok = _tcp_reachable(primary)
        if tcp_ok:
            result["sync_status"] = "tcp-ok-rpc-error"
            if not result["last_error"]:
                result["last_error"] = "host reachable but RPC call failed"
    return result


def check_all_chains(chain_id: Optional[str] = None,
                     timeout: float = 6.0) -> dict:
    """Probe every enabled chain (or a single one) and roll up the result.

    Returns:
        {
          "status": "ok" | "degraded" | "down",
          "online_count": int, "total_count": int,
          "chains": [ {chain_id, online, latency_ms, block_height, ...} ],
          "generated_at": iso,
        }
    """
    registry = get_chains()
    ids = ([chain_id] if chain_id in registry
           else [c.chain_id for c in registry.values() if c.enabled])

    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, max(1, len(ids)))) as ex:
        rows = list(ex.map(lambda cid: _probe_chain(cid, timeout=timeout), ids))

    online = sum(1 for r in rows if r["online"])
    if online == len(rows):
        status = "ok"
    elif online > 0:
        status = "degraded"
    else:
        status = "down"

    return {
        "status": status,
        "online_count": online,
        "total_count": len(rows),
        "chains": rows,
        "generated_at": timezone.now().isoformat(),
    }


def stale_since(seconds: int = 300):
    """Helper for UIs: timestamp threshold after which cached data is stale."""
    return timezone.now() - timedelta(seconds=seconds)
