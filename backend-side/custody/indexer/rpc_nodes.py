"""
Editable per-chain RPC node resolution.

Resolution order for a chain's RPC URL:
  1. ops.NodeEndpoint rows (DB) — kind="rpc", enabled=True, ordered by
     is_primary DESC, priority ASC. These are EDITABLE at runtime from the
     ops dashboard (POST/PATCH /ops/nodes), so operators can rotate RPC
     providers without a redeploy.
  2. Fallback: the static ChainConfig.rpc_url from env/registry
     (RPC_ETH / RPC_BSC / RPC_TRX / RPC_SOL / RPC_TON).

No secrets here. RPC URLs are non-secret infrastructure config.
"""
from __future__ import annotations

import logging
from typing import List, Optional

logger = logging.getLogger("custody.rpc_nodes")


def rpc_urls(chain_id: str) -> List[str]:
    """All usable RPC URLs for a chain, best-first (DB nodes then env)."""
    urls: List[str] = []
    try:
        from ops.models import NodeEndpoint
        qs = (NodeEndpoint.objects
              .filter(chain_id=chain_id, kind="rpc", enabled=True)
              .order_by("-is_primary", "priority", "name"))
        urls = [n.url for n in qs if n.url]
    except Exception as e:  # noqa: BLE001 - DB unavailable => env fallback
        logger.debug("node registry unavailable for %s: %s", chain_id, e)
    try:
        from ..config import get_chain
        env_url = get_chain(chain_id).rpc_url
        if env_url and env_url not in urls:
            urls.append(env_url)
    except Exception:  # noqa: BLE001
        pass
    return urls


def primary_rpc_url(chain_id: str) -> Optional[str]:
    """Best RPC URL for a chain, or None if nothing configured."""
    urls = rpc_urls(chain_id)
    return urls[0] if urls else None


def probe_node(url: str, chain_id: str, timeout: float = 6.0) -> dict:
    """Live-probe one RPC endpoint. Returns health fields (never raises).

    Chain-family aware:
      EVM  : eth_blockNumber (JSON-RPC)
      TRON : GET /wallet/getnowblock
      SOL  : getSlot (JSON-RPC)
      TON  : getMasterchainInfo (toncenter v2)
    """
    import time
    import requests
    from ..config import get_chain, ChainKind

    t0 = time.time()
    try:
        kind = get_chain(chain_id).kind
    except Exception:  # noqa: BLE001
        kind = None

    try:
        if kind == ChainKind.EVM:
            r = requests.post(url, json={"jsonrpc": "2.0", "id": 1,
                                         "method": "eth_blockNumber",
                                         "params": []}, timeout=timeout)
            r.raise_for_status()
            height = int(r.json()["result"], 16)
        elif kind == ChainKind.TRON:
            base = url.rstrip("/")
            r = requests.post(f"{base}/wallet/getnowblock", json={},
                              timeout=timeout)
            r.raise_for_status()
            height = int(r.json().get("block_header", {})
                         .get("raw_data", {}).get("number", 0))
        elif kind == ChainKind.SOLANA:
            r = requests.post(url, json={"jsonrpc": "2.0", "id": 1,
                                         "method": "getSlot",
                                         "params": []}, timeout=timeout)
            r.raise_for_status()
            height = int(r.json()["result"])
        elif kind == ChainKind.TON:
            # Accept both REST-style (…/api/v2/getMasterchainInfo) and
            # JSON-RPC-style (…/api/v2/jsonRPC) base URLs.
            base = url.rstrip("/")
            if base.endswith("/jsonRPC"):
                base = base[: -len("/jsonRPC")]
            r = requests.get(f"{base}/getMasterchainInfo",
                             timeout=timeout)
            r.raise_for_status()
            height = int(r.json()["result"]["last"]["seqno"])
        else:
            r = requests.get(url, timeout=timeout)
            r.raise_for_status()
            height = None
        latency_ms = int((time.time() - t0) * 1000)
        return {"healthy": True, "latency_ms": latency_ms,
                "block_height": height, "sync_status": "synced",
                "last_error": ""}
    except Exception as e:  # noqa: BLE001 - probe must report, not raise
        latency_ms = int((time.time() - t0) * 1000)
        return {"healthy": False, "latency_ms": latency_ms,
                "block_height": None, "sync_status": "unreachable",
                "last_error": str(e)[:300]}