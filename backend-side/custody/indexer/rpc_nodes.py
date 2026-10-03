"""Compatibility exports for the canonical DB-only RPC resolver."""

from __future__ import annotations

from custody.chain_registry import ChainUnavailable, rpc_urls


def primary_rpc_url(chain_id: str) -> str:
    return rpc_urls(chain_id)[0]


def probe_node(url: str, chain_id: str, timeout: float = 6.0) -> dict:
    """Probe an endpoint according to the configured chain family."""
    import time

    import requests

    from custody.chain_registry import ChainKind, get_chain_spec

    started = time.time()
    try:
        kind = get_chain_spec(chain_id).kind
        if kind is ChainKind.EVM:
            response = requests.post(
                url,
                json={"jsonrpc": "2.0", "id": 1, "method": "eth_blockNumber", "params": []},
                timeout=timeout,
            )
            response.raise_for_status()
            height = int(response.json()["result"], 16)
        elif kind is ChainKind.TRON:
            response = requests.post(
                f"{url.rstrip('/')}/wallet/getnowblock", json={}, timeout=timeout
            )
            response.raise_for_status()
            height = int(
                response.json().get("block_header", {}).get("raw_data", {}).get("number", 0)
            )
        elif kind is ChainKind.SOLANA:
            response = requests.post(
                url,
                json={"jsonrpc": "2.0", "id": 1, "method": "getSlot", "params": []},
                timeout=timeout,
            )
            response.raise_for_status()
            height = int(response.json()["result"])
        elif kind is ChainKind.TON:
            base = url.rstrip("/").removesuffix("/jsonRPC")
            response = requests.get(f"{base}/getMasterchainInfo", timeout=timeout)
            response.raise_for_status()
            height = int(response.json()["result"]["last"]["seqno"])
        else:  # defensive: registry rejects unsupported kinds
            raise ChainUnavailable(f"unsupported probe kind {kind}")
        return {
            "healthy": True,
            "latency_ms": int((time.time() - started) * 1000),
            "block_height": height,
            "sync_status": "synced",
            "last_error": "",
        }
    except Exception as exc:  # probe reports health rather than raising
        return {
            "healthy": False,
            "latency_ms": int((time.time() - started) * 1000),
            "block_height": None,
            "sync_status": "unreachable",
            "last_error": str(exc)[:300],
        }
