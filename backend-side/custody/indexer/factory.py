"""Runtime registry and family-adapter based indexer factory."""

from __future__ import annotations

from ..chain_adapters import get_adapter
from ..chain_registry import ChainUnavailable, get_chain_spec, rpc_urls
from .base import IndexerClient, IndexerUnavailable


def get_indexer(chain_id: str) -> IndexerClient:
    spec = get_chain_spec(str(chain_id))
    try:
        rpc_urls(spec.chain_id)
    except ChainUnavailable as exc:
        raise IndexerUnavailable(str(exc)) from exc
    return get_adapter(spec.chain_id).build_indexer(spec)
