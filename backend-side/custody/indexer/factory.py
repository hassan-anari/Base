"""Indexer client factory by network."""
from __future__ import annotations

from .base import IndexerClient
from .eth import EthIndexer
from .bsc import BscIndexer
from .trx import TrxIndexer
from .sol import SolIndexer
from .ton import TonIndexer
from ..config import Network


_CLIENTS = {
    Network.ETH: EthIndexer,
    Network.BSC: BscIndexer,
    Network.TRX: TrxIndexer,
    Network.SOL: SolIndexer,
    Network.TON: TonIndexer,
}


def get_indexer(network: Network) -> IndexerClient:
    return _CLIENTS[network]()