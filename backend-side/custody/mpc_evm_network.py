"""Explicit Phase 6E network authorization and per-endpoint EVM identity checks."""

from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlsplit

from django.conf import settings

from .chain_registry import ChainKind, get_chain_spec, rpc_urls

# Reviewed public testnets. The custody alias never substitutes for numeric identity.
PUBLIC_TESTNETS = {"ETH": 11155111, "BSC": 97, "MATIC": 80002, "ARB": 421614, "BASE": 84532}
LOCAL_DEVELOPMENT_CHAIN_IDS = frozenset({31337, 31338})


class MpcNetworkError(ValueError):
    """Configured or observed network identity is not authorized for Phase 6E."""


def _loopback_endpoint(url):
    try:
        endpoint = urlsplit(url)
        return (
            endpoint.scheme in {"http", "https"}
            and endpoint.port is not None
            and endpoint.username is None
            and endpoint.password is None
            and not endpoint.fragment
            and ip_address(endpoint.hostname).is_loopback
        )
    except (TypeError, ValueError):
        return False


def authorize_evm_network(chain_id, *, endpoint=None):
    spec = get_chain_spec(chain_id)
    if (
        spec.kind is not ChainKind.EVM
        or not spec.is_testnet
        or spec.chain_id not in PUBLIC_TESTNETS
        or type(spec.evm_chain_id) is not int
        or spec.evm_chain_id <= 0
    ):
        raise MpcNetworkError("Phase 6E integration permits isolated EVM test chains only")
    if spec.evm_chain_id == PUBLIC_TESTNETS[spec.chain_id]:
        return spec
    development = settings.MPC_EVM_DEVELOPMENT_CHAINS
    if (
        spec.evm_chain_id not in LOCAL_DEVELOPMENT_CHAIN_IDS
        or settings.MPC_INTEGRATION_ENVIRONMENT != "development"
        or not isinstance(development, dict)
        or type(development.get(spec.chain_id)) is not int
        or development.get(spec.chain_id) != spec.evm_chain_id
    ):
        raise MpcNetworkError("EVM network is outside the reviewed testnet allowlist")
    # Check the complete failover configuration and the actual endpoint again.
    endpoints = rpc_urls(spec.chain_id)
    if endpoint is not None:
        endpoints.append(endpoint)
    if not all(_loopback_endpoint(url) for url in endpoints):
        raise MpcNetworkError(
            "custom development EVM networks require literal loopback RPC endpoints"
        )
    return spec


def verify_evm_endpoint(chain_id, url, transport):
    spec = authorize_evm_network(chain_id, endpoint=url)
    identity = network_identity(chain_id)
    reported = transport.rpc(url, "eth_chainId", [])
    try:
        if not isinstance(reported, str) or not reported.startswith("0x"):
            raise ValueError
        numeric = int(reported, 16)
    except (TypeError, ValueError):
        raise MpcNetworkError("EVM RPC chain ID response is malformed") from None
    if numeric != spec.evm_chain_id:
        raise MpcNetworkError("EVM RPC chain ID does not match the authorized runtime network")
    if "genesis_hash" in identity:
        block = transport.rpc(url, "eth_getBlockByNumber", ["0x0", False])
        if not isinstance(block, dict) or block.get("hash") != identity["genesis_hash"]:
            raise MpcNetworkError("EVM RPC genesis does not match the approved network")


def network_identity(chain_id):
    spec = authorize_evm_network(chain_id)
    identity = {"evm_chain_id": spec.evm_chain_id}
    pins = settings.MPC_EVM_GENESIS_HASHES
    genesis = pins.get(chain_id) if isinstance(pins, dict) else None
    if genesis is not None or spec.evm_chain_id in LOCAL_DEVELOPMENT_CHAIN_IDS:
        try:
            if not isinstance(genesis, str) or len(genesis) != 66 or not genesis.startswith("0x"):
                raise ValueError
            if bytes.fromhex(genesis[2:]).hex() != genesis[2:] or int(genesis[2:], 16) == 0:
                raise ValueError
        except (TypeError, ValueError):
            raise MpcNetworkError(
                "isolated EVM network requires an approved genesis hash"
            ) from None
        identity["genesis_hash"] = genesis
    return identity


def verify_evm_rpc_endpoints(chain_id, transport):
    for url in rpc_urls(chain_id):
        verify_evm_endpoint(chain_id, url, transport)


def guarded_evm_rpc(chain_id, url, transport, method, params):
    if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
        verify_evm_endpoint(chain_id, url, transport)
    return transport.rpc(url, method, params)
