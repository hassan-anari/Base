"""Phase 6F-A isolated TRON trust boundary; public networks remain disabled.

TRON has no EVM chain ID RPC. Pins must be obtained from the operator's isolated
validator configuration, independently of the execution RPC. A dedicated genesis
parent marker plus two pinned block identities excludes public/mainnet genesis.
These checks authenticate consistency within an explicitly trusted node boundary;
they are not a light-client proof and cannot establish honesty of a malicious node.
"""

import hashlib

from django.conf import settings

from .chain_registry import ChainKind, get_chain_spec, rpc_urls
from .mpc_evm_network import MpcNetworkError, _loopback_endpoint
from .tron_wire import block_identity, hex_bytes

ISOLATED_PARENT = hashlib.sha256(b"Wallet-MPC Phase6F isolated TRON genesis v1").hexdigest()


def authorize_tron_network(chain_id, *, endpoint=None):
    spec = get_chain_spec(chain_id)
    policy = settings.MPC_TRON_NETWORK
    if (
        not settings.MPC_TRON_INTEGRATION_ENABLED
        or settings.MPC_INTEGRATION_ENVIRONMENT != "development"
        or spec.kind is not ChainKind.TRON
        or spec.chain_id != "TRX"
        or not spec.is_testnet
        or spec.evm_chain_id is not None
        or spec.native_decimals != 6
        or not isinstance(policy, dict)
        or policy.get("network") != "isolated-v1"
    ):
        raise MpcNetworkError("TRON MPC permits explicitly pinned isolated test validators only")
    try:
        hex_bytes(policy["genesis_block_id"], 32)
        hex_bytes(policy["checkpoint_block_id"], 32)
        height = policy["checkpoint_height"]
        if type(height) is not int or height <= 0:
            raise ValueError
        if (
            int(policy["genesis_block_id"][:16], 16) != 0
            or int(policy["checkpoint_block_id"][:16], 16) != height
        ):
            raise ValueError
        trusted = policy["trusted_endpoints"]
        endpoints = rpc_urls(chain_id)
        if (
            not isinstance(trusted, list)
            or not trusted
            or not all(_loopback_endpoint(url) for url in trusted)
            or any(url not in trusted for url in endpoints)
            or (endpoint is not None and endpoint not in trusted)
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise MpcNetworkError(
            "TRON requires canonical independent pins and trusted loopback endpoints"
        ) from None
    return spec


def network_identity(chain_id):
    authorize_tron_network(chain_id)
    policy = settings.MPC_TRON_NETWORK
    return {
        key: policy[key]
        for key in ("network", "genesis_block_id", "checkpoint_height", "checkpoint_block_id")
    }


def verify_tron_endpoint(chain_id, url, transport):
    authorize_tron_network(chain_id, endpoint=url)
    policy = settings.MPC_TRON_NETWORK
    for number, expected in (
        (0, policy["genesis_block_id"]),
        (policy["checkpoint_height"], policy["checkpoint_block_id"]),
    ):
        block = transport.post(url, "/wallet/getblockbynum", {"num": number})
        height, observed, _ = block_identity(block)
        if height != number or observed != expected:
            raise MpcNetworkError("TRON RPC does not match independently pinned network evidence")
        if number == 0 and block["block_header"]["raw_data"].get("parentHash") != ISOLATED_PARENT:
            raise MpcNetworkError("public TRON genesis is forbidden in Phase 6F-A")


def verify_tron_rpc_endpoints(chain_id, transport):
    for url in rpc_urls(chain_id):
        verify_tron_endpoint(chain_id, url, transport)


def guarded_tron_post(chain_id, url, transport, path, payload):
    if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
        verify_tron_endpoint(chain_id, url, transport)
    return transport.post(url, path, payload)


def verify_mpc_rpc_endpoints(chain_id, transport):
    from .mpc_evm_network import verify_evm_rpc_endpoints

    if get_chain_spec(chain_id).kind is ChainKind.TRON:
        verify_tron_rpc_endpoints(chain_id, transport)
    elif get_chain_spec(chain_id).kind is ChainKind.SOLANA:
        from .mpc_solana_network import verify_solana_rpc_endpoints

        verify_solana_rpc_endpoints(chain_id, transport)
    elif get_chain_spec(chain_id).kind is ChainKind.EVM:
        verify_evm_rpc_endpoints(chain_id, transport)
    else:
        raise MpcNetworkError("unsupported MPC network family")
