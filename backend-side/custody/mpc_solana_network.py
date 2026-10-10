"""Isolated Solana RPC trust policy; genesis pins are established outside RPC.

This trusted RPC boundary is not a light client or proof of RPC honesty.
Public devnet/testnet and mainnet are outside the reviewed activation policy.
"""

from django.conf import settings

from .chain_registry import ChainKind, get_chain_spec, rpc_urls
from .mpc_evm_network import MpcNetworkError, _loopback_endpoint

PUBLIC_GENESIS_PREFIXES = ("5eykt4Us", "EtWTRABZ", "4uhcVJyU")


def authorize_solana_network(chain_id, *, endpoint=None):
    from solders.hash import Hash

    spec = get_chain_spec(chain_id)
    policy = settings.MPC_SOLANA_NETWORK
    if (
        not settings.MPC_SOLANA_INTEGRATION_ENABLED
        or settings.MPC_INTEGRATION_ENVIRONMENT != "development"
        or spec.kind is not ChainKind.SOLANA
        or spec.chain_id != "SOL"
        or not spec.is_testnet
        or spec.evm_chain_id is not None
        or spec.native_decimals != 9
        or not isinstance(policy, dict)
        or policy.get("network") != "isolated-v1"
        or policy.get("genesis_source") != "validator-genesis-artifact"
    ):
        raise MpcNetworkError("Solana MPC permits independently pinned isolated validators only")
    try:
        genesis = policy["genesis_hash"]
        if str(Hash.from_string(genesis)) != genesis or genesis.startswith(PUBLIC_GENESIS_PREFIXES):
            raise ValueError
        artifact = policy["genesis_artifact_sha256"]
        if len(artifact) != 64 or bytes.fromhex(artifact).hex() != artifact:
            raise ValueError
        trusted = policy["trusted_endpoints"]
        if (
            not isinstance(trusted, list)
            or not trusted
            or not all(_loopback_endpoint(url) for url in trusted)
            or not rpc_urls(chain_id)
            or any(url not in trusted for url in rpc_urls(chain_id))
            or (endpoint is not None and endpoint not in trusted)
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise MpcNetworkError(
            "Solana requires independent genesis evidence and trusted endpoints"
        ) from None
    return spec


def network_identity(chain_id):
    authorize_solana_network(chain_id)
    return {
        key: settings.MPC_SOLANA_NETWORK[key]
        for key in ("network", "genesis_hash", "genesis_source", "genesis_artifact_sha256")
    }


def verify_solana_endpoint(chain_id, url, transport):
    authorize_solana_network(chain_id, endpoint=url)
    if transport.rpc(url, "getGenesisHash", []) != settings.MPC_SOLANA_NETWORK["genesis_hash"]:
        raise MpcNetworkError("Solana RPC genesis differs from independently established pin")


def verify_solana_rpc_endpoints(chain_id, transport):
    for url in rpc_urls(chain_id):
        verify_solana_endpoint(chain_id, url, transport)


def guarded_solana_rpc(chain_id, url, transport, method, params):
    if settings.MPC_SIGNER_BACKEND == "self_hosted_mpc":
        verify_solana_endpoint(chain_id, url, transport)
    return transport.rpc(url, method, params)


def require_fresh(chain_id, last_valid_block, transport, *, blockhash):
    """Only a fresh message may start FROST; this does not prove non-inclusion."""
    if type(last_valid_block) is not int or last_valid_block <= 0:
        raise ValueError("Solana validity evidence is missing")
    for url in rpc_urls(chain_id):
        valid = guarded_solana_rpc(
            chain_id, url, transport, "isBlockhashValid", [blockhash, {"commitment": "finalized"}]
        )
        if not isinstance(valid, dict) or valid.get("value") is not True:
            raise ValueError("original Solana blockhash is not valid on trusted RPC")
        height = guarded_solana_rpc(
            chain_id, url, transport, "getBlockHeight", [{"commitment": "finalized"}]
        )
        if type(height) is not int or height + 10 >= last_valid_block:
            raise ValueError("Solana blockhash lacks reviewed signing/broadcast validity margin")
