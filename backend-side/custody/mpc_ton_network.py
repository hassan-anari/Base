"""TON-only policy for the pinned, proof-verified disposable validator fixture.

Local genesis anchors the upstream consensus verifier and independently checked
shard ancestry. Configuration flags cannot authorize a public network.
"""

from django.conf import settings

from .chain_registry import ChainKind, get_chain_spec, rpc_urls
from .mpc_evm_network import MpcNetworkError, _loopback_endpoint
from .ton_wire import wallet_id

# The actual consensus/inclusion path is separately exercised by the TON suite.
FINALITY_ACCEPTANCE_COMPLETE = True


def network_identity(chain_id):
    spec = get_chain_spec(chain_id)
    policy = settings.MPC_TON_NETWORK
    if (
        spec.kind is not ChainKind.TON
        or spec.chain_id != "TON"
        or not spec.is_testnet
        or spec.evm_chain_id is not None
        or spec.native_decimals != 9
    ):
        raise MpcNetworkError("TON requires isolated network registry identity")
    if (
        not isinstance(policy, dict)
        or policy.get("network") != "isolated-acton-v1"
        or policy.get("genesis_source") != "localton-generated-zerostate"
    ):
        raise MpcNetworkError("independently established TON genesis required")
    try:
        wallet_id(policy["global_id"])
        for name in (
            "zerostate_root_hash",
            "zerostate_file_hash",
            "basechain_zerostate_root_hash",
            "basechain_zerostate_file_hash",
            "settings_sha256",
            "image_digest",
        ):
            value = policy[name]
            if len(value) != 64 or bytes.fromhex(value).hex() != value:
                raise ValueError
    except (KeyError, TypeError, ValueError):
        raise MpcNetworkError("incomplete TON genesis artifact identity") from None
    return {
        k: policy[k]
        for k in (
            "network",
            "global_id",
            "genesis_source",
            "zerostate_root_hash",
            "zerostate_file_hash",
            "basechain_zerostate_root_hash",
            "basechain_zerostate_file_hash",
            "settings_sha256",
            "image_digest",
        )
    }


def authorize_ton_network(chain_id, *, endpoint=None):
    network_identity(chain_id)
    policy = settings.MPC_TON_NETWORK
    if (
        not settings.MPC_TON_INTEGRATION_ENABLED
        or settings.MPC_SIGNER_BACKEND != "self_hosted_mpc"
        or settings.MPC_INTEGRATION_ENVIRONMENT != "development"
        or settings.CUSTODY_DEMO_MODE
        or settings.CUSTODY_TX_MODE != "live"
        or settings.CUSTODY_INDEXER_MODE != "live"
    ):
        raise MpcNetworkError("TON MPC isolated feature is disabled")
    trusted = policy.get("trusted_endpoints")
    if (
        not isinstance(trusted, list)
        or not trusted
        or not all(_loopback_endpoint(x) for x in trusted)
        or any(x not in trusted for x in rpc_urls(chain_id))
        or (endpoint is not None and endpoint not in trusted)
    ):
        raise MpcNetworkError("TON loopback endpoint boundary mismatch")
    if not FINALITY_ACCEPTANCE_COMPLETE:
        raise MpcNetworkError("TON_MASTERCHAIN_FINALITY_ACCEPTANCE_INCOMPLETE")
    return get_chain_spec(chain_id)


def verify_ton_rpc_endpoints(chain_id, transport):
    del transport
    client = proof_client(chain_id)
    checkpoint, _ = client.checkpoint()
    return checkpoint


def proof_client(chain_id):
    authorize_ton_network(chain_id)
    from .ton_proofs import TonProofClient

    policy = settings.MPC_TON_NETWORK
    paths = policy.get("artifacts", {})
    return TonProofClient(
        binary=paths["lite_client"],
        config=paths["global_config"],
        zerostate=paths["zerostate"],
        basestate=paths["basestate"],
        settings_file=paths["settings"],
        identity=network_identity(chain_id),
    )
