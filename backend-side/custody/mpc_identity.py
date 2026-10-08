"""Local blockchain identities derived from verified MPC public metadata."""

from .chain_registry import ChainKind, get_chain_spec


def address_from_public_key(chain_id: str, public_key_hex: str) -> str:
    kind = get_chain_spec(chain_id).kind
    raw = bytes.fromhex(public_key_hex.removeprefix("0x"))
    if kind in {ChainKind.EVM, ChainKind.TRON}:
        from eth_keys import keys

        public_key = (
            keys.PublicKey.from_compressed_bytes(raw)
            if len(raw) == 33
            else keys.PublicKey(raw[1:] if len(raw) == 65 and raw[0] == 4 else raw)
        )
        if kind is ChainKind.EVM:
            return public_key.to_checksum_address()
        from tronpy.keys import PublicKey

        return PublicKey(public_key.to_bytes()).to_base58check_address()
    if kind is ChainKind.SOLANA:
        if len(raw) != 32:
            raise ValueError("Solana FROST public key must be 32 bytes")
        from solders.pubkey import Pubkey

        return str(Pubkey.from_bytes(raw))
    raise ValueError("MPC identity is unsupported for this chain")
