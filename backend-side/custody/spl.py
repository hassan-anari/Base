"""Classic SPL Token account identity helpers."""

from solders.pubkey import Pubkey

from .token_metadata import CLASSIC_TOKEN_PROGRAM

ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"


def derive_ata(owner: str, mint: str) -> str:
    """Derive the canonical ATA for owner/mint/classic Token Program."""
    owner_key = Pubkey.from_string(owner)
    mint_key = Pubkey.from_string(mint)
    token_program = Pubkey.from_string(CLASSIC_TOKEN_PROGRAM)
    ata_program = Pubkey.from_string(ASSOCIATED_TOKEN_PROGRAM)
    address, _ = Pubkey.find_program_address(
        [bytes(owner_key), bytes(token_program), bytes(mint_key)], ata_program
    )
    return str(address)
