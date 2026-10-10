//! Independently rebuild the pinned V5R1 authorization with an upstream cell library.
//! No secret, coordinator, signing primitive, or RPC is implemented here.
use crate::{dkg::hex, sign::decode_hex};
use anyhow::{ensure, Context, Result};
use everscale_types::{
    boc::Boc,
    cell::{Cell, CellBuilder},
};
use serde::{Deserialize, Serialize};

pub const CODE_HASH: &str = "20834b7b72b112147e1b2fb457b84e74d1a30f04f737d4f62a668e9552d2b72f";
pub const JETTON_CODE_HASH: &str =
    "a760d629d5343e76d045017d9dc216fc8a307a8377815feb2b0a5c490e733486";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TonAuthorization {
    pub wallet_version: String,
    pub code_hash: String,
    pub workchain: i8,
    pub network_global_id: i32,
    pub wallet_id: u32,
    pub seqno: u32,
    pub valid_until: u32,
    pub deploy: bool,
    pub destination: String,
    pub amount: String,
    pub attached_nanoton: String,
    pub bounce: bool,
    pub send_mode: u8,
    pub comment_hex: String,
    pub jetton_master: Option<String>,
    pub jetton_source: Option<String>,
    pub jetton_destination: Option<String>,
    pub jetton_wallet_code_hash: Option<String>,
    pub query_id: Option<u64>,
    pub signed_cell_boc_hex: String,
    pub state_init_boc_hex: Option<String>,
}
fn code(jetton: bool) -> Result<Cell> {
    let (artifact, expected) = if jetton {
        (
            include_str!("../../../backend-side/custody/ton_contracts/jetton-wallet.boc.hex"),
            JETTON_CODE_HASH,
        )
    } else {
        (
            include_str!("../../../backend-side/custody/ton_contracts/wallet-v5r1.boc.hex"),
            CODE_HASH,
        )
    };
    let cell = Boc::decode_hex(artifact.trim())?;
    ensure!(
        hex(cell.repr_hash().as_slice()) == expected,
        "contract artifact mismatch"
    );
    Ok(cell)
}
fn init(code: Cell, data: Cell) -> Result<Cell> {
    let mut b = CellBuilder::new();
    b.store_small_uint(6, 5)?; // split_depth=None, special=None, code=Some, data=Some, library=empty
    b.store_reference(code)?;
    b.store_reference(data)?;
    Ok(b.build()?)
}
fn address(builder: &mut CellBuilder, address: &str) -> Result<()> {
    let hash = address
        .strip_prefix("0:")
        .context("workchain zero raw address required")?;
    let raw = decode_hex(hash).context("invalid address")?;
    ensure!(
        raw.len() == 32 && hex(&raw) == hash,
        "canonical address required"
    );
    builder.store_small_uint(4, 3)?; // addr_std$10 anycast=None
    builder.store_u8(0)?;
    builder.store_raw(&raw, 256)?;
    Ok(())
}
fn coins(builder: &mut CellBuilder, text: &str) -> Result<()> {
    let value: u128 = text.parse()?;
    ensure!(
        value < (1u128 << 120) && value.to_string() == text,
        "invalid Coins"
    );
    let size = (128 - value.leading_zeros()).div_ceil(8) as u8;
    builder.store_small_uint(size, 4)?;
    let bytes = value.to_be_bytes();
    builder.store_raw(&bytes[16 - usize::from(size)..], u16::from(size) * 8)?;
    Ok(())
}
fn comment(text: &str) -> Result<Cell> {
    let raw = decode_hex(text).context("invalid comment")?;
    ensure!(raw.len() <= 96 && hex(&raw) == text, "unsupported comment");
    let mut b = CellBuilder::new();
    if !raw.is_empty() {
        b.store_u32(0)?;
        b.store_raw(&raw, (raw.len() * 8) as u16)?;
    }
    Ok(b.build()?)
}
fn jetton_address(owner: &str, master: &str) -> Result<String> {
    let code = code(true)?;
    let mut data = CellBuilder::new();
    coins(&mut data, "0")?;
    address(&mut data, owner)?;
    address(&mut data, master)?;
    data.store_reference(code.clone())?;
    Ok(format!(
        "0:{}",
        hex(init(code, data.build()?)?.repr_hash().as_slice())
    ))
}
impl TonAuthorization {
    pub fn signing_hash(&self, group: &str, source: &str, asset: &str) -> Result<Vec<u8>> {
        ensure!(
            self.wallet_version == "V5R1"
                && self.code_hash == CODE_HASH
                && self.workchain == 0
                && self.network_global_id < 0
                && ![-239, -3].contains(&self.network_global_id)
                && self.wallet_id == ((self.network_global_id as u32) ^ 0x80000000)
                && self.send_mode == 3
                && self.valid_until > 0
                && (!self.deploy || self.seqno == 0),
            "unapproved TON wallet context"
        );
        let public = decode_hex(group).context("invalid group")?;
        ensure!(public.len() == 32, "invalid FROST owner");
        let mut data = CellBuilder::new();
        data.store_bit_one()?;
        data.store_u32(0)?;
        data.store_u32(self.wallet_id)?;
        data.store_raw(&public, 256)?;
        data.store_bit_zero()?;
        let state_init = init(code(false)?, data.build()?)?;
        ensure!(
            source == format!("0:{}", hex(state_init.repr_hash().as_slice())),
            "TON StateInit source mismatch"
        );
        match &self.state_init_boc_hex {
            Some(raw) => ensure!(
                self.deploy
                    && raw.len() <= 8192
                    && Boc::decode_hex(raw)?.repr_hash() == state_init.repr_hash(),
                "deployment mismatch"
            ),
            None => ensure!(!self.deploy, "deployment StateInit missing"),
        }
        ensure!(self.amount != "0", "positive amount required");
        let (to, body) = match &self.jetton_master {
            None => {
                ensure!(
                    asset == "TON"
                        && self.query_id.is_none()
                        && self.jetton_source.is_none()
                        && self.jetton_destination.is_none()
                        && self.jetton_wallet_code_hash.is_none()
                        && self.attached_nanoton == self.amount,
                    "native authorization mismatch"
                );
                (self.destination.clone(), comment(&self.comment_hex)?)
            }
            Some(master) => {
                ensure!(
                    asset != "TON"
                        && self.bounce
                        && self.attached_nanoton == "100000000"
                        && self.jetton_wallet_code_hash.as_deref() == Some(JETTON_CODE_HASH),
                    "Jetton policy mismatch"
                );
                let from = jetton_address(source, master)?;
                ensure!(
                    self.jetton_source.as_ref() == Some(&from)
                        && self.jetton_destination.as_ref()
                            == Some(&jetton_address(&self.destination, master)?),
                    "Jetton owner/master mismatch"
                );
                let mut b = CellBuilder::new();
                b.store_u32(0x0f8a7ea5)?;
                b.store_u64(self.query_id.context("missing query ID")?)?;
                coins(&mut b, &self.amount)?;
                address(&mut b, &self.destination)?;
                address(&mut b, source)?;
                b.store_bit_zero()?; // no custom payload
                coins(&mut b, "1")?; // fixed notification budget
                b.store_bit_one()?;
                b.store_reference(comment(&self.comment_hex)?)?;
                (from, b.build()?)
            }
        };
        let mut msg = CellBuilder::new();
        msg.store_small_uint(if self.bounce { 6 } else { 4 }, 4)?;
        msg.store_small_uint(0, 2)?; // relaxed source addr_none
        address(&mut msg, &to)?;
        coins(&mut msg, &self.attached_nanoton)?;
        msg.store_bit_zero()?; // no extra currencies
        coins(&mut msg, "0")?;
        coins(&mut msg, "0")?;
        msg.store_u64(0)?;
        msg.store_u32(0)?;
        msg.store_bit_zero()?; // no recipient StateInit
        if msg.size_bits() + body.bit_len() < 1023 && msg.size_refs() + body.reference_count() <= 4
        {
            msg.store_bit_zero()?;
            msg.store_slice(body.as_slice()?)?;
        } else {
            msg.store_bit_one()?;
            msg.store_reference(body)?;
        }
        let mut action = CellBuilder::new();
        action.store_reference(CellBuilder::new().build()?)?;
        action.store_u32(0x0ec3c86d)?;
        action.store_u8(3)?;
        action.store_reference(msg.build()?)?;
        let mut signing = CellBuilder::new();
        signing.store_u32(0x7369676e)?;
        signing.store_u32(self.wallet_id)?;
        signing.store_u32(self.valid_until)?;
        signing.store_u32(self.seqno)?;
        signing.store_bit_one()?;
        signing.store_reference(action.build()?)?;
        signing.store_bit_zero()?; // no extensions / signature mode changes
        let cell = signing.build()?;
        ensure!(
            self.signed_cell_boc_hex.len() <= 8192
                && Boc::decode_hex(&self.signed_cell_boc_hex)?.repr_hash() == cell.repr_hash(),
            "canonical signed TON cell mismatch"
        );
        Ok(cell.repr_hash().as_slice().to_vec())
    }
}
