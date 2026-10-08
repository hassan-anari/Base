//! Public-only upstream fixture for real-network replay injection tests.
//! Never exports secret round state or participates in successful DKG tests.
fn main() {
    let (_secret, public) =
        frost_ed25519::keys::dkg::part1(1u16.try_into().unwrap(), 3, 2, rand_core::OsRng).unwrap();
    println!(
        "{}",
        serde_json::to_string(&public.serialize().unwrap()).unwrap()
    );
}
