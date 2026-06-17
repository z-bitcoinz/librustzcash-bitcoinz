use blake2b_simd::Params;
use ff::Field;
use rand_core::{CryptoRng, RngCore};

use crate::consensus::{self, BlockHeight};

use super::Rseed;

pub fn hash_to_scalar(persona: &[u8], a: &[u8], b: &[u8]) -> jubjub::Fr {
    let mut hasher = Params::new().hash_length(64).personal(persona).to_state();
    hasher.update(a);
    hasher.update(b);
    let ret = hasher.finalize();
    jubjub::Fr::from_bytes_wide(ret.as_array())
}

pub fn generate_random_rseed<P: consensus::Parameters, R: RngCore + CryptoRng>(
    params: &P,
    height: BlockHeight,
    rng: &mut R,
) -> Rseed {
    generate_random_rseed_internal(params, height, rng)
}

pub(crate) fn generate_random_rseed_internal<P: consensus::Parameters, R: RngCore>(
    _params: &P,
    _height: BlockHeight,
    rng: &mut R,
) -> Rseed {
    // BitcoinZ never implemented ZIP-212: its "Canopy" upgrade only changed
    // funding-streams/mining, not Sapling note encryption. Old BitcoinZ Core full
    // nodes (e.g. 2.2.0) only understand the legacy v1 (BeforeZip212, note-plaintext
    // lead byte 0x01) format and silently drop any v2 (AfterZip212, 0x02) note on
    // receive. So we ALWAYS emit v1 notes here, regardless of height, so that both old
    // full nodes AND modern wallets can detect incoming shielded payments. (The
    // matching receive path in note_encryption.rs accepts both 0x01 and 0x02.)
    Rseed::BeforeZip212(jubjub::Fr::random(rng))
}
