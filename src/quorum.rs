// This file is part of Chhaya and is licensed under the GNU Affero General Public License v3.0 or later.
// See the LICENSE file in the project root for license details.

use blstrs::{pairing, G1Projective, G2Affine, G2Projective, Scalar};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group};
use rand_core_06::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Public parameters describing a BLS signing quorum.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumDescriptor {
    pub sig_algo: String,
    pub member_set_hash: [u8; 32],
    pub epoch: u64,
}

impl QuorumDescriptor {
    pub fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.sig_algo.as_bytes());
        hasher.update(self.member_set_hash);
        hasher.update(self.epoch.to_le_bytes());
        let o = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&o);
        out
    }
}

/// Domain separation tag used when hashing messages for signatures.
pub const SIG_DST: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
/// Domain separation tag used when deriving proofs of possession.
pub const POP_DST: &[u8] = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

/// Hashes arbitrary data into the G1 curve using the provided domain separation tag.
pub fn hash_to_g1(msg: &[u8], dst: &[u8]) -> G1Projective {
    G1Projective::hash_to_curve(msg, dst, &[])
}

/// Produces a BLS signature for `msg` using `sk` and domain separation `dst`.
pub fn bls_sign(sk: &Scalar, msg: &[u8], dst: &[u8]) -> G1Projective {
    let h = hash_to_g1(msg, dst);
    h * sk
}

/// Verifies a BLS signature against the supplied public key and message.
pub fn bls_verify(pk: &G2Projective, msg: &[u8], sig: &G1Projective, dst: &[u8]) -> bool {
    let h = hash_to_g1(msg, dst);
    pairing(&sig.to_affine(), &G2Affine::generator()) == pairing(&h.to_affine(), &pk.to_affine())
}

/// Checks that the proof of possession matches the given BLS public key.
pub fn verify_proof_of_possession(pk: &G2Projective, pop: &G1Projective) -> bool {
    let pk_bytes = pk.to_affine().to_compressed();
    let h = hash_to_g1(&pk_bytes, POP_DST);
    pairing(&pop.to_affine(), &G2Affine::generator()) == pairing(&h.to_affine(), &pk.to_affine())
}

/// Public information associated with a quorum participant's key share.
#[derive(Clone, Debug)]
pub struct KeySharePublic {
    pub id: Scalar,
    pub pk: G2Projective,
    pub pop: G1Projective,
}

/// Secret and public material for a single quorum participant.
#[derive(Clone, Debug)]
pub struct KeyShare {
    pub id: Scalar,
    pub sk: Scalar,
    pub public: KeySharePublic,
}

/// Deterministically generates threshold shares for testing the quorum flow.
pub fn happy_path_ceremony(
    n: usize,
    t: usize,
    epoch: u64,
    rng: &mut impl RngCore,
) -> (QuorumDescriptor, G2Projective, Vec<KeyShare>) {
    let secret = Scalar::random(&mut *rng);
    let mut coeffs = vec![secret];
    for _ in 1..t {
        coeffs.push(Scalar::random(&mut *rng));
    }
    let mut shares = Vec::with_capacity(n);
    for i in 1..=n {
        let x = Scalar::from(i as u64);
        let mut y = Scalar::ZERO;
        let mut x_pow = Scalar::ONE;
        for coeff in &coeffs {
            y += *coeff * x_pow;
            x_pow *= x;
        }
        let pk = G2Projective::generator() * y;
        let pk_bytes = pk.to_affine().to_compressed();
        let h = hash_to_g1(&pk_bytes, POP_DST);
        let pop = h * y;
        shares.push(KeyShare {
            id: x,
            sk: y,
            public: KeySharePublic { id: x, pk, pop },
        });
    }
    let mut pks: Vec<Vec<u8>> = shares
        .iter()
        .map(|s| s.public.pk.to_affine().to_compressed().to_vec())
        .collect();
    pks.sort();
    let mut hasher = Sha256::new();
    for pk_bytes in pks {
        hasher.update(pk_bytes);
    }
    let mut member_hash = [0u8; 32];
    member_hash.copy_from_slice(&hasher.finalize());
    let desc = QuorumDescriptor {
        sig_algo: "BLS12381G1_XMD:SHA-256_SSWU_RO".to_string(),
        member_set_hash: member_hash,
        epoch,
    };
    let group_pk = G2Projective::generator() * secret;
    (desc, group_pk, shares)
}

/// Signs a message using a single quorum member's share.
pub fn partial_sign(share: &KeyShare, msg: &[u8], dst: &[u8]) -> G1Projective {
    bls_sign(&share.sk, msg, dst)
}

/// Errors returned when aggregating threshold signatures.
#[derive(Debug)]
pub enum QuorumError {
    Singular,
}

/// Lagrange-interpolates partial signatures into a group signature.
pub fn aggregate_signatures(parts: &[(Scalar, G1Projective)]) -> Result<G1Projective, QuorumError> {
    let ids: Vec<Scalar> = parts.iter().map(|(id, _)| *id).collect();
    let mut agg = G1Projective::identity();
    for (i, (id_i, sig_i)) in parts.iter().enumerate() {
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (j, id_j) in ids.iter().enumerate() {
            if i != j {
                num *= -*id_j;
                den *= *id_i - *id_j;
            }
        }
        let inv = den.invert();
        let inv = inv.into_option().ok_or(QuorumError::Singular)?;
        let coeff = num * inv;
        agg += sig_i * coeff;
    }
    Ok(agg)
}

/// Verifies the proof of possession attached to a share's public information.
pub fn verify_share_pop(share: &KeySharePublic) -> bool {
    verify_proof_of_possession(&share.pk, &share.pop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use group::{Curve, Group};
    use rand_core_06::OsRng;

    #[test]
    fn bls_sign_verify_roundtrip() {
        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);
        let pk = G2Projective::generator() * sk;
        let msg = b"hello";
        let dst = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
        let sig = bls_sign(&sk, msg, dst);
        assert!(bls_verify(&pk, msg, &sig, dst));
    }

    #[test]
    fn bls_pop_verification() {
        let mut rng = OsRng;
        let sk = Scalar::random(&mut rng);
        let pk = G2Projective::generator() * sk;
        let pk_bytes = pk.to_affine().to_compressed();
        let dst = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
        let h = hash_to_g1(&pk_bytes, dst);
        let pop = h * sk;
        assert!(verify_proof_of_possession(&pk, &pop));
    }

    #[test]
    fn threshold_sign_roundtrip() {
        let mut rng = OsRng;
        let (desc, group_pk, shares) = happy_path_ceremony(3, 2, 1, &mut rng);
        assert_eq!(desc.epoch, 1);
        for s in &shares {
            assert!(verify_share_pop(&s.public));
        }
        let msg = b"test";
        let sig1 = partial_sign(&shares[0], msg, SIG_DST);
        let sig2 = partial_sign(&shares[1], msg, SIG_DST);
        let full = aggregate_signatures(&[(shares[0].id, sig1), (shares[1].id, sig2)]).unwrap();
        assert!(bls_verify(&group_pk, msg, &full, SIG_DST));
    }
}
