extern crate rand;
extern crate curve25519_dalek;
extern crate merlin;
extern crate bulletproofs;

// Range proof using the native bulletproofs interface

use curve25519_dalek::scalar::Scalar;
use rand::thread_rng;
use merlin::Transcript;
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};

#[cfg(test)]
mod tests {
    use super::*;
    use merlin::Transcript;
    use rand::rngs::OsRng;
    use rand::Rng;

    #[test]
    // Test Bulletproof's internal API from the outside
    fn test_builtin_api() {
        // Generators for Pedersen commitments.  These can be selected
        // independently of the Bulletproofs generators.
        let pc_gens = PedersenGens::default();

        // Generators for Bulletproofs, valid for proofs up to bitsize 64
        // and aggregation size up to 1.
        let bp_gens = BulletproofGens::new(64, 1);

        // A secret value we want to prove lies in the range [0, 2^16)
        let mut rng = rand::thread_rng();
        let secret_value = rng.gen_range(0, 1 << 16);

        // The API takes a blinding factor for the commitment.
        let blinding = Scalar::random(&mut thread_rng());

        // The proof can be chained to an existing transcript.
        // Here we create a transcript with a doctest domain separator.
        let mut prover_transcript = Transcript::new(b"doctest example");

        // Create a 16-bit rangeproof.
        let (proof, committed_value) = RangeProof::prove_single(
            &bp_gens,
            &pc_gens,
            &mut prover_transcript,
            secret_value,
            &blinding,
            16,
        ).expect("A real program could handle errors");

        // Verification requires a transcript with identical initial state:
        let mut verifier_transcript = Transcript::new(b"doctest example");
        assert!(
            proof
                .verify_single(&bp_gens, &pc_gens, &mut verifier_transcript, &committed_value, 16)
                .is_ok()
        );
    }
}
