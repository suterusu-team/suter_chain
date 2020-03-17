use crate::cipher::EGICipher;
use crate::primering::PrimeRing;
use frame_support::{
    dispatch::{Vec},
};

use crate::cipher::CipherFunctor;

pub trait CipherProof <K, F, T> {
    /* Prove that a cipher text is encoded from either zero
     * or one.
     */
    fn bit_proof(&self, b:F, s:F, t:T) -> bool;
    /* Prove that a cipher text is encoded from x ∈ 2^{k-1} */
    fn within_exp(&self, b:F, s:F, target:T, proof:Vec<T>) -> bool;
}

impl<T:PrimeRing<T>> CipherProof<T, T, (T,T)> for EGICipher<T>
    where T:Copy + PartialEq {
    fn bit_proof(&self, b:T, s:T, t:(T,T)) -> bool {
        // cipher_text = γ^a * y^r, γ^r
        /* To proof that a = 1 or 0
         * it is sufficient to proof that t.1 ^ x = t.0
         * or t.1^ x = t.0 / γ.
         *
         * Since we require s = (r + bx)
         * t.1^s = t.1 ^ r * t.1^{bx} = t.1^r * t.0 ^ b (for case 0)
         * t.1^s = t.1 ^ r * t.1^{bx} = t.1^r * t.0/γ ^ b (for case 1)
         */
        let primering = self.prime;
        /* The case zero: */
        let b0 = primering.power(t.0, b);
        /* The case one: */
        let b1 = primering.power(primering.div(t.0, self.gamma), b);
        primering.power(self.gamma, s)
            == primering.mul(t.1, b0)
        || primering.power(self.gamma, s)
            == primering.mul(t.1, b1)
    }

    /* Suppose that
     * R equals to Σ_i x_i*E_i, then it follows that
     * E_k != 0 and x_i needs to be either one or zero.
     * Also ∏_i cipher(x_i*E_i, γ_i) needs to equal to cipher(R*E,γ)
     */
    fn within_exp(&self, b:T, s:T, target:(T,T), proof:Vec<(T,T)>) -> bool {
        let p = proof.iter().fold(true, |acc, val| {
            acc && self.bit_proof(b, s, *val)
        });
        p && self.check(proof, target)
    }
}
