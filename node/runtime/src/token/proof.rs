use crate::token::cipher::EGICipher;
use crate::token::primering::PrimeRing;
use support::{
    dispatch::{Vec},
};

use crate::token::cipher::CipherFunctor;

pub trait CipherProof <K, F, T> {
    /* Prove that a cipher text is encoded from either zero
     * or one.
     */
    fn bit_proof(&self, t:T) -> bool;
    /* Prove that a cipher text is encoded from x ∈ 2^{k-1} */
    fn within_exp(&self, k:F, target:T, proof:Vec<T>) -> bool;
}

impl<T:PrimeRing<T>> CipherProof<T, T, (T,T)> for EGICipher<T>
    where T:Copy + PartialEq {
    fn bit_proof(&self, t:(T,T)) -> bool {
        return true;
    }

    /* Suppose that
     * R equals to Σ_i x_i*E_i, then it follows that
     * E_k != 0 and x_i needs to be either one or zero.
     * Also ∏_i cipher(x_i*E_i, γ_i) needs to equal to cipher(R*E,γ)
     */
    fn within_exp(&self, k:T, target:(T,T), proof:Vec<(T,T)>) -> bool {
        let p = proof.iter().fold(true, |acc, val| {
            acc && self.bit_proof(*val)
        });
        return self.check(proof, target);
    }
}
