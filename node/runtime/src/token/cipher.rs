use support::{
    dispatch::{Vec},
};

use crate::token::primering::PrimeRing;

//
// Suppose x is the private key and y=γ^x is the public
// key.
//
// A transfer amout b is encoded by the sender using
// a group generator γ by γ^b.
//
// For convenience, the encrypted amout of b will looks like the
// following:
//
// cipher_text = γ^b * y^r, γ^r
//
// Which is equal to γ^b * γ^(x * r), γ^r
// Thus the receiver can get γ^b back using
// γ^b = cipher_text.0 / cipher_text.1^x
//

#[derive(PartialEq)]
pub struct EGICipher<T:Copy> {
    pub gamma: T,
    pub prime: T,
}

/*
 * So far the amount is encoded using base γ
 */
pub trait CipherFunctor<Key, F, T> {

    /* encode src to target of T */
    fn encode(&self, pk: Key, src:F, r:F) -> T;

    /* Check wheter a proof proves that the prover knows the src */
    fn check(&self, proof:Vec<T>, t:T) -> bool;

    /*
     * We hope that a ciphertest can be change to another without revealing its
     * secret
     */
    fn switch(&self, old:Key, new:Key, t:T) -> T;

    /*
     * Not all the cipher forms a functor from F to T
     * under operator plus and minus
     */
    fn plus(&self, src:T, target:T) -> T;
    fn minus(&self, src:T, target:T) -> T;

}

/* U128 Pair as Amount Entries */
impl<T:PrimeRing<T>> CipherFunctor<T, T, (T,T)> for EGICipher<T>
    where T:Copy + PartialEq {
    /*
     * Suppose sender sends the amout := a
     * We encode it into (γ^a * pk^r, γ^r)
     */
    fn encode(&self, pk:T, a:T, r:T) -> (T, T) {
        let gamma = self.gamma;
        let p = self.prime;
        let gamma_exp_amt = p.power(gamma, a);
        let p_exp_r = p.power(pk, r);
        let gamma_exp_r = p.power(gamma, r);
        (p.mul(gamma_exp_amt, p_exp_r), gamma_exp_r)
    }

    fn plus(&self, v1:(T, T), v2:(T,T)) -> (T,T) {
        let p = self.prime;
        /* We need to check v1.1 == v2.1 ? */
        (p.mul(v1.0, v2.0), v1.1)
    }

    fn minus(&self, v1:(T, T), v2:(T,T)) -> (T,T) {
        let p = self.prime;
        /* We need to check v1.1 == v2.1 ? */
        (p.div(v1.0, v2.0), v1.1)
    }

    fn switch(&self, old:T, new:T, t:(T,T)) -> (T, T) {
        // cipher_text = γ^b * y^r, γ^r
        let p = self.prime;
        let gamma = self.gamma;
        let delta = p.div(new, old);
        (p.mul(t.0, p.power(delta,gamma)), t.1)
    }

    /*
     * Standard check:
     * hash function h hashes (a, private, r) where r is an randomly picked
     * number of type f:T
     */
    fn check(&self, proof:Vec<(T,T)>, t:(T,T)) -> bool {
        let mut proof_vec = proof.clone();
        let v = proof_vec.pop().unwrap();
        let s = proof_vec.iter().fold(v, |s, val| {
            self.plus(s, *val)
        });
        return s==t
    }
}

mod tests {
    //use super::*;
}
