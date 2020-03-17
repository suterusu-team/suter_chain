pub use primitive_types::{U256};
use frame_support::{
    dispatch::{Vec},
};

pub trait PrimeRing<T> {
    fn mul(self:&Self, x:T, y:T) -> T;
    fn power(self:&Self, x:T, y:T) -> T;
    fn plus(self:&Self, x:T, y:T) -> T;
    fn minus(self:&Self, x:T, y:T) -> T;
    fn inverse(self:&Self, x:T) -> T;
    fn div(self:&Self, x:T,y:T) -> T;
    fn zero(self:&Self) -> T;
    fn one(self:&Self) -> T;
}

impl PrimeRing<u128> for u128{
    fn plus(self:&Self, x:u128,y:u128) -> u128 {
        let x256 = U256::from(x);
        let y256 = U256::from(y);
        let z = x256 + y256;
        z.checked_rem(U256::from(*self)).unwrap().as_u128()
    }

    fn minus(self:&Self, x:u128,y:u128) -> u128 {
        let x256 = U256::from(x);
        let y256 = U256::from(y);
        let z = x256 - y256;
        z.checked_rem(U256::from(*self)).unwrap().as_u128()
    }


    /*
     * May be not quick enough
     */
    fn mul(self:&Self, x:u128,y:u128) -> u128 {
        let x256 = U256::from(x);
        let y256 = U256::from(y);
        let z = x256.checked_mul(y256).unwrap();
        z.checked_rem(U256::from(*self)).unwrap().as_u128()
    }

    /*
     * May be not quick enough.
     * FIXME: The following function needs test for
     * little/big end ?
     */
    fn power(self:&Self, x:u128, y:u128) -> u128 {
        let y256 = U256::from(y);
        let bits = U256::bits(&y256);
        let mut tracks = Vec::new();
        let mut acc = x;
        for bit in 0..bits {
            if y256.bit(bit) {
                tracks.push(acc);
            } else {
                tracks.push(1);
            }
            acc = self.mul(acc,acc);
        }
        acc = 1;
        for bit in 0..bits {
            acc = self.mul(acc, tracks[bit]);
        }
        acc
    }

    fn inverse(self:&Self, x:u128) -> u128 {
        self.power(x, self-1)
    }

    /* FIXME:
     * A quick way to compute (a^k)^(-1) is to
     * compue a^{p-1-k}.
     * However we does not use this trick.
     * TODO:
     * If we want it quicker, decompose v into a^k
     * and apply the above trick if necessary
     */
    fn div(self:&Self, x:u128,y:u128) -> u128 {
        self.mul(x, self.power(y, self-2))
    }

    fn zero(&self) -> u128 {
        0
    }

    fn one(&self) -> u128 {
        1
    }
}



/// tests for this module
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_tests_plus() {
        let p:u128 = 7;
        assert_eq!(p.plus(1,3), 4);
    }
    fn op_tests_minus() {
        let p:u128 = 7;
        assert_eq!(p.minus(1,3), 5);
    }
    #[test]
    fn op_tests_mul() {
        let p:u128 = 7;
        assert_eq!(p.mul(2,3), 6);
        assert_eq!(p.mul(3,3), 2);
        assert_eq!(p.mul(3,6), 4);
    }
    #[test]
    fn op_tests_pow() {
        let p:u128 = 7;
        assert_eq!(p.power(2,3), 1);
        assert_eq!(p.power(3,3), 6);
    }
    #[test]
    fn op_tests_div() {
        let p:u128 = 7;
        assert_eq!(p.div(6,3), 2);
        assert_eq!(p.div(2,3), 3);
        assert_eq!(p.div(4,3), 6);
        assert_eq!(p.div(4,6), 3);
    }
}

