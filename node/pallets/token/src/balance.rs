use codec::{Encode, Decode};
use crate::cipher::{
    EGICipher,
    CipherFunctor,
};

enum CipherBalanceException {
    ReleaseLockFailure
}

impl core::convert::From<CipherBalanceException> for &str {
    fn from (e:CipherBalanceException) -> &'static str {
        match e {
        CipherBalanceException::ReleaseLockFailure => "ReleaseLockFailure"
        }
    }
}

pub trait CipherBalance<B>
    where B:Copy,
    Self: core::marker::Sized {
    type Balance;
    fn make (cipher:&EGICipher<B>, pk:B, b:B, r:B) -> Self;
    fn set(self, cipher:&EGICipher<B>, b:B) -> Self;
    fn lock(self, cipher:&EGICipher<B>, b:B) -> Self;
    fn release_locked(self, cipher:&EGICipher<B>, b:B) -> Result<Self, &'static str>;
    fn switch(self, cipher:&EGICipher<B>, npk:u128) -> Self;
    fn increase(self, cipher:&EGICipher<B>, delta:B) -> Self;
    fn decrease(self, cipher:&EGICipher<B>, delta:B) -> Self;
}

#[derive(Encode, Decode, Default, Clone, PartialEq)]
pub struct CipherText<T>{
    pub pubkey: T,
    pub rel: T,
    pub current: (T, T),
    pub lock: (T, T),
}

impl CipherBalance<u128> for CipherText<u128>{

    type Balance = u128;

    /**
     * Encoded the transfer amout cipher into CipherBalance.
     * Set the lock to be the cipher of amount zero
     */
    fn make(cipher:&EGICipher<u128>, pk:u128, b:u128, r:u128) -> Self {
        CipherText {pubkey:pk, rel:r, current:cipher.encode(pk, b, r), lock:cipher.encode(pk, 0, r)}
    }


    /**
     * Lock amount of balance from self and increase the current amount.
     * If some amount is already locked then add the locked amount togeter
     */

    fn lock(self, cipher:&EGICipher<u128>, b:u128) -> Self {
        let e = cipher.encode(self.pubkey, b, self.rel);
        let current = cipher.minus(self.current, e);
        let lock = cipher.plus(self.lock, e);
        CipherText {pubkey:self.pubkey, rel:self.rel, current:current, lock:lock}
    }

    /**
     * Amount can be locked several times but needs to be released in total
     * so that we dont have to provide another proof to show the locked amount is larger
     * then the released amount.
     */
    fn release_locked(self, cipher:&EGICipher<u128>, amount:u128) -> Result<CipherText<u128>, &'static str> {
        let t = cipher.encode(self.pubkey, amount, self.rel);
        let lock = cipher.encode(self.pubkey, 0, self.rel);
        if self.lock == t {
            let x = CipherText {
                pubkey:self.pubkey,
                rel:self.rel,
                current:self.current,
                lock:(0,0)
            };
            Ok(x)
        } else {
            Err(CipherBalanceException::ReleaseLockFailure.into())
        }
    }

    fn set(self, cipher:&EGICipher<u128>, b:u128) -> Self {
        let current = cipher.encode(self.pubkey, b, self.rel);
        CipherText {pubkey:self.pubkey, rel:self.rel, current:current, lock:self.lock}
    }

    fn switch(self, cipher:&EGICipher<u128>,npub:u128) -> Self {
        let pk = self.pubkey;
        let current = cipher.switch(self.pubkey, npub, self.current);
        let lock = cipher.switch(self.pubkey, npub, self.lock);
        CipherText {pubkey:npub, rel:self.rel, current:current, lock:lock}
    }

    fn increase(self, cipher:&EGICipher<u128>, delta:u128) -> Self {
        let e = cipher.encode(self.pubkey, delta, self.rel);
        CipherText {pubkey:self.pubkey, rel:self.rel, current: cipher.plus(self.current, e), lock:self.lock}
    }

    fn decrease(self, cipher:&EGICipher<u128>, delta:u128) -> Self {
        let e = cipher.encode(self.pubkey, delta, self.rel);
        CipherText {pubkey:self.pubkey, rel:self.rel, current: cipher.minus(self.current, e), lock:self.lock}
    }
}


