pub use primitive_types::{U256};

use support::{decl_storage, decl_module, decl_event,
    traits::{
        Currency,
    },
    dispatch::{Vec, Result},
};

use sr_primitives::{
    traits::{
        StaticLookup,
    },
};

use system::{
    OnNewAccount,
    ensure_signed,
};

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

type CipherText<T> = (T,T);
type PubKey<T> = T;
type Amount<T> = T; /* γ^b where b is the amount */

mod primegroup;

pub fn zp_mul(x:u128,y:u128,p:u128) -> u128 {
    let x256 = U256::from(x);
    let y256 = U256::from(y);
    let z = x256.checked_mul(y256).unwrap();
    z.checked_rem(U256::from(p)).unwrap().as_u128()
}

/*
 * May be not quick enough.
 * FIXME:
 * The following function needs test for
 * little/big end
 */
pub fn zp_pow(x:u128,y:u128,p:u128) -> u128 {
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
        acc = zp_mul(acc,acc,p);
    }
    acc = 1;
    for bit in 0..bits {
        acc = zp_mul(acc, tracks[bit],p);
    }
    acc
}

/* FIXME:
 * A quick way to compute (a^k)^(-1) is to
 * compue a^{p-1-k}.
 * However we does not use this trick.
 * TODO:
 * If we want it quicker, decompose v into a^k
 * and apply the above trick if necessary
 */
pub fn zp_div(x:u128,y:u128,p:u128) -> u128 {
    zp_mul(x, zp_pow(y, p-2, p), p)
}



/*
 * So far the amount is encoded using base γ
 */
pub trait AmountCipher<T> {
    fn prime() -> T;
    fn base() -> PubKey<T>;
    fn encode_amount(p_recv:PubKey<T>,a:Amount<T>,r:T) -> Self; 
    fn plus_amount(self, p:Self) -> Self;
    fn minus_amount(self, p:Self) -> Self;
    fn decode_amount(self,p_recv:PubKey<T>) -> T; 
}

/* U128 Pair as Amount Entries */
impl AmountCipher<u128> for CipherText<u128> {
    /* FIXME: hard code prime group */
    fn prime() -> u128 {
        return 2377;
    }
    /* FIXME: hard code base */
    fn base() -> u128 {
        1234
    }
    /*
     * Suppose sender sends the amout := a
     * We encod it into (γ^a * p_recv^r, γ^r)
     */
    fn encode_amount(p_recv:PubKey<u128>,a:u128,r:u128) -> CipherText<u128> {
        let gamma = Self::base();
        let p = Self::prime();
        let gamma_exp_amt = zp_pow(gamma, a, p);
        let p_recv_exp_r = zp_pow(p_recv, r, p);
        let gamma_exp_r = zp_pow(gamma, r, p);
        (zp_mul(gamma_exp_amt, p_recv_exp_r, p), gamma_exp_r)
    }
    fn plus_amount(self, v:CipherText<u128>) -> CipherText<u128> {
        let p = Self::prime();
        (zp_mul(self.0, v.0, p), v.1)
    }
    fn minus_amount(self, v:CipherText<u128>) -> CipherText<u128> {
        let p = Self::prime();
        (zp_div(self.0, v.0, p), v.1)
    }
    fn decode_amount(self, k:u128) -> u128{
        1234
    }
}

use codec::{Encode, Decode};

#[derive(Encode, Decode, Default, Clone, PartialEq)]
pub struct TransferHistory {
    pub_key: u128,
    history: CipherText<u128>,
}
pub trait History<B> {
    type Balance;
    fn get_pub_key (&self) -> B;
    fn new (k:B, h:CipherText<B>) -> Self;
    fn increase_balance (self, c:B) -> Self;
    fn decrease_balance (self, c:B) -> Self;
    fn compose_entry (&self, c:B) -> CipherText<B>;
}

/// The module's configuration trait.
pub trait Trait<I: Instance = DefaultInstance>: system::Trait
    {
    /*
    type TransferHistory : History<u128>;
    */
    type TransferHistory;
}

impl History<u128> for TransferHistory {

    type Balance = u128;

    fn compose_entry(&self, a:Self::Balance) -> CipherText<u128> {
        /*
         * Encoded the transfer amout cipher into
         * amout cipher text.
         */
        let p_key = self.get_pub_key();
        /* TODO: change it into a range number */
        let r = 10;
        CipherText::<u128>::encode_amount(p_key, a, r)
    }

    fn new (k:u128, h:CipherText<u128>) -> Self {
        TransferHistory {pub_key:k, history:h}
    }

    fn get_pub_key (&self) -> u128 {
        self.pub_key
    }
    fn increase_balance(self, a:Self::Balance) -> TransferHistory {
        let e = self.compose_entry(a);
        let new_cipher = self.history.plus_amount(e);
        Self::new(self.get_pub_key(), new_cipher)
    }

    fn decrease_balance(self, a:Self::Balance) -> TransferHistory {
        let e = self.compose_entry(a);
        let new_cipher = self.history.minus_amount(e);
        Self::new(self.get_pub_key(), new_cipher)
    }
}
/*
impl<T:Trait<I>, I: Instance> Trait<I> for T {
    type Event = Event<T>;
    type TransferHistory = TransferHistory;
    type OnNewAccount = OnNewAccount<Self::AccountId>;
}
*/

decl_storage! {
    trait Store for Module<T:Trait<I>, I:Instance = DefaultInstance>
    as TokenStorage {
        BalanceProof get(u128): u128;
        BalanceHistory get(balance_history_getter):
            map T::AccountId => TransferHistory;
    }
}



decl_module! {
    pub struct Module<T: Trait<I>, I: Instance = DefaultInstance> for enum Call
    where origin: T::Origin {
        fn transfer(origin,
            amount:u128,
			recv: <T::Lookup as StaticLookup>::Source
        ) -> Result {
            let src = ensure_signed(origin)?;
            let src_history = <BalanceHistory<T,I>>::get(src.clone());
			let dest = T::Lookup::lookup(recv)?;
            let dest_history = <BalanceHistory<T,I>>::get(dest.clone());
            let src_new = src_history.decrease_balance(amount);
            let dest_new = dest_history.increase_balance(amount);
            <BalanceHistory<T,I>>::insert(src, src_new);
            <BalanceHistory<T,I>>::insert(dest, dest_new);
            Ok(())
        }
    }
}

decl_event!(
	pub enum Event<T, I: Instance = DefaultInstance> where
		<T as system::Trait>::AccountId,
		<T as Trait<I>>::TransferHistory
	{
		/// A new account was created.
		NewAccount(AccountId, TransferHistory),
	}
);

