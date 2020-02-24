pub use primitive_types::{U256};

use support::{
    decl_storage, decl_module, decl_event,
    dispatch::{Result},
/*
    traits::{
        Currency,
    },
*/
};

use sr_primitives::{
    traits::{
        StaticLookup,
    },
};


use system::{
    ensure_signed,
    ensure_root,
};

use primegroup::PrimeRing;

mod primegroup;

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

/*
 * So far the amount is encoded using base γ
 */
pub trait AmountCipher<T> {
    fn prime() -> u128;
    fn base() -> PubKey<T>;
    fn encode_amount(p_recv:PubKey<T>,a:Amount<T>,r:T) -> Self;
    fn change_pubkey(self, old:PubKey<T>, new:PubKey<T>) -> Self;
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
     * We encode it into (γ^a * p_recv^r, γ^r)
     */
    fn encode_amount(p_recv:PubKey<u128>,a:u128,r:u128) -> CipherText<u128> {
        let gamma = Self::base();
        let p = Self::prime();
        let gamma_exp_amt = p.power(gamma, a);
        let p_recv_exp_r = p.power(p_recv, r);
        let gamma_exp_r = p.power(gamma, r);
        (p.mul(gamma_exp_amt, p_recv_exp_r), gamma_exp_r)
    }
    fn plus_amount(self, v:CipherText<u128>) -> CipherText<u128> {
        let p = Self::prime();
        (p.mul(self.0, v.0), v.1)
    }
    fn minus_amount(self, v:CipherText<u128>) -> CipherText<u128> {
        let p = Self::prime();
        (p.div(self.0, v.0), v.1)
    }
    /* We should never use this since the private key is private */
    fn decode_amount(self, x:PubKey<u128>) -> u128 {
        let p = Self::prime();
        p.div(self.0, p.power(self.1, x))
    }
    fn change_pubkey(self, old:u128, new:u128) ->CipherText<u128> {
        // cipher_text = γ^b * y^r, γ^r
        let p = Self::prime();
        let gamma = Self::base();
        let delta = p.div(new, old);
        (p.mul(self.0, p.power(delta,gamma)), self.1)
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
    fn set_balance(self, c:B) -> Self;
    fn reset_pubkey(self, c:B) -> Self;
    fn increase_balance (self, c:B) -> Self;
    fn decrease_balance (self, c:B) -> Self;
    fn compose_entry (&self, c:B) -> CipherText<B>;
}

/// The module's configuration trait.
pub trait Trait<I: Instance = DefaultInstance>: system::Trait {
    type Balance;
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

    fn reset_pubkey(self, npub:u128) -> Self {
        let p_key = self.get_pub_key();
        Self::new (npub, self.history.change_pubkey(p_key, npub))
    }

    fn set_balance(self, a:Self::Balance) -> TransferHistory {
        let e = self.compose_entry(a);
        Self::new(self.get_pub_key(), e)
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

/* We need implement Balance trait as follows
 * One
 * Zero
 * CheckedMul
 * CheckedDiv
 * CheckedSquareRoot
 * CheckedAdd
 * CheckedSub
impl<T:Trait<I>, I: Instance> Currency<T::AccountId> for Module<T,I>
where
    T::Balance: History<u128>
{
    type Balance = T::Balance;
    fn total_balance(who: &T::AccountId) -> Self::Balance {
        0
    }
}
*/

impl<T:Trait<I>, I: Instance> Module<T,I> {
	fn initialize_primeset(prime: &u128) {
	}
}

decl_storage! {
    trait Store for Module<T:Trait<I>, I:Instance = DefaultInstance>
    as Token {
        pub Primeset build(|config: &GenesisConfig| {
            config.primeset
        }): u128;

        BalanceHistory get(balance_history_getter):
            map T::AccountId => TransferHistory;
    }
	add_extra_genesis {
		config(primeset): u128;
        build(|config| Module::<T,I>::initialize_primeset(&config.primeset))
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

        fn reset_balance(
            origin,
            amount:u128,
            who: <T::Lookup as StaticLookup>::Source
        ) {
            ensure_root(origin)?;
            let who = T::Lookup::lookup(who)?;
            let who_history = <BalanceHistory<T,I>>::get(who.clone());
            let who_new = who_history.set_balance(amount);
            <BalanceHistory<T,I>>::insert(who, who_new);
        }

        fn reset_pubkey(
            origin,
            key:u128,
        ) {
            let who = ensure_signed(origin)?;
            let who_history = <BalanceHistory<T,I>>::get(who.clone());
            let who_new = who_history.reset_pubkey(key);
            <BalanceHistory<T,I>>::insert(who, who_new);
        }

        fn get_proof(
            origin,
            #[compact] amount:u128,
        ) {
            ensure_root(origin)?;
            Primeset::<I>::put(amount);
        }
    }
}

decl_event!(
	pub enum Event<T, I: Instance = DefaultInstance> where
		<T as system::Trait>::AccountId,
		<T as Trait<I>>::Balance
	{
		/// A new account was created.
		NewAccount(AccountId, Balance),
	}
);

