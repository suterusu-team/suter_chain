pub use primitive_types::{U256};

use crate::token::cipher::{
    EGICipher,
    CipherFunctor,
};

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


mod primering;
mod cipher;

use codec::{Encode, Decode};

#[derive(Encode, Decode, Default, Clone, PartialEq)]
struct CipherInfo(u128, u128);

impl CipherInfo {
    fn to_cipher(self) -> EGICipher<u128> {
        EGICipher {gamma:self.0, prime:self.1}
    }
}

pub trait CipherBalance<B>
    where B:Copy {
    type Balance;
    fn make (cipher:&EGICipher<B>, pk:B, b:B, r:B) -> Self;
    fn set(self, cipher:&EGICipher<B>, b:B) -> Self;
    fn lock(self, cipher:&EGICipher<B>, b:B) -> Self;
    fn switch(self, cipher:&EGICipher<B>, npk:u128) -> Self;
    fn increase(self, cipher:&EGICipher<B>, delta:B) -> Self;
    fn decrease(self, cipher:&EGICipher<B>, delta:B) -> Self;
}

/// The module's configuration trait.
pub trait Trait<I: Instance = DefaultInstance>: system::Trait {
    type Balance;
}

#[derive(Encode, Decode, Default, Clone, PartialEq)]
pub struct CipherText<T>{
    pubkey: T,
    rel: T,
    current: (T, T),
    lock: (T, T),
}

impl CipherBalance<u128> for CipherText<u128>{

    type Balance = u128;

    fn make(cipher:&EGICipher<u128>, pk:u128, b:u128, r:u128) -> Self {
        /*
         * Encoded the transfer amout cipher into
         * amout cipher text.
         */
        CipherText {pubkey:pk, rel:r, current:cipher.encode(pk, b, r), lock:cipher.encode(pk, b, r)}
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

    fn lock(self, cipher:&EGICipher<u128>, b:u128) -> Self {
        let e = cipher.encode(self.pubkey, b, self.rel);
        let current = cipher.minus(self.current, e);
        let lock = cipher.plus(self.lock, e);
        CipherText {pubkey:self.pubkey, rel:self.rel, current:current, lock:lock}

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
        pub ProofSetting build(|config: &GenesisConfig| {
            config.primeset
        }): u128;

        pub Rel: u128;

        pub Cipher: CipherInfo;

        BalanceMap get(balance_balance_getter):
            map T::AccountId => CipherText<u128>;
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
            let cipher = Cipher::<I>::get().to_cipher();
            let src = ensure_signed(origin)?;
            let src_balance = <BalanceMap<T,I>>::get(src.clone());
			let dest = T::Lookup::lookup(recv)?;
            let dest_balance = <BalanceMap<T,I>>::get(dest.clone());
            let src_new = src_balance.decrease(&cipher, amount);
            let dest_new = dest_balance.increase(&cipher, amount);
            <BalanceMap<T,I>>::insert(src, src_new);
            <BalanceMap<T,I>>::insert(dest, dest_new);
            Ok(())
        }

        fn lock_balance(
            origin,
            amount:u128,
            proof:[u128;4],
        ) {
            let who = ensure_signed(origin)?;
            let cipher = Cipher::<I>::get().to_cipher();
            let balance = <BalanceMap<T,I>>::get(who.clone());
            let delta = cipher.encode(balance.pubkey, amount, balance.rel);
            let remain_cipher = cipher.minus(balance.current, delta);
            /* TODO: need to port zkrp in ING */
            cipher.check(proof.to_vec(), remain_cipher);
            let who_new = balance.lock(&cipher, amount);
            <BalanceMap<T,I>>::insert(who, who_new);
        }

        fn reset_balance(
            origin,
            amount:u128,
        ) {
            let who = ensure_signed(origin)?;
            let cipher = Cipher::<I>::get().to_cipher();
            let rel = Rel::<I>::get();
            let who_balance = <BalanceMap<T,I>>::get(who.clone());
            let who_new = who_balance.set(&cipher, amount);
            <BalanceMap<T,I>>::insert(who, who_new);
        }

        fn set_pubkey(
            origin,
            key:u128,
        ) {
            let who = ensure_signed(origin)?;
            let cipher = Cipher::<I>::get().to_cipher();
            let who_balance = <BalanceMap<T,I>>::get(who.clone());
            let who_new = who_balance.switch(&cipher, key);
            <BalanceMap<T,I>>::insert(who, who_new);
        }

        fn get_proof_setting(
            origin,
            #[compact] amount:u128,
        ) {
            ensure_root(origin)?;
            ProofSetting::<I>::get();
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

