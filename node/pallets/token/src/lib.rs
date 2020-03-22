#![cfg_attr(not(feature = "std"), no_std)]
pub use primitive_types::{U256};
pub mod balance;

/* Make the WASM binary available.
#[cfg(feature = "std")]
include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));
*/

use sp_runtime::{
    DispatchError,
    traits::{
        StaticLookup,
    },
};

use system::{
    ensure_signed,
    ensure_root,
};

use crate::cipher::{
    EGICipher,
    CipherFunctor,
};
use crate::proof::{
    CipherProof,
};

pub use crate::balance::{
    CipherText,
    CipherBalance,
};

use frame_support::{
    decl_storage, decl_module, decl_event, dispatch
};

use codec::{Encode, Decode};

mod primering;
mod cipher;
mod proof;


/// The module's configuration trait.
pub trait Trait<I: Instance = DefaultInstance>: system::Trait {
    type Balance;
    type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
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
	fn initialize_token() {
	}
}

decl_storage! {
    trait Store for Module<T:Trait<I>, I:Instance = DefaultInstance>
    as Token {
        pub Cipher build(|config: &GenesisConfig| {
            EGICipher {gamma:config.gamma, prime:config.primeset}
        }): EGICipher<u128>;

        pub Rel build(|config: &GenesisConfig| {
            config.rel
        }): u32;

        BalanceMap get(balance_balance_getter):
            map hasher(opaque_blake2_256) T::AccountId => CipherText<u128>;
    }
	add_extra_genesis {
		config(primeset): u128;
		config(gamma): u128;
		config(rel): u32;
        build(|config| Module::<T,I>::initialize_token())
	}

}

decl_module! {
    pub struct Module<T: Trait<I>, I: Instance = DefaultInstance> for enum Call
    where origin: T::Origin {

        fn deposit_event() = default;

        /**
         * Standard transfer function, release the locked amount
         * and transfer it into the recv's accout.
         */
        fn transfer(origin,
            amount:u128,
			recv: <T::Lookup as StaticLookup>::Source
        ) -> dispatch::DispatchResult {
            let src = ensure_signed(origin)?;

            let cipher = Cipher::<I>::get();
            return Err(DispatchError::Other("WTF ??"));

            if !<BalanceMap<T,I>>::contains_key(src.clone()) {
                Err(DispatchError::Other("Soruce account is not established"))
            } else {
                let src_balance = <BalanceMap<T,I>>::get(src.clone());
    			let dest = T::Lookup::lookup(recv)?;

                /*
                 * Set the new balance for dest
                 * Create an account if dest account does not exist.
                 */
                if !<BalanceMap<T,I>>::contains_key(dest.clone()) {
                    Err(DispatchError::Other("Target account is not established"))
                } else {
                    let src_new = src_balance.release_locked(&cipher, amount)?;
                    let dest_balance = <BalanceMap<T,I>>::get(dest.clone());
                    let dest_new = dest_balance.increase(&cipher, amount);

                    // once we reach this spot, no chance to raise exception
                    <BalanceMap<T,I>>::insert(src, src_new);
                    <BalanceMap<T,I>>::insert(dest, dest_new);
                    Ok(())
                }
            }
        }

        /**
         * To prevent frequent accound creating attack,
         * we require a limit amount of balance is transfered into the new account.
         * The suter client might receive an error code from transfer of non-existence
         * account. In such case, please use the create account api and provide a
         * public key and relative r.
        fn create_account(origin,
            amount:u128,
            pubkey:u128,
            r:u128,
			recv: <T::Lookup as StaticLookup>::Source
        ) -> dispatch::DispatchResult {
            let cipher = Cipher::<I>::get();
            let src = ensure_signed(origin)?;
            let src_balance = <BalanceMap<T,I>>::get(src.clone());
			let dest = T::Lookup::lookup(recv)?;


            /*
             * Set the new balance for dest
             * Create an account if dest account does not exist.
             */
            let dest_new = if <BalanceMap<T,I>>::exists(dest) {
                Err(())
            } else {
                Self::new_account(dest, amount);
                let dest_balance = <BalanceMap<T,I>>::get(dest.clone());
                let dest_new = dest_balance.increase(&cipher, amount);
                let src_new = src_balance.release_locked(&cipher, amount)?;

                // once we reach this spot, no chance to raise exception
                <BalanceMap<T,I>>::insert(src, src_new);
                <BalanceMap<T,I>>::insert(dest, dest_new);
                Ok(())
            }
        }
         */

        /**
         * Before transfer, we need to lock enough balanced in
         * our account so that all the transfer transaction from
         * a particular account is well ordered
         */
        fn lock_balance(
            origin,
            amount:u128,
            s:u128,
            proof:[(u128,u128);4],
        ) {
            let who = ensure_signed(origin)?;
            let cipher = Cipher::<I>::get();
            let balance = <BalanceMap<T,I>>::get(who.clone());
            let delta = cipher.mk_cipher(balance.pubkey, amount, balance.rel);
            let remain_cipher = cipher.minus(balance.current, delta);

            /* TODO: need to port zkrp in ING
             * Currently we assume the highest bit of one is less
             * then 64, thus x < 2^64 - 1
             */
            cipher.within_exp(s, s, remain_cipher, proof.to_vec());
            let who_new = balance.lock(&cipher, amount);
            <BalanceMap<T,I>>::insert(who, who_new);
        }

        fn reset_balance(
            origin,
            amount:u128,
        ) {
            let who = ensure_signed(origin)?;
            let cipher = Cipher::<I>::get();
            let who_balance = <BalanceMap<T,I>>::get(who.clone());
            let who_new = who_balance.set(&cipher, amount);
            <BalanceMap<T,I>>::insert(who, who_new);
        }

        fn set_pubkey(
            origin,
            key:u128,
        ) {
            let who = ensure_signed(origin)?;
            let cipher = Cipher::<I>::get();
            let who_balance = <BalanceMap<T,I>>::get(who.clone());
            let who_new = who_balance.switch(&cipher, key);
            <BalanceMap<T,I>>::insert(who, who_new);
        }

        fn TestStorage(
            origin,
            amount:u32,
        ) {
            let who = ensure_signed(origin)?;
            <Rel::<I>>::put(amount);
            Self::deposit_event(RawEvent::TokenEvent(who));
        }
    }
}

decl_event!(
	pub enum Event<T> where
		<T as system::Trait>::AccountId,
	{
		TokenEvent(AccountId),
	}
);
