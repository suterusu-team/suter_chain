pub use primitive_types::U256;

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

decl_storage! {
    trait Store for Module<T:Trait<I>, I:Instance = DefaultInstance>
    as TokenStorage {
        TokenBalance get(balance): u64;
        UserInfo: map T::AccountId => Vec<u128>;
    }
}



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
// γ^b * y^r, γ^r
//


pub trait AmountCipher<T,CipherText,Key> {
    fn base() -> Key;
    fn encodeAmount(k:Key,v:T) -> Self; 
    fn decodeAmount(self,k:Key) -> T; 
    fn toU128(self) -> U256;
}

type PairOf<T> = (T,T);

impl AmountCipher<u128, PairOf<u128>,u128> for (u128, u128) {
    fn base() -> u128{
        1234
    }
    fn encodeAmount(t:u128,v:u128) -> (u128,u128) {
        (v,v)
    }
    fn decodeAmount(v:(u128, u128), k:u128) -> u128{
        v
    }
}

struct TransferHistory(Vec<PairOf<u128>>);

/* Token transfer entry */
pub trait History<T, I: Instance = DefautInstance>: system::Trait {
    type Key;
    type Balance;
    type Cipher;
    fn composeEntry (b:Self::Key, c:Self::Balance) -> Self::Cipher;
    fn getBalance (self) -> Self::Balance;
}

/// The module's configuration trait.
pub trait Trait<I: Instance = DefaultInstance>: system::Trait {
    type Balance;
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;
    type OnNewAccount: OnNewAccount<Self::AccountId>;

}

impl<T> History<T, I> for TransferHistory {
    type Key = T;
    type Balance = T;
    type Cipher = PairOf<T>;
    fn composeEntry(k:Self::Key, c:Self::Balance)
    {
        /*
         * Encoded the transfer amout cipher into
         * the amout cipher list.
         */
        A::encodeAmount(k,c)
        
    }
}

impl<I> Trait<I> for History<T,I> {
    type Balance = T;
    type OnNewAccount = OnNewAccount<Self::AccountId>;
}

decl_module! {
    pub struct Module<T: Trait<I>, I: Instance = DefaultInstance> for enum Call
    where origin: T::Origin {
        fn transfer(origin,
            encoded_amt:u128,
			dest: <T::Lookup as StaticLookup>::Source
        ) -> Result {
            let _ = ensure_signed(origin)?;
            let balance_cipher_context = getBalance();
            /*
             * TODO:
             * Decode the amount and put it into the
             * Cipher Context
            let valid = decode_transfer encoded_amt balance_cipher_context;
			let dest = T::Lookup::lookup(dest)?;
            let target = getTarget
             */
            Ok(())
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

