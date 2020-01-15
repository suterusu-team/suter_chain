use support::{decl_storage, decl_module};
use system::ensure_signed;

//
// Suppose x is the private key and y=g^x is the public
// key.
//
// A transfer amout b is encoded by the sender using
// a group generator γ by γ^b.
//
// For convenience, we set γ = g at the moment.
// Now the encrypted amout of b will looks like the
// following:
//
// γ^b * y^r, γ^r
//

struct AmountCipher((u64, u64));
struct TransferHistory(u64);


/*
 * Token is encoded in a list of AmoutCipher
 */
pub trait Token {
    fn getBalance<T:Trait>(self) -> T::Balance;
}

pub trait BTrait<I: Instance = DefaultInstance>: system::Trait {
	type Balance: Token;
    type OnNewAccount: OnNewAccount<Self::AccountId>;
}

/// The module's configuration trait.
pub trait Trait: system::Trait {
	type Event: From<Event<Self>> + Into<<Self as system::Trait>::Event>;

}

impl<T:Trait<I>, I: DefaultInstance> BTrait<I> for T {
    type Balance = T::Balance;
    type OnNewAccount = T::OnNewAccount;
}

pub trait History<B:BTrait> {
    fn compose_history_entry(self, c:AmountCipher) ->
        B::Balance;
}

impl History for TransferHistory {
    fn compose_history_entry(self, c:AmountCipher)
    {
        /*
         * Encoded the transfer amout cipher into
         * the amout cipher list.
         */
        0
    }
}

decl_storage! {
    trait Store for Module<T:Trait> as TokenStorage {
        TokenBalance get(balance): u32;
        UserInfo: map T::AccountId => u32;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn transfer(origin,
            encoded_amt:{u64, u64},
			dest: <T::Lookup as StaticLookup>::Source
        ) -> Result {
            let _ = ensure_signed(origin)?;
            let balance_cipher_context = getBalance();
            let valid = decode_transfer encoded_amt balance_cipher_context;
			let dest = T::Lookup::lookup(dest)?;
            let target = getTarget
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

