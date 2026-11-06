//! PumpSwap pools as the program lays them out, and the swaps that trade
//! their token for SOL either way round.
//!
//! A pool has WSOL on one side and the token on the other, and which side is
//! which depends on who made it:
//!
//! - **Graduations.** When a pump.fun bonding curve completes, pump.fun's
//!   program migrates the token to PumpSwap: its `migrate` instruction calls
//!   `create_pool` with the token as the base and WSOL as the quote, and the
//!   original deployer as the pool's coin creator. The token is usually a
//!   Token-2022 mint.
//! - **Pools made by hand.** Anyone can call `create_pool` directly. Those
//!   seen trading are mostly WSOL as the base and the token as the quote,
//!   and many are opened to draw bots in and pulled seconds later.
//!
//! The pool account, in order: discriminator, `pool_bump` u8, `index` u16,
//! `creator`, `base_mint`, `quote_mint`, `lp_mint`, the base and quote
//! vaults, `lp_supply` u64, `coin_creator`, `is_mayhem_mode` bool, then a
//! second flag and more. (`coin_creator` comes before `is_mayhem_mode`, as on
//! mainnet; the ultima crate has them the other way round, which fails on
//! every pool with a coin creator.)

use solana_instruction::{AccountMeta, Instruction};
use solana_sdk::pubkey::Pubkey;
use ultima_swap_pumpfun::{self as pumpswap, Pool, SwapError};

/// The pump.fun bonding-curve program, which migrates graduated tokens.
pub const PUMP_PROGRAM: Pubkey = Pubkey::from_str_const("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P");
/// Anchor discriminator for the Pool account: sha256("account:Pool")[..8].
pub const POOL_DISCRIMINATOR: [u8; 8] = [241, 154, 109, 4, 17, 177, 109, 188];

const KEY: usize = 32;
/// Where `coin_creator` starts: after the discriminator, bump, index, six
/// keys and `lp_supply`.
const COIN_CREATOR_AT: usize = 8 + 1 + 2 + 6 * KEY + 8;

/// Which side of a pool is SOL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum Side {
    /// WSOL is the base and the token the quote: pools made by hand.
    #[default]
    SolBase,
    /// The token is the base and WSOL the quote: graduations.
    SolQuote,
}

impl Side {
    /// The side of a pool between WSOL and some token; none for any other.
    pub fn of(pool: &Pool) -> Option<Self> {
        match (pool.base_mint == pumpswap::WSOL_MINT, pool.quote_mint == pumpswap::WSOL_MINT) {
            (true, false) => Some(Self::SolBase),
            (false, true) => Some(Self::SolQuote),
            _ => None,
        }
    }

    /// The token of a pool on this side.
    pub fn token_mint(self, pool: &Pool) -> Pubkey {
        match self {
            Self::SolBase => pool.quote_mint,
            Self::SolQuote => pool.base_mint,
        }
    }

    /// The pool's SOL vault and token vault, in that order.
    pub fn vaults(self, pool: &Pool) -> (Pubkey, Pubkey) {
        match self {
            Self::SolBase => (pool.pool_base_token_account, pool.pool_quote_token_account),
            Self::SolQuote => (pool.pool_quote_token_account, pool.pool_base_token_account),
        }
    }

    /// The pool's (SOL, token) reserves from its (base, quote) reserves.
    pub fn sol_and_token(self, base: u64, quote: u64) -> (u64, u64) {
        match self {
            Self::SolBase => (base, quote),
            Self::SolQuote => (quote, base),
        }
    }

    /// Tokens bought with `sol_in`, before slippage.
    pub fn tokens_for_sol(self, sol_reserves: u64, token_reserves: u64, sol_in: u64) -> Result<u64, SwapError> {
        // The same constant product with the fee on the input, whichever
        // side each is on: only the names differ.
        pumpswap::quote_out_for_exact_base_in(sol_reserves, token_reserves, sol_in, pumpswap::DEFAULT_FEE_BPS)
    }

    /// Lamports `tokens_in` sell for, before slippage.
    pub fn sol_for_tokens(self, sol_reserves: u64, token_reserves: u64, tokens_in: u64) -> Result<u64, SwapError> {
        pumpswap::base_out_for_exact_quote_in(sol_reserves, token_reserves, tokens_in, pumpswap::DEFAULT_FEE_BPS)
    }
}

/// Reads a pool account. Lenient on what follows the fields read here, which
/// the program has grown before.
pub fn decode_pool(data: &[u8]) -> Result<Pool, std::io::Error> {
    let bad = |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_owned());
    if data.len() < COIN_CREATOR_AT + KEY + 1 {
        return Err(bad("pool account too short"));
    }
    if data[..8] != POOL_DISCRIMINATOR {
        return Err(bad("not a pool account"));
    }
    let key = |at: usize| Pubkey::new_from_array(data[at..at + KEY].try_into().expect("32 bytes"));
    let keys_at = 8 + 1 + 2;
    Ok(Pool {
        pool_bump: data[8],
        index: u16::from_le_bytes([data[9], data[10]]),
        creator: key(keys_at),
        base_mint: key(keys_at + KEY),
        quote_mint: key(keys_at + 2 * KEY),
        lp_mint: key(keys_at + 3 * KEY),
        pool_base_token_account: key(keys_at + 4 * KEY),
        pool_quote_token_account: key(keys_at + 5 * KEY),
        lp_supply: u64::from_le_bytes(data[keys_at + 6 * KEY..COIN_CREATOR_AT].try_into().expect("8 bytes")),
        coin_creator: key(COIN_CREATOR_AT),
        is_mayhem_mode: data[COIN_CREATOR_AT + KEY] != 0,
    })
}

/// Why a pool is not traded here, if it is not: mayhem pools pay other fee
/// recipients, and the flag after `is_mayhem_mode` is one these swaps are
/// not built for when set.
pub fn not_tradable(pool: &Pool, raw: Option<&[u8]>) -> Option<&'static str> {
    if pool.is_mayhem_mode {
        return Some("a mayhem-mode pool");
    }
    if raw.and_then(|d| d.get(COIN_CREATOR_AT + KEY + 1)).is_some_and(|f| *f != 0) {
        return Some("a pool flag these swaps are not built for");
    }
    None
}

/// A pool seen created, with everything a buy needs read from the
/// `create_pool` instruction itself: nothing has to be fetched first.
#[derive(Debug, Clone)]
pub struct NewPool {
    pub pool: Pubkey,
    /// The pool as the program will store it.
    pub data: Pool,
    pub base_token_program: Pubkey,
    pub quote_token_program: Pubkey,
    /// What the creator put in, which is the opening reserves.
    pub base_reserves: u64,
    pub quote_reserves: u64,
    /// Made by pump.fun's migration, not by hand.
    pub graduated: bool,
    /// The flag after `is_mayhem_mode` in the instruction.
    pub flagged: bool,
}

impl NewPool {
    pub fn side(&self) -> Option<Side> {
        Side::of(&self.data)
    }

    /// The token's mint and program.
    pub fn token(&self) -> Option<(Pubkey, Pubkey)> {
        Some(match self.side()? {
            Side::SolBase => (self.data.quote_mint, self.quote_token_program),
            Side::SolQuote => (self.data.base_mint, self.base_token_program),
        })
    }

    /// The opening (SOL, token) reserves.
    pub fn sol_and_token(&self) -> Option<(u64, u64)> {
        Some(self.side()?.sol_and_token(self.base_reserves, self.quote_reserves))
    }

    /// Who to blame for the pool: the deployer of a graduated token, the
    /// signer that made a pool by hand.
    pub fn creator(&self) -> Pubkey {
        if self.graduated {
            self.data.coin_creator
        } else {
            self.data.creator
        }
    }

    /// Why it is not traded, if it is not.
    pub fn not_tradable(&self) -> Option<&'static str> {
        if self.side().is_none() {
            return Some("not a WSOL/token pool");
        }
        if self.flagged {
            return Some("a pool flag these swaps are not built for");
        }
        not_tradable(&self.data, None)
    }
}

/// Reads a `create_pool` instruction, by its accounts as the program takes
/// them (checked against mainnet on 2026-11-03):
///
/// ```text
/// 0 pool  1 global_config  2 creator  3 base_mint  4 quote_mint  5 lp_mint
/// 6-8 the creator's base, quote and LP token accounts
/// 9 pool base vault  10 pool quote vault  11 system  12 Token-2022
/// 13 base token program  14 quote token program  15 ATA program
/// 16 event authority  17 program
/// ```
///
/// and its arguments: `index` u16, `base_amount_in` u64, `quote_amount_in`
/// u64, `coin_creator`, `is_mayhem_mode` bool, then a second flag.
/// `called_by` is the program of the top-level instruction it runs under:
/// pump.fun's for a graduation, PumpSwap's own when called directly.
///
/// The coin creator is stored as given only for a graduation; a pool made by
/// hand stores none, whatever the argument says (seen on mainnet).
pub fn parse_create_pool(data: &[u8], accounts: &[Pubkey], called_by: Pubkey) -> Option<NewPool> {
    if data.len() < 8 + 2 + 8 + 8 + KEY + 1 || data[..8] != pumpswap::CREATE_POOL_DISCRIMINATOR {
        return None;
    }
    if accounts.len() < 15 || accounts[1] != pumpswap::GLOBAL_CONFIG {
        return None;
    }
    let args = &data[8..];
    let index = u16::from_le_bytes([args[0], args[1]]);
    let base_reserves = u64::from_le_bytes(args[2..10].try_into().ok()?);
    let quote_reserves = u64::from_le_bytes(args[10..18].try_into().ok()?);
    let coin_creator = Pubkey::new_from_array(args[18..18 + KEY].try_into().ok()?);
    let is_mayhem_mode = args[18 + KEY] != 0;
    let flagged = args.get(18 + KEY + 1).is_some_and(|f| *f != 0);
    let graduated = called_by == PUMP_PROGRAM;
    Some(NewPool {
        pool: accounts[0],
        data: Pool {
            pool_bump: 0,
            index,
            creator: accounts[2],
            base_mint: accounts[3],
            quote_mint: accounts[4],
            lp_mint: accounts[5],
            pool_base_token_account: accounts[9],
            pool_quote_token_account: accounts[10],
            lp_supply: 0,
            is_mayhem_mode,
            coin_creator: if graduated { coin_creator } else { Pubkey::default() },
        },
        base_token_program: accounts[13],
        quote_token_program: accounts[14],
        base_reserves,
        quote_reserves,
        graduated,
        flagged,
    })
}

/// A pool to trade: its address, its data, and the token programs of its
/// two mints.
#[derive(Debug, Clone)]
pub struct Market {
    pub pool: Pubkey,
    pub data: Pool,
    pub side: Side,
    /// The token's program: Token or Token-2022. WSOL's is always Token.
    pub token_program: Pubkey,
}

impl Market {
    fn programs(&self) -> (Pubkey, Pubkey) {
        match self.side {
            Side::SolBase => (pumpswap::TOKEN_PROGRAM, self.token_program),
            Side::SolQuote => (self.token_program, pumpswap::TOKEN_PROGRAM),
        }
    }

    /// Buys at least `min_tokens` for at most `max_sol` lamports. The swap
    /// takes its SOL from the user's WSOL account, which has to hold
    /// `max_sol` when it runs.
    pub fn buy_ix(&self, user: Pubkey, max_sol: u64, min_tokens: u64, fee_index: usize) -> Result<Instruction, SwapError> {
        match self.side {
            // PumpSwap's sell: exactly `max_sol` of WSOL in.
            Side::SolBase => self.swap(Swap::Sell { base_in: max_sol, min_quote_out: min_tokens }, user, fee_index),
            // PumpSwap's buy: exactly `min_tokens` out, at most `max_sol` in.
            Side::SolQuote => self.swap(Swap::Buy { base_out: min_tokens, max_quote_in: max_sol }, user, fee_index),
        }
    }

    /// Sells exactly `tokens` for at least `min_sol` lamports, into the
    /// user's WSOL account.
    pub fn sell_ix(&self, user: Pubkey, tokens: u64, min_sol: u64, fee_index: usize) -> Result<Instruction, SwapError> {
        match self.side {
            // PumpSwap's buy: exactly `min_sol` of WSOL out, at most `tokens` in.
            Side::SolBase => self.swap(Swap::Buy { base_out: min_sol, max_quote_in: tokens }, user, fee_index),
            Side::SolQuote => self.swap(Swap::Sell { base_in: tokens, min_quote_out: min_sol }, user, fee_index),
        }
    }

    /// A PumpSwap `buy` or `sell`, in the account order of the program's
    /// IDL, then the remaining accounts it reads by position: the `pool-v2`
    /// PDA when the pool has a coin creator, then a buyback fee recipient
    /// and its token account for the quote mint.
    fn swap(&self, swap: Swap, user: Pubkey, fee_index: usize) -> Result<Instruction, SwapError> {
        let p = &self.data;
        let (base_program, quote_program) = self.programs();
        let fee_recipient = *pumpswap::PROTOCOL_FEE_RECIPIENTS.get(fee_index).ok_or(SwapError::MathOverflow)?;
        let buyback_recipient = *pumpswap::BUYBACK_FEE_RECIPIENTS.get(fee_index).ok_or(SwapError::MathOverflow)?;
        let (event_authority, _) = pumpswap::derive_event_authority();
        let program = pumpswap::PUMP_AMM_PROGRAM_ID;
        let pda = |seeds: &[&[u8]], owner: &Pubkey| Pubkey::find_program_address(seeds, owner).0;
        let creator_vault = pda(&[b"creator_vault", p.coin_creator.as_ref()], &program);
        let fee_config = pda(&[b"fee_config", program.as_ref()], &pumpswap::FEE_PROGRAM);

        let mut accounts = vec![
            AccountMeta::new(self.pool, false),
            AccountMeta::new(user, true),
            AccountMeta::new_readonly(pumpswap::GLOBAL_CONFIG, false),
            AccountMeta::new_readonly(p.base_mint, false),
            AccountMeta::new_readonly(p.quote_mint, false),
            AccountMeta::new(ata(&user, &p.base_mint, &base_program), false),
            AccountMeta::new(ata(&user, &p.quote_mint, &quote_program), false),
            AccountMeta::new(p.pool_base_token_account, false),
            AccountMeta::new(p.pool_quote_token_account, false),
            AccountMeta::new(fee_recipient, false),
            AccountMeta::new(ata(&fee_recipient, &p.quote_mint, &quote_program), false),
            AccountMeta::new_readonly(base_program, false),
            AccountMeta::new_readonly(quote_program, false),
            AccountMeta::new_readonly(pumpswap::SYSTEM_PROGRAM, false),
            AccountMeta::new_readonly(pumpswap::ASSOCIATED_TOKEN_PROGRAM, false),
            AccountMeta::new_readonly(event_authority, false),
            AccountMeta::new_readonly(program, false),
            AccountMeta::new(ata(&creator_vault, &p.quote_mint, &quote_program), false),
            AccountMeta::new_readonly(creator_vault, false),
        ];
        let mut data = Vec::with_capacity(25);
        match swap {
            Swap::Buy { base_out, max_quote_in } => {
                accounts.push(AccountMeta::new_readonly(pda(&[b"global_volume_accumulator"], &program), false));
                accounts.push(AccountMeta::new(pda(&[b"user_volume_accumulator", user.as_ref()], &program), false));
                data.extend_from_slice(&pumpswap::BUY_DISCRIMINATOR);
                data.extend_from_slice(&base_out.to_le_bytes());
                data.extend_from_slice(&max_quote_in.to_le_bytes());
                data.push(0); // track_volume: none
            }
            Swap::Sell { base_in, min_quote_out } => {
                data.extend_from_slice(&pumpswap::SELL_DISCRIMINATOR);
                data.extend_from_slice(&base_in.to_le_bytes());
                data.extend_from_slice(&min_quote_out.to_le_bytes());
            }
        }
        accounts.push(AccountMeta::new_readonly(fee_config, false));
        accounts.push(AccountMeta::new_readonly(pumpswap::FEE_PROGRAM, false));
        if p.coin_creator != Pubkey::default() {
            accounts.push(AccountMeta::new_readonly(pumpswap::derive_pool_v2(&p.base_mint).0, false));
        }
        accounts.push(AccountMeta::new_readonly(buyback_recipient, false));
        accounts.push(AccountMeta::new(ata(&buyback_recipient, &p.quote_mint, &quote_program), false));
        Ok(Instruction { program_id: program, accounts, data })
    }
}

enum Swap {
    Buy { base_out: u64, max_quote_in: u64 },
    Sell { base_in: u64, min_quote_out: u64 },
}

/// The associated token account of `wallet` for `mint` under `program`.
pub fn ata(wallet: &Pubkey, mint: &Pubkey, program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(
        &[wallet.as_ref(), program.as_ref(), mint.as_ref()],
        &pumpswap::ASSOCIATED_TOKEN_PROGRAM,
    )
    .0
}

/// The user's WSOL account, which every swap pays from or into.
pub fn wsol_account(user: &Pubkey) -> Pubkey {
    ata(user, &pumpswap::WSOL_MINT, &pumpswap::TOKEN_PROGRAM)
}

/// Puts `lamports` of SOL into the user's WSOL account, making the account
/// when there is none: a buy takes its SOL from there. Three instructions,
/// for the account, the transfer and the sync of its balance.
pub fn wrap_sol(user: &Pubkey, lamports: u64) -> [Instruction; 3] {
    let wsol = wsol_account(user);
    // System program instruction 2, Transfer: the index as u32, then the lamports.
    let mut transfer = vec![2, 0, 0, 0];
    transfer.extend_from_slice(&lamports.to_le_bytes());
    [
        pumpswap::create_ata_if_needed(user, &pumpswap::WSOL_MINT, &pumpswap::TOKEN_PROGRAM),
        Instruction {
            program_id: pumpswap::SYSTEM_PROGRAM,
            accounts: vec![AccountMeta::new(*user, true), AccountMeta::new(wsol, false)],
            data: transfer,
        },
        // Token instruction 17, SyncNative: the account's balance as its SOL.
        Instruction { program_id: pumpswap::TOKEN_PROGRAM, accounts: vec![AccountMeta::new(wsol, false)], data: vec![17] },
    ]
}

/// Closes the user's WSOL account: its SOL and its rent come back.
pub fn unwrap_sol(user: &Pubkey) -> Instruction {
    close_account(user, &pumpswap::WSOL_MINT, &pumpswap::TOKEN_PROGRAM)
}

/// Burns `amount` of `mint` from the user's token account under `program`
/// (Token instruction 8, Burn).
pub fn burn(user: &Pubkey, mint: &Pubkey, program: &Pubkey, amount: u64) -> Instruction {
    let mut data = vec![8];
    data.extend_from_slice(&amount.to_le_bytes());
    Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(ata(user, mint, program), false),
            AccountMeta::new(*mint, false),
            AccountMeta::new_readonly(*user, true),
        ],
        data,
    }
}

/// Closes the user's token account for `mint` under `program`, its rent
/// going back to the user (Token instruction 9, CloseAccount).
pub fn close_account(user: &Pubkey, mint: &Pubkey, program: &Pubkey) -> Instruction {
    Instruction {
        program_id: *program,
        accounts: vec![
            AccountMeta::new(ata(user, mint, program), false),
            AccountMeta::new(*user, false),
            AccountMeta::new_readonly(*user, true),
        ],
        data: vec![9],
    }
}

/// pump.fun's `migrate_v2`: sha256("global:migrate_v2")[..8].
pub const MIGRATE_V2_DISCRIMINATOR: [u8; 8] = [187, 203, 18, 31, 206, 237, 254, 41];
/// pump.fun's Global account, which holds the migration fee.
pub const PUMP_GLOBAL: Pubkey = Pubkey::from_str_const("4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf");
/// Where the Global account keeps `pool_migration_fee`, in lamports.
const MIGRATION_FEE_AT: usize = 146;

/// An account as it was read from the chain: the program that owns it and
/// its data. Who owns an account is what says its data can be believed.
#[derive(Debug, Clone, Copy)]
pub struct Read<'a> {
    pub owner: &'a Pubkey,
    pub data: &'a [u8],
}

/// A pump.fun migration seen before it has run (in the Shreds stream),
/// by its accounts as `migrate_v2` takes them (checked against mainnet on
/// 2026-11-03; the instruction has 29):
///
/// ```text
/// 0 Global  2 mint  3 WSOL  4 bonding curve  5 its token account
/// 9 PumpSwap  10 pool  11 pool creator  14 PumpSwap global config
/// 15 LP mint  17 pool base vault  18 pool quote vault
/// 19 base token program  20 quote token program
/// ```
///
/// A transaction in the Shreds stream has not run, and anyone can put a
/// `migrate_v2` with accounts of their choosing into a block: it fails,
/// and is in the stream all the same. So nothing here is taken on the
/// instruction's word. Every account that decides what is bought is the
/// one address the mint gives it (`parse`), and the two accounts read
/// before the buy are owned by the programs that write them (`new_pool`).
/// A bonding curve at the mint's own address, owned by pump.fun's program,
/// is what says pump.fun made the mint: only that program can make an
/// account there, and it makes it as it mints the token.
///
/// What the pool will open with is not in the instruction: the token
/// account's balance becomes the base, and the curve's SOL less the
/// migration fee the quote.
#[derive(Debug, Clone)]
pub struct Migration {
    accounts: Vec<Pubkey>,
}

/// The one address `program` can sign for under `seeds`.
fn pda(seeds: &[&[u8]], program: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(seeds, program).0
}

/// The index of the pool a migration makes: pump.fun's own, the first.
const CANONICAL_POOL_INDEX: u16 = 0;

impl Migration {
    /// `None` for anything that is not a `migrate_v2` laid out as above
    /// with every account the mint's own: such a transaction is left to
    /// Geyser, which shows the pool only if it was really made.
    pub fn parse(data: &[u8], accounts: &[Pubkey]) -> Option<Self> {
        if data.len() < 8 || data[..8] != MIGRATE_V2_DISCRIMINATOR || accounts.len() != 29 {
            return None;
        }
        let a = accounts;
        let laid_out = a[0] == PUMP_GLOBAL
            && a[3] == pumpswap::WSOL_MINT
            && a[9] == pumpswap::PUMP_AMM_PROGRAM_ID
            && a[14] == pumpswap::GLOBAL_CONFIG;
        if !laid_out {
            return None;
        }
        let (mint, wsol, token_program) = (a[2], pumpswap::WSOL_MINT, a[19]);
        if token_program != pumpswap::TOKEN_PROGRAM && token_program != pumpswap::TOKEN_2022_PROGRAM {
            return None;
        }
        let curve = pda(&[b"bonding-curve", mint.as_ref()], &PUMP_PROGRAM);
        let authority = pda(&[b"pool-authority", mint.as_ref()], &PUMP_PROGRAM);
        let pool = pda(
            &[b"pool", &CANONICAL_POOL_INDEX.to_le_bytes(), authority.as_ref(), mint.as_ref(), wsol.as_ref()],
            &pumpswap::PUMP_AMM_PROGRAM_ID,
        );
        let the_mints_own = a[4] == curve
            && a[5] == ata(&curve, &mint, &token_program)
            && a[10] == pool
            && a[11] == authority
            && a[15] == pda(&[b"pool_lp_mint", pool.as_ref()], &pumpswap::PUMP_AMM_PROGRAM_ID)
            && a[17] == ata(&pool, &mint, &token_program)
            && a[18] == ata(&pool, &wsol, &pumpswap::TOKEN_PROGRAM)
            && a[20] == pumpswap::TOKEN_PROGRAM;
        the_mints_own.then(|| Self { accounts: accounts.to_vec() })
    }

    pub fn pool(&self) -> Pubkey {
        self.accounts[10]
    }

    /// The accounts to read, in the order `new_pool` takes them: the
    /// bonding curve, its token account, pump.fun's Global.
    pub fn to_read(&self) -> [Pubkey; 3] {
        [self.accounts[4], self.accounts[5], PUMP_GLOBAL]
    }

    /// The pool it will create, from the accounts `to_read` names as they
    /// are before it runs. Each is believed only from the program that
    /// writes it: the curve and Global from pump.fun's, the token account
    /// from the mint's token program, holding that mint for the curve.
    pub fn new_pool(&self, bonding_curve: Read, token_account: Read, global: Read) -> Result<NewPool, &'static str> {
        let a = &self.accounts;
        if *bonding_curve.owner != PUMP_PROGRAM {
            return Err("the bonding curve is not pump.fun's");
        }
        if *global.owner != PUMP_PROGRAM {
            return Err("pump.fun's Global is not pump.fun's");
        }
        // A token account opens with its mint, then its owner.
        let holds = |at: usize, key: &Pubkey| token_account.data.get(at..at + KEY) == Some(key.as_ref());
        if *token_account.owner != a[19] || !holds(0, &a[2]) || !holds(KEY, &a[4]) {
            return Err("the curve's token account is not the curve's");
        }
        let (bonding_curve, token_account, global) = (bonding_curve.data, token_account.data, global.data);
        let u64_at = |d: &[u8], at: usize| d.get(at..at + 8).map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")));
        // discriminator, four reserves, supply, complete, creator, two flags
        if bonding_curve.len() < 83 {
            return Err("the bonding curve could not be read");
        }
        if bonding_curve[48] == 0 {
            return Err("the bonding curve is not complete");
        }
        let real_sol = u64_at(bonding_curve, 32).expect("checked");
        let tokens = u64_at(token_account, 64).ok_or("the curve's token account could not be read")?;
        let fee = u64_at(global, MIGRATION_FEE_AT).ok_or("pump.fun's Global could not be read")?;
        let sol = real_sol.checked_sub(fee).filter(|s| *s > 0).ok_or("already migrated")?;
        if tokens == 0 {
            return Err("already migrated");
        }
        Ok(NewPool {
            pool: a[10],
            data: Pool {
                pool_bump: 0,
                index: CANONICAL_POOL_INDEX,
                creator: a[11],
                base_mint: a[2],
                quote_mint: a[3],
                lp_mint: a[15],
                pool_base_token_account: a[17],
                pool_quote_token_account: a[18],
                lp_supply: 0,
                coin_creator: Pubkey::new_from_array(bonding_curve[49..81].try_into().expect("32 bytes")),
                is_mayhem_mode: bonding_curve[81] != 0,
            },
            base_token_program: a[19],
            quote_token_program: a[20],
            base_reserves: tokens,
            quote_reserves: sol,
            graduated: true,
            flagged: bonding_curve[82] != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(s: &str) -> Pubkey {
        s.parse().unwrap()
    }

    /// The `create_pool` pump.fun's `migrate_v2` called in slot 464874772:
    /// index 0, 206.9M tokens and 84.99 SOL in.
    fn graduation() -> NewPool {
        let mut data = pumpswap::CREATE_POOL_DISCRIMINATOR.to_vec();
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&206_900_000_000_000u64.to_le_bytes());
        data.extend_from_slice(&84_990_359_056u64.to_le_bytes());
        data.extend_from_slice(k("C8oBfdKGaaNeNVqzmL2awkrTWxdjGd6Ho7qssqSCS1Yx").as_ref());
        data.extend_from_slice(&[0; 12]);
        let accounts: Vec<Pubkey> = [
            "F6KbJYYxzdT27XZD3mznj9PCqUG5kojHQFZzQFE13rPp",
            "ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw",
            "3rmiDHgHJJjusvK7SoZrg1kFmuRY8eZtKAtnRessqYx5",
            "8V16miNE7UHGUGD4cWP9MX8SNSJK1fhaxqTasHCJpump",
            "So11111111111111111111111111111111111111112",
            "GxXDTiGZjqTw7xK4jJfQFiTBXkeyvFQ3jpp83PLBmVAi",
            "RvKZ3wSvFgvDBv97cGPgkVhyFPJeDrpBhyKtzdESx5y",
            "Deu985QqBpfUuSjwMoV2cHRgwdrDHDyegsajBVYwruk",
            "2B8awmPxSALJGRBWiU4T1tPWWkZY6GgdH8qX8ATayr34",
            "EmZZ5bNaJ9qLG5MoneCuG1b5kEaj15dXscTRRLpWibC",
            "4pAzP13YwoV4zNZEyHfa8GwGphVJPjcdxzCnLgXCphVV",
            "11111111111111111111111111111111",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            "GS4CU59F31iL7aR2Q8zVS8DRrcRnXX1yjQ66TqNVQnaR",
            "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
        ]
        .iter()
        .map(|s| k(s))
        .collect();
        parse_create_pool(&data, &accounts, PUMP_PROGRAM).unwrap()
    }

    #[test]
    fn a_graduation_is_read_from_its_create_pool() {
        let p = graduation();
        assert!(p.graduated);
        assert_eq!(p.side(), Some(Side::SolQuote));
        assert_eq!(p.sol_and_token(), Some((84_990_359_056, 206_900_000_000_000)));
        assert_eq!(p.token(), Some((k("8V16miNE7UHGUGD4cWP9MX8SNSJK1fhaxqTasHCJpump"), pumpswap::TOKEN_2022_PROGRAM)));
        // The deployer is to blame, not pump.fun's per-mint authority.
        assert_eq!(p.creator(), k("C8oBfdKGaaNeNVqzmL2awkrTWxdjGd6Ho7qssqSCS1Yx"));
        assert_eq!(p.not_tradable(), None);
    }

    #[test]
    fn a_pool_made_by_hand_blames_its_signer_and_stores_no_coin_creator() {
        let data = {
            let mut d = pumpswap::CREATE_POOL_DISCRIMINATOR.to_vec();
            d.extend_from_slice(&[0; 2 + 8 + 8]);
            d.extend_from_slice(k("C8oBfdKGaaNeNVqzmL2awkrTWxdjGd6Ho7qssqSCS1Yx").as_ref());
            d.push(0);
            d
        };
        let accounts: Vec<Pubkey> = (0..18).map(|i| if i == 1 { pumpswap::GLOBAL_CONFIG } else { Pubkey::new_unique() }).collect();
        let p = parse_create_pool(&data, &accounts, pumpswap::PUMP_AMM_PROGRAM_ID).unwrap();
        assert!(!p.graduated);
        assert_eq!(p.creator(), accounts[2]);
        assert_eq!(p.data.coin_creator, Pubkey::default());
        // Not a create_pool without PumpSwap's global config at 1.
        let mut wrong = accounts.clone();
        wrong[1] = Pubkey::new_unique();
        assert!(parse_create_pool(&data, &wrong, pumpswap::PUMP_AMM_PROGRAM_ID).is_none());
    }

    #[test]
    fn a_pool_account_is_read_with_coin_creator_before_mayhem() {
        let p = graduation();
        let mut raw = POOL_DISCRIMINATOR.to_vec();
        raw.push(255);
        raw.extend_from_slice(&0u16.to_le_bytes());
        for key in [p.data.creator, p.data.base_mint, p.data.quote_mint, p.data.lp_mint, p.data.pool_base_token_account, p.data.pool_quote_token_account] {
            raw.extend_from_slice(key.as_ref());
        }
        raw.extend_from_slice(&4_208_723_649_508u64.to_le_bytes());
        raw.extend_from_slice(p.data.coin_creator.as_ref());
        raw.push(1); // mayhem
        raw.extend_from_slice(&[0; 57]);
        assert_eq!(raw.len(), 301);
        let pool = decode_pool(&raw).unwrap();
        assert_eq!(pool.coin_creator, p.data.coin_creator);
        assert!(pool.is_mayhem_mode);
        assert_eq!(not_tradable(&pool, Some(&raw)), Some("a mayhem-mode pool"));
        assert_eq!(Side::of(&pool), Some(Side::SolQuote));
    }

    #[test]
    fn a_graduation_trades_the_token_on_token_2022_and_sol_on_token() {
        let p = graduation();
        let m = Market { pool: p.pool, data: p.data.clone(), side: Side::SolQuote, token_program: pumpswap::TOKEN_2022_PROGRAM };
        let user = Pubkey::new_unique();
        let buy = m.buy_ix(user, 1_000, 10, 0).unwrap();
        assert_eq!(buy.data[..8], pumpswap::BUY_DISCRIMINATOR);
        assert_eq!(u64::from_le_bytes(buy.data[8..16].try_into().unwrap()), 10);
        assert_eq!(u64::from_le_bytes(buy.data[16..24].try_into().unwrap()), 1_000);
        let keys: Vec<Pubkey> = buy.accounts.iter().map(|a| a.pubkey).collect();
        assert_eq!(keys[5], ata(&user, &p.data.base_mint, &pumpswap::TOKEN_2022_PROGRAM));
        assert_eq!(keys[6], ata(&user, &pumpswap::WSOL_MINT, &pumpswap::TOKEN_PROGRAM));
        assert_eq!(keys[11], pumpswap::TOKEN_2022_PROGRAM);
        assert_eq!(keys[12], pumpswap::TOKEN_PROGRAM);
        // 23 IDL accounts, pool-v2 (a coin creator), the buyback pair.
        assert_eq!(keys.len(), 26);
        assert_eq!(keys[23], pumpswap::derive_pool_v2(&p.data.base_mint).0);
        let sell = m.sell_ix(user, 10, 1, 0).unwrap();
        assert_eq!(sell.data[..8], pumpswap::SELL_DISCRIMINATOR);
        assert_eq!(sell.accounts.len(), 24);
    }

    #[test]
    fn a_pool_made_by_hand_trades_as_ultima_built_it() {
        let data = Pool {
            pool_bump: 255,
            index: 0,
            creator: Pubkey::new_unique(),
            base_mint: pumpswap::WSOL_MINT,
            quote_mint: Pubkey::new_unique(),
            lp_mint: Pubkey::new_unique(),
            pool_base_token_account: Pubkey::new_unique(),
            pool_quote_token_account: Pubkey::new_unique(),
            lp_supply: 0,
            is_mayhem_mode: false,
            coin_creator: Pubkey::default(),
        };
        let pool = Pubkey::new_unique();
        let user = Pubkey::new_unique();
        let m = Market { pool, data: data.clone(), side: Side::SolBase, token_program: pumpswap::TOKEN_2022_PROGRAM };
        let ours = m.buy_ix(user, 100, 7, 3).unwrap();
        let theirs = pumpswap::build_sell(pumpswap::SellParams {
            pool,
            pool_data: data.clone(),
            user,
            base_amount_in: 100,
            min_quote_amount_out: 7,
            fee_recipient_index: 3,
            quote_token_program: pumpswap::TOKEN_2022_PROGRAM,
        })
        .unwrap();
        assert_eq!(ours, theirs);
        let ours = m.sell_ix(user, 100, 7, 3).unwrap();
        let theirs = pumpswap::build_buy(pumpswap::BuyParams {
            pool,
            pool_data: data,
            user,
            base_amount_out: 7,
            max_quote_amount_in: 100,
            fee_recipient_index: 3,
            quote_token_program: pumpswap::TOKEN_2022_PROGRAM,
        })
        .unwrap();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn a_migration_seen_before_it_runs_makes_the_pool_its_create_pool_will() {
        // Mainnet, slot 464884226: migrate_v2's accounts, and the
        // create_pool it called.
        let ks = |v: &[&str]| v.iter().map(|s| k(s)).collect::<Vec<_>>();
        let migrate = mainnet_migrate_v2();
        let create = ks(&[
            "Gr5UkyMn47JKgC2cupw9ixaBrnfiKYjV1MH8eWXFQUpj", "ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw",
            "9VdZuPTHZ8E67XyVhMXFJpLWgShdTUqZMeaLJQ4h8beR", "2YV529hsrMAGYzMiY4dHBXocaLKb6bgVs86Udi2Dpump",
            "So11111111111111111111111111111111111111112", "42hakv5ggjhCqhVrQTHroUkEpMKTD23QzzwqwcuF5Lhq",
            "5B6rzfdv9GUcLeYG6tM9qmGZYMuZbWKAXkcQmRAYst4d", "FM9odD6xPj9xyoo7gRDPLGoGvPb44MfYbDHppoxK5vHy",
            "JBHCsPVhU2oqNwrcY8qf65EW1NnA4PpssB4iXLCZa2uC", "Ejmsnw7ktFCKKpdC6zxFs6eLDrjgxBDVzuKuX6yyp4cz",
            "GLt2CtKbstGNRemdr81auaJaJRbZvFcpfDdHdheP3ZWr", "11111111111111111111111111111111",
            "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
            "GS4CU59F31iL7aR2Q8zVS8DRrcRnXX1yjQ66TqNVQnaR", "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
        ]);
        let coin_creator = k("C8oBfdKGaaNeNVqzmL2awkrTWxdjGd6Ho7qssqSCS1Yx");
        let mut create_data = pumpswap::CREATE_POOL_DISCRIMINATOR.to_vec();
        create_data.extend_from_slice(&0u16.to_le_bytes());
        create_data.extend_from_slice(&206_900_000_000_000u64.to_le_bytes());
        create_data.extend_from_slice(&84_990_359_056u64.to_le_bytes());
        create_data.extend_from_slice(coin_creator.as_ref());
        create_data.extend_from_slice(&[0; 2]);
        let want = parse_create_pool(&create_data, &create, PUMP_PROGRAM).unwrap();

        let m = Migration::parse(&MIGRATE_V2_DISCRIMINATOR, &migrate).unwrap();
        assert_eq!(m.to_read()[..2], migrate[4..6]);
        let token_2022 = pumpswap::TOKEN_2022_PROGRAM;
        let mut curve = vec![0u8; 151];
        curve[32..40].copy_from_slice(&(84_990_359_056u64 + 15_000_001).to_le_bytes());
        curve[48] = 1;
        curve[49..81].copy_from_slice(coin_creator.as_ref());
        let mut token_account = vec![0u8; 165];
        token_account[..32].copy_from_slice(migrate[2].as_ref());
        token_account[32..64].copy_from_slice(migrate[4].as_ref());
        token_account[64..72].copy_from_slice(&206_900_000_000_000u64.to_le_bytes());
        let mut global = vec![0u8; 200];
        global[146..154].copy_from_slice(&15_000_001u64.to_le_bytes());
        let pump = |data| Read { owner: &PUMP_PROGRAM, data };
        let tokens = |data| Read { owner: &token_2022, data };
        let got = m.new_pool(pump(&curve), tokens(&token_account), pump(&global)).unwrap();
        assert_eq!(got.pool, want.pool);
        assert_eq!(format!("{:?}", got.data), format!("{:?}", want.data));
        assert_eq!(
            (got.base_token_program, got.quote_token_program, got.base_reserves, got.quote_reserves),
            (want.base_token_program, want.quote_token_program, want.base_reserves, want.quote_reserves)
        );
        assert!(got.graduated && !got.flagged);
        assert_eq!(got.creator(), coin_creator);

        // Run already: the curve is empty.
        let mut emptied = token_account.clone();
        emptied[64..72].fill(0);
        assert_eq!(m.new_pool(pump(&curve), tokens(&emptied), pump(&global)).unwrap_err(), "already migrated");
        // The 25-account form, and anything laid out otherwise, is not read.
        assert!(Migration::parse(&MIGRATE_V2_DISCRIMINATOR, &migrate[..25]).is_none());
        let mut moved = migrate.clone();
        moved.swap(9, 10);
        assert!(Migration::parse(&MIGRATE_V2_DISCRIMINATOR, &moved).is_none());
    }

    /// Mainnet, slot 464884226: the accounts of a `migrate_v2`.
    fn mainnet_migrate_v2() -> Vec<Pubkey> {
        [
            "4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf", "39azUYFWPz3VHgKCf3VChUwbpURdCHRxjWVowf5jUJjg",
            "2YV529hsrMAGYzMiY4dHBXocaLKb6bgVs86Udi2Dpump", "So11111111111111111111111111111111111111112",
            "FWy2KzfmWeXdcAU1j3AAAH74bNSvKxYYfiKSmHbhEaVM", "HUcedVmtcCt38GKQm7162xZbDj24bgTdKyz9LzjXXeNu",
            "BFoD9J6j4PDqxPhaG6UphbALw9j7HbM1FvFEeA65KvWZ", "9C4nRvhhVquCKATjDCx5FKvNS9PNgNqgyWy9AcoDjYv5",
            "11111111111111111111111111111111", "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA",
            "Gr5UkyMn47JKgC2cupw9ixaBrnfiKYjV1MH8eWXFQUpj", "9VdZuPTHZ8E67XyVhMXFJpLWgShdTUqZMeaLJQ4h8beR",
            "5B6rzfdv9GUcLeYG6tM9qmGZYMuZbWKAXkcQmRAYst4d", "FM9odD6xPj9xyoo7gRDPLGoGvPb44MfYbDHppoxK5vHy",
            "ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw", "42hakv5ggjhCqhVrQTHroUkEpMKTD23QzzwqwcuF5Lhq",
            "JBHCsPVhU2oqNwrcY8qf65EW1NnA4PpssB4iXLCZa2uC", "Ejmsnw7ktFCKKpdC6zxFs6eLDrjgxBDVzuKuX6yyp4cz",
            "GLt2CtKbstGNRemdr81auaJaJRbZvFcpfDdHdheP3ZWr", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "GS4CU59F31iL7aR2Q8zVS8DRrcRnXX1yjQ66TqNVQnaR",
            "SysvarRent111111111111111111111111111111111", "Ce6TQqeHC9p8KetsN6JsjHK7UTZk7nasjjnr7XxXp9F1",
            "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P", "4XRADvW4n2uh1krsGjT4BvTv3YxedXxbUsWsfB4BhyN4",
            "73VFQCPEpcQvHj142qdcT3Gd9ZP3fu9QwCH2hMYBxS4W",
        ]
        .iter()
        .map(|s| k(s))
        .collect()
    }

    /// A transaction in the Shreds stream has not run, so its accounts are
    /// whatever its sender wrote. Each one that decides what is bought has
    /// to be the address the mint gives it.
    #[test]
    fn a_migration_naming_an_account_that_is_not_the_mints_own_is_not_read() {
        let real = mainnet_migrate_v2();
        assert!(Migration::parse(&MIGRATE_V2_DISCRIMINATOR, &real).is_some());
        let someone_elses = k("C8oBfdKGaaNeNVqzmL2awkrTWxdjGd6Ho7qssqSCS1Yx");
        // The mint, the curve, its token account, the pool, its creator,
        // the LP mint, both vaults and both token programs.
        for forged in [2, 4, 5, 10, 11, 15, 17, 18, 19, 20] {
            let mut accounts = real.clone();
            accounts[forged] = someone_elses;
            assert!(
                Migration::parse(&MIGRATE_V2_DISCRIMINATOR, &accounts).is_none(),
                "account {forged} was taken on the instruction's word"
            );
        }
        // The other token program in the mint's place moves every address
        // derived through it.
        let mut accounts = real.clone();
        accounts[19] = pumpswap::TOKEN_PROGRAM;
        assert!(Migration::parse(&MIGRATE_V2_DISCRIMINATOR, &accounts).is_none());
    }

    /// The curve and the token account are read from the chain, where an
    /// account at the right address is still only as good as its owner.
    #[test]
    fn a_migration_is_not_bought_from_accounts_the_wrong_program_owns() {
        let accounts = mainnet_migrate_v2();
        let m = Migration::parse(&MIGRATE_V2_DISCRIMINATOR, &accounts).unwrap();
        let token_2022 = pumpswap::TOKEN_2022_PROGRAM;
        let system = pumpswap::SYSTEM_PROGRAM;
        let mut curve = vec![0u8; 151];
        curve[32..40].copy_from_slice(&90_000_000_000u64.to_le_bytes());
        curve[48] = 1;
        let mut token_account = vec![0u8; 165];
        token_account[..32].copy_from_slice(accounts[2].as_ref());
        token_account[32..64].copy_from_slice(accounts[4].as_ref());
        token_account[64..72].copy_from_slice(&206_900_000_000_000u64.to_le_bytes());
        let mut global = vec![0u8; 200];
        global[146..154].copy_from_slice(&15_000_001u64.to_le_bytes());
        let by = |owner, data| Read { owner, data };
        let pool = |c: Read, t: Read, g: Read| m.new_pool(c, t, g).map(|p| p.pool);

        assert_eq!(pool(by(&PUMP_PROGRAM, &curve), by(&token_2022, &token_account), by(&PUMP_PROGRAM, &global)), Ok(m.pool()));
        assert_eq!(
            pool(by(&system, &curve), by(&token_2022, &token_account), by(&PUMP_PROGRAM, &global)),
            Err("the bonding curve is not pump.fun's")
        );
        assert_eq!(
            pool(by(&PUMP_PROGRAM, &curve), by(&token_2022, &token_account), by(&system, &global)),
            Err("pump.fun's Global is not pump.fun's")
        );
        let not_the_curves = Err("the curve's token account is not the curve's");
        // Owned by the other token program, by no token program at all,
        // holding another mint, or held for another wallet.
        assert_eq!(
            pool(by(&PUMP_PROGRAM, &curve), by(&pumpswap::TOKEN_PROGRAM, &token_account), by(&PUMP_PROGRAM, &global)),
            not_the_curves
        );
        assert_eq!(pool(by(&PUMP_PROGRAM, &curve), by(&system, &token_account), by(&PUMP_PROGRAM, &global)), not_the_curves);
        let mut another_mint = token_account.clone();
        another_mint[..32].copy_from_slice(accounts[3].as_ref());
        assert_eq!(pool(by(&PUMP_PROGRAM, &curve), by(&token_2022, &another_mint), by(&PUMP_PROGRAM, &global)), not_the_curves);
        let mut another_wallet = token_account.clone();
        another_wallet[32..64].copy_from_slice(accounts[11].as_ref());
        assert_eq!(pool(by(&PUMP_PROGRAM, &curve), by(&token_2022, &another_wallet), by(&PUMP_PROGRAM, &global)), not_the_curves);
        assert_eq!(pool(by(&PUMP_PROGRAM, &curve), by(&token_2022, &[]), by(&PUMP_PROGRAM, &global)), not_the_curves);
    }
}
