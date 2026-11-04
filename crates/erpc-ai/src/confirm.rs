// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Asking the person before a tool spends or stops something.
//!
//! A tool that starts a paid product, ends one or tops up credit never runs
//! on the model's word: erpc builds what the person is shown from what
//! user-api says (the product, its price, the balance), and only a yes from
//! the person at the terminal sends the request. The model's text is not in
//! it, so a model cannot word its way past it. A session with no one to ask
//! (`erpc ai -m` in a script, `--json`) has no [`Confirm`], and such a tool
//! refuses.

use core::fmt::Write as _;
use core::future::Future;
use core::pin::Pin;

use unicode_width::UnicodeWidthStr as _;

/// What the person is asked: a title and lines of label and value, in the
/// language of the run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Confirmation {
    /// What will happen.
    pub title: String,
    /// Each fact: its label, and the value.
    pub lines: Vec<(String, String)>,
}

impl Confirmation {
    /// The confirmation as plain text, its values lined up after labels of
    /// any width (a CJK character takes two columns).
    #[must_use]
    pub fn text(&self) -> String {
        let width = self
            .lines
            .iter()
            .map(|(label, _)| label.width())
            .max()
            .unwrap_or(0);
        let mut out = self.title.clone();
        for (label, value) in &self.lines {
            let pad = width - label.width();
            let _ = write!(out, "\n  {label}{}  {value}", " ".repeat(pad));
        }
        out
    }
}

/// The wallet a top-up pays from: its address, known without the key, and
/// the key itself, read only after the person said yes.
pub trait CreditWallet {
    /// The paying address, as configured.
    ///
    /// # Errors
    ///
    /// Says what is missing from the configuration.
    fn address(&self) -> Result<erpc_wallet::evm::Address, String>;

    /// The key, read from where it is kept, after the gate allowed it.
    ///
    /// # Errors
    ///
    /// Why it could not be read, or that it is not the configured address.
    fn key(&self) -> Result<erpc_wallet::evm::EvmKey, String>;

    /// The 1Password vault a new wallet would go in by default, if one is
    /// known.
    fn vault(&self) -> Option<String>;

    /// Why a new wallet may not be made because one is set up already,
    /// perhaps half way; none when there is none. The same check
    /// [`Self::create`] makes, asked before the person is.
    fn existing(&self) -> Option<String> {
        self.address()
            .ok()
            .map(|a| format!("a wallet is set up already: {a}; erpc does not replace one"))
    }

    /// The wallet erpc made before, kept in 1Password, when none is
    /// configured here: the one to use rather than make another. Only its
    /// address is read.
    ///
    /// # Errors
    ///
    /// Why 1Password could not be searched.
    fn find(&self) -> Pin<Box<dyn Future<Output = Result<Option<FoundWallet>, String>> + '_>> {
        Box::pin(async { Ok(None) })
    }

    /// Sets up `found`, `allow_ai` saying whether erpc ai may ask to pay
    /// from it; returns its address.
    ///
    /// # Errors
    ///
    /// Why it was not set up.
    fn adopt<'a>(
        &'a self,
        found: &'a FoundWallet,
        allow_ai: bool,
    ) -> Pin<Box<dyn Future<Output = Result<erpc_wallet::evm::Address, String>> + 'a>> {
        let _ = (found, allow_ai);
        Box::pin(async { Err("this erpc cannot set up a wallet".to_owned()) })
    }

    /// Makes a new wallet in `vault` and sets it up, `allow_ai` saying
    /// whether erpc ai may ask to pay from it; returns its address. The
    /// work (1Password, which may wait for an unlock) runs off the async
    /// thread.
    ///
    /// # Errors
    ///
    /// Why it was not made (one exists, the vault refused, …).
    fn create<'a>(
        &'a self,
        vault: &'a str,
        allow_ai: bool,
    ) -> Pin<Box<dyn Future<Output = Result<erpc_wallet::evm::Address, String>> + 'a>>;
}

/// A wallet erpc made before, found in 1Password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundWallet {
    /// Its address.
    pub address: erpc_wallet::evm::Address,
    /// Where its key is: an `op://` reference, read only to sign.
    pub reference: String,
    /// The vault it is in, by name, for the person.
    pub vault: String,
    /// How many more wallet items erpc made there are; the oldest one is
    /// this.
    pub others: usize,
}

/// A question the model puts to the person, answered by picking from
/// options rather than typing. It decides nothing by itself: a pick is
/// passed back to the model as the person's words, and anything it leads
/// to that changes the account still asks its own [`Confirmation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// What is asked.
    pub question: String,
    /// What the person can pick: a label and, perhaps, a line about it.
    pub options: Vec<(String, Option<String>)>,
    /// Whether several can be picked.
    pub multiple: bool,
}

/// What the person did with a [`Question`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The options picked, by index, in order.
    Picked(Vec<usize>),
    /// None fitted: the person will say it in their own words, in their
    /// next message.
    OwnWords,
    /// None fitted, and the person typed their answer there and then:
    /// where there is no next message to wait for, such as `erpc ai -m`.
    Said(String),
}

/// What the person said to a [`Confirmation`] that can also be allowed
/// from then on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allow {
    /// No.
    No,
    /// Yes, this once.
    Once,
    /// Yes, and the same again without asking until the console ends.
    Always,
    /// Yes, and every command, scripts too, without asking until the
    /// console ends or a new conversation starts, once a second question
    /// has made sure.
    Everything,
}

/// Whoever can answer a [`Confirmation`]: the person at the terminal.
pub trait Confirm {
    /// Shows `ask` and returns whether the person said yes.
    fn confirm<'a>(&'a self, ask: &'a Confirmation) -> Pin<Box<dyn Future<Output = bool> + 'a>>;

    /// Shows `ask` with answers besides yes and no: yes, and the same
    /// command again without asking, or every command, until the console
    /// ends. Where those cannot be offered it is a plain yes or no.
    fn allow<'a>(&'a self, ask: &'a Confirmation) -> Pin<Box<dyn Future<Output = Allow> + 'a>> {
        Box::pin(async move {
            if self.confirm(ask).await {
                Allow::Once
            } else {
                Allow::No
            }
        })
    }

    /// Shows `question` and returns what the person picked. Where picking
    /// is not possible the person answers in their own words.
    fn choose<'a>(&'a self, question: &'a Question) -> Pin<Box<dyn Future<Output = Answer> + 'a>> {
        let _ = question;
        Box::pin(async { Answer::OwnWords })
    }
}

#[cfg(test)]
mod tests {
    use super::Confirmation;

    #[test]
    fn the_text_lines_up_the_values() {
        let ask = Confirmation {
            title: "Start VPS Plus".to_owned(),
            lines: vec![
                ("Price".to_owned(), "€0.14 per hour".to_owned()),
                ("Region".to_owned(), "frankfurt".to_owned()),
            ],
        };
        assert_eq!(
            ask.text(),
            "Start VPS Plus\n  Price   €0.14 per hour\n  Region  frankfurt"
        );
        // Wide characters take two columns each.
        let ask = Confirmation {
            title: "开始 VPS Plus".to_owned(),
            lines: vec![
                ("价格".to_owned(), "x".to_owned()),
                ("区域".to_owned(), "y".to_owned()),
                ("VAT".to_owned(), "z".to_owned()),
            ],
        };
        assert_eq!(ask.text(), "开始 VPS Plus\n  价格  x\n  区域  y\n  VAT   z");
    }
}
