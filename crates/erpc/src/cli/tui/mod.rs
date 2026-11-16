// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The full-screen console.

pub mod chat;
pub mod mark;
pub mod markdown;
mod picker;
pub mod splash;

/// How much the terminal can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Look {
    /// Whether to colour anything. Off under `NO_COLOR` and on dumb terminals.
    pub color: bool,
    /// Whether colours can be given as RGB. Without it they are picked from
    /// the 256-colour palette, which every terminal in use has.
    pub truecolor: bool,
    /// Whether to animate. Off with `ERPC_NO_ANIMATION`, and wherever colour
    /// is off.
    pub animate: bool,
}

impl Look {
    /// What this terminal can show, read from the environment.
    #[must_use]
    pub fn detect() -> Self {
        Self::from_env(|name| std::env::var(name).ok())
    }

    fn from_env(var: impl Fn(&str) -> Option<String>) -> Self {
        let set = |name: &str| var(name).is_some_and(|v| !v.is_empty());
        let color = !set("NO_COLOR") && var("TERM").as_deref() != Some("dumb");
        let truecolor = color
            && var("COLORTERM")
                .is_some_and(|v| v.eq_ignore_ascii_case("truecolor") || v == "24bit");
        Self {
            color,
            truecolor,
            animate: color && !set("ERPC_NO_ANIMATION"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Look;

    fn look(pairs: &[(&str, &str)]) -> Look {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Look::from_env(move |name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
    }

    #[test]
    fn no_color_turns_off_colour_and_animation() {
        let l = look(&[("NO_COLOR", "1"), ("COLORTERM", "truecolor")]);
        assert!(!l.color && !l.truecolor && !l.animate);
    }

    #[test]
    fn truecolor_is_used_only_when_the_terminal_says_so() {
        assert!(look(&[("COLORTERM", "truecolor")]).truecolor);
        assert!(!look(&[("TERM", "xterm-256color")]).truecolor);
        assert!(look(&[]).animate);
        assert!(!look(&[("ERPC_NO_ANIMATION", "1")]).animate);
    }
}
