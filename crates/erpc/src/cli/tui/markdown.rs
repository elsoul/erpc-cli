// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Just enough Markdown for the console: headings, bullets, rules,
//! **bold**, `code` and fenced code blocks, as styled spans. One line at a
//! time, so an answer can be drawn while it is still being written.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;

/// What the renderer remembers between lines.
#[derive(Debug, Default)]
pub struct Markdown {
    in_code_block: bool,
}

impl Markdown {
    /// Styles one line.
    pub fn line(&mut self, line: &str) -> Vec<Span<'static>> {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            self.in_code_block = !self.in_code_block;
            return vec![Span::styled("────", dim())];
        }
        if self.in_code_block {
            return vec![Span::styled(
                format!("  {line}"),
                Style::new().fg(Color::Cyan),
            )];
        }
        if trimmed.starts_with('#') {
            let text = trimmed.trim_start_matches('#').trim();
            return vec![Span::styled(
                text.to_owned(),
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )];
        }
        if matches!(trimmed, "---" | "***" | "___") {
            return vec![Span::styled("────────", dim())];
        }
        let indent = &line[..line.len() - trimmed.len()];
        if let Some(rest) = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
        {
            let mut spans = vec![
                Span::raw(indent.to_owned()),
                Span::styled("• ", Style::new().fg(Color::Cyan)),
            ];
            spans.extend(inline(rest));
            return spans;
        }
        inline(line)
    }
}

fn dim() -> Style {
    Style::new().fg(Color::DarkGray)
}

/// Styles `**bold**` and `` `code` `` within a line.
fn inline(text: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut plain = String::new();
    let mut rest = text;
    let flush = |plain: &mut String, spans: &mut Vec<Span<'static>>| {
        if !plain.is_empty() {
            spans.push(Span::raw(std::mem::take(plain)));
        }
    };
    while !rest.is_empty() {
        if let Some(after) = rest.strip_prefix("**")
            && let Some(end) = after.find("**")
        {
            flush(&mut plain, &mut spans);
            spans.push(Span::styled(
                after[..end].to_owned(),
                Style::new().add_modifier(Modifier::BOLD),
            ));
            rest = &after[end + 2..];
            continue;
        }
        if let Some(after) = rest.strip_prefix('`')
            && let Some(end) = after.find('`')
        {
            flush(&mut plain, &mut spans);
            spans.push(Span::styled(
                after[..end].to_owned(),
                Style::new().fg(Color::Yellow),
            ));
            rest = &after[end + 1..];
            continue;
        }
        let step = rest.chars().next().map_or(1, char::len_utf8);
        plain.push_str(&rest[..step]);
        rest = &rest[step..];
    }
    flush(&mut plain, &mut spans);
    spans
}

#[cfg(test)]
mod tests {
    use ratatui::style::Modifier;
    use ratatui::text::Span;

    use super::Markdown;

    fn plain(spans: &[Span<'_>]) -> String {
        spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn markup_is_turned_into_styling_not_shown() {
        let mut md = Markdown::default();
        assert_eq!(plain(&md.line("## Title")), "Title");
        let spans = md.line("- run `erpc login` **now**");
        assert_eq!(plain(&spans), "• run erpc login now");
        assert!(
            spans
                .iter()
                .any(|s| s.content == "now" && s.style.add_modifier.contains(Modifier::BOLD))
        );
        assert_eq!(plain(&md.line("  * nested")), "  • nested");
        assert_eq!(
            plain(&md.line("a ** b")),
            "a ** b",
            "an unmatched marker is left as is"
        );
    }

    #[test]
    fn code_blocks_are_kept_verbatim() {
        let mut md = Markdown::default();
        md.line("```bash");
        assert_eq!(
            plain(&md.line("- not a bullet **x**")),
            "  - not a bullet **x**"
        );
        md.line("```");
        assert_eq!(plain(&md.line("- a bullet")), "• a bullet");
    }
}
