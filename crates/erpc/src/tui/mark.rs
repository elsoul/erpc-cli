// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The ERPC mark, in terminal pixels.
//!
//! Drawn by hand from the mark's SVG on a grid of 24 by 12: the circle,
//! the blue triangle, the orange one and the triangle inside it, with the
//! dark lines where they meet. Four pixels share a cell as a quadrant
//! block, so the mark is 12 columns by 6 rows and comes out about square.
//!
//! A cell shows two colours at most, and the drawing keeps to that. It is
//! also why there is no outline round the outside: the terminal's own
//! background stands in for it. The colours are the SVG's gradients, taken
//! at the middle of each row of cells.

use ratatui::style::{Color, Style};
use ratatui::text::Span;

use super::Look;

/// The mark's width in columns.
pub const WIDTH: usize = 12;

/// The mark, a letter a pixel: `c` the circle, `b` the blue triangle, `o`
/// the orange one, `y` the triangle inside it, `#` the dark lines between
/// them and `.` nothing. The right half mirrors the left.
const ART: [&str; 12] = [
    "........................",
    ".......ccc.oo.ccc.......",
    "....ccccc#oooo#ccccc....",
    ".bbbbbbb##oooo##bbbbbbb.",
    "..bbbbbb#oooooo#bbbbbb..",
    "....bbb#ooo##ooo#bbb....",
    "...cc##ooo#yy#ooo##cc...",
    "....c#oooo#yy#oooo#c....",
    ".....oooo#yyyy#oooo.....",
    ".....oooo#yyyy#oooo.....",
    "....oooo#yyyyyy#oooo....",
    "...oooo#yyyyyyyy#oooo...",
];

/// Where the drawing sits in the SVG's 512 by 512 box: the top of its
/// first row of pixels, and the height of each.
const TOP: f32 = 122.1;
const PIXEL: f32 = 304.0 / 12.0;

/// A colour that runs from one height in the SVG to another, as
/// `(y, 0xRRGGBB)` at each end.
struct Gradient {
    from: (f32, u32),
    to: (f32, u32),
}

#[allow(clippy::unreadable_literal)]
const CIRCLE: Gradient = Gradient {
    from: (390.1, 0xF5F3FF),
    to: (142.1, 0xC084FC),
};
#[allow(clippy::unreadable_literal)]
const BLUE: Gradient = Gradient {
    from: (198.1, 0x2563EB),
    to: (400.1, 0xBFDBFE),
};
#[allow(clippy::unreadable_literal)]
const ORANGE: Gradient = Gradient {
    from: (421.1, 0xFED7AA),
    to: (117.1, 0xEA580C),
};
#[allow(clippy::unreadable_literal)]
const INNER: Gradient = Gradient {
    from: (421.1, 0xFEF3C7),
    to: (248.0, 0xFBBF24),
};
/// The lines between the shapes.
#[allow(clippy::unreadable_literal)]
const LINE: u32 = 0x09090B;

impl Gradient {
    /// The colour at height `y`, as `0xRRGGBB`.
    fn at(&self, y: f32) -> u32 {
        let (y0, c0) = self.from;
        let (y1, c1) = self.to;
        let t = ((y - y0) / (y1 - y0)).clamp(0.0, 1.0);
        let channel = |shift: u32| {
            let a = f32::from(((c0 >> shift) & 0xFF) as u8);
            let b = f32::from(((c1 >> shift) & 0xFF) as u8);
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let value = (a + (b - a) * t).round() as u32;
            value << shift
        };
        channel(16) | channel(8) | channel(0)
    }
}

/// Each set of quadrants, by bit: 1 top left, 2 top right, 4 bottom left,
/// 8 bottom right.
const QUADRANTS: [&str; 16] = [
    " ", "▘", "▝", "▀", "▖", "▌", "▞", "▛", "▗", "▚", "▐", "▜", "▄", "▙", "▟", "█",
];

/// The mark as rows of styled cells, or nothing without colour -- in one
/// colour it is only a blot.
#[must_use]
pub fn rows(look: Look) -> Vec<Vec<Span<'static>>> {
    if !look.color {
        return Vec::new();
    }
    (0..ART.len() / 2)
        .map(|row| (0..WIDTH).map(|col| cell(look, row, col)).collect())
        .collect()
}

/// One cell: its four pixels as a quadrant block. Where some of them are
/// empty, the block is the colour and the terminal shows through the
/// rest; where there are two colours, the block is the one with fewer
/// pixels, on the other. A cell of one colour is a space on it.
fn cell(look: Look, row: usize, col: usize) -> Span<'static> {
    #[allow(clippy::cast_precision_loss)]
    let y = TOP + (2 * row + 1) as f32 * PIXEL;
    let pixels = [(0, 0), (0, 1), (1, 0), (1, 1)]
        .map(|(down, right)| shade(ART[2 * row + down].as_bytes()[2 * col + right], y));
    let count = |colour: u32| pixels.iter().filter(|&&p| p == Some(colour)).count();
    let mut colours = pixels.iter().flatten().copied();
    let Some(first) = colours.next() else {
        return Span::raw(" ");
    };
    let second = colours.find(|&c| c != first);
    let (fore, back) = match second {
        _ if pixels.contains(&None) => (first, None),
        None => return Span::styled(" ", Style::new().bg(color(look, first))),
        Some(second) if count(second) < count(first) => (second, Some(first)),
        Some(second) => (first, Some(second)),
    };
    let bits = pixels
        .iter()
        .enumerate()
        .filter(|(_, p)| **p == Some(fore))
        .fold(0, |bits, (i, _)| bits | 1 << i);
    let mut style = Style::new().fg(color(look, fore));
    if let Some(back) = back {
        style = style.bg(color(look, back));
    }
    Span::styled(QUADRANTS[bits], style)
}

/// The colour of a pixel drawn as `letter` in the row of cells at height
/// `y`, or `None` where there is nothing.
fn shade(letter: u8, y: f32) -> Option<u32> {
    match letter {
        b'c' => Some(CIRCLE.at(y)),
        b'b' => Some(BLUE.at(y)),
        b'o' => Some(ORANGE.at(y)),
        b'y' => Some(INNER.at(y)),
        b'#' => Some(LINE),
        _ => None,
    }
}

fn color(look: Look, pixel: u32) -> Color {
    let [_, r, g, b] = pixel.to_be_bytes();
    if look.truecolor {
        Color::Rgb(r, g, b)
    } else {
        Color::Indexed(nearest_256(r, g, b))
    }
}

/// The nearest colour in the 256-colour palette: the 6x6x6 cube or the
/// grey ramp, whichever is closer.
pub(crate) fn nearest_256(r: u8, g: u8, b: u8) -> u8 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let step = |c: u8| {
        (0..6_u8)
            .min_by_key(|&i| c.abs_diff(LEVELS[usize::from(i)]))
            .unwrap_or(0)
    };
    let (ri, gi, bi) = (step(r), step(g), step(b));
    let cube = (
        16 + 36 * ri + 6 * gi + bi,
        (
            LEVELS[usize::from(ri)],
            LEVELS[usize::from(gi)],
            LEVELS[usize::from(bi)],
        ),
    );
    let mean = (u16::from(r) + u16::from(g) + u16::from(b)) / 3;
    let gray_step = u8::try_from((mean.saturating_sub(8) / 10).min(23)).unwrap_or(23);
    let level = 8 + 10 * gray_step;
    let gray = (232 + gray_step, (level, level, level));
    let distance = |(cr, cg, cb): (u8, u8, u8)| {
        let d = |a: u8, c: u8| u32::from(a.abs_diff(c)).pow(2);
        d(r, cr) + d(g, cg) + d(b, cb)
    };
    if distance(gray.1) < distance(cube.1) {
        gray.0
    } else {
        cube.0
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ratatui::style::Color;
    use ratatui::text::Span;

    use super::{ART, ORANGE, PIXEL, QUADRANTS, TOP, WIDTH, color, nearest_256, rows, shade};
    use crate::tui::Look;

    const LOOK: Look = Look {
        color: true,
        truecolor: true,
        animate: true,
    };

    /// What a cell shows in each quarter: top left, top right, bottom
    /// left, bottom right.
    fn seen(span: &Span<'_>) -> [Option<Color>; 4] {
        let bits = QUADRANTS
            .iter()
            .position(|q| *q == span.content)
            .expect("a quadrant block");
        [1, 2, 4, 8].map(|bit| {
            if bits & bit == 0 {
                span.style.bg
            } else {
                span.style.fg
            }
        })
    }

    #[test]
    fn the_mark_is_six_rows_of_twelve_cells() {
        let rows = rows(LOOK);
        assert_eq!(rows.len(), 6);
        assert!(rows.iter().all(|row| row.len() == WIDTH));
    }

    #[test]
    fn the_drawing_is_a_mirror_image_of_known_letters() {
        for row in ART {
            assert_eq!(row.len(), 2 * WIDTH, "{row}");
            assert!(row.bytes().all(|b| b".#cboy".contains(&b)), "{row}");
            assert!(row.bytes().eq(row.bytes().rev()), "{row}");
        }
    }

    #[test]
    fn no_cell_needs_more_than_two_colours() {
        for row in (0..ART.len()).step_by(2) {
            for col in (0..2 * WIDTH).step_by(2) {
                let letters: BTreeSet<u8> = [(0, 0), (0, 1), (1, 0), (1, 1)]
                    .iter()
                    .map(|(down, right)| ART[row + down].as_bytes()[col + right])
                    .collect();
                assert!(letters.len() <= 2, "cell {row},{col}: {letters:?}");
            }
        }
    }

    #[test]
    fn every_pixel_shows_in_its_shapes_colour() {
        for (row, cells) in rows(LOOK).iter().enumerate() {
            #[allow(clippy::cast_precision_loss)]
            let y = TOP + (2 * row + 1) as f32 * PIXEL;
            for (col, span) in cells.iter().enumerate() {
                let want = [(0, 0), (0, 1), (1, 0), (1, 1)].map(|(down, right)| {
                    shade(ART[2 * row + down].as_bytes()[2 * col + right], y)
                        .map(|pixel| color(LOOK, pixel))
                });
                assert_eq!(seen(span), want, "cell {row},{col}");
            }
        }
    }

    #[test]
    fn what_shows_is_the_same_mirrored_left_to_right() {
        for row in rows(LOOK) {
            for (left, right) in row.iter().zip(row.iter().rev()) {
                let [tl, tr, bl, br] = seen(right);
                assert_eq!(seen(left), [tr, tl, br, bl]);
            }
        }
    }

    #[test]
    fn the_orange_runs_from_the_svgs_deep_orange_to_its_peach() {
        assert_eq!(ORANGE.at(117.1), 0x00EA_580C);
        assert_eq!(ORANGE.at(421.1), 0x00FE_D7AA);
        assert_eq!(ORANGE.at(0.0), 0x00EA_580C, "held past the ends");
    }

    #[test]
    fn without_colour_there_is_no_mark() {
        let look = Look {
            color: false,
            truecolor: false,
            animate: false,
        };
        assert!(rows(look).is_empty());
    }

    #[test]
    fn colours_map_to_the_nearest_palette_entry() {
        assert_eq!(nearest_256(0, 0, 0), 16);
        assert_eq!(nearest_256(255, 255, 255), 231);
        assert_eq!(nearest_256(128, 128, 128), 244);
        assert_eq!(nearest_256(234, 88, 12), 166);
    }
}
