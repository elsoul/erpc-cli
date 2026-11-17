// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! The first thing `erpc` shows: a data centre in orbit. Stars drift past,
//! a planet's edge rises into view with the lights of its data centres on
//! it, satellites circle the name, and the name assembles itself out of
//! bits -- all while the session signs in behind it.
//!
//! Each frame is a function of the time since the start, so a test can draw
//! any moment of it, and skipping it is drawing its last moment. The
//! animation never makes anyone wait: it lasts about as long as signing in
//! does, and a key ends it.

use std::f32::consts::{FRAC_PI_2, TAU};
use std::time::{Duration, Instant};

use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures_util::{Stream, StreamExt as _};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::{DefaultTerminal, Frame};

use super::{Look, mark};

/// The name, in block letters. The box-drawing characters are the shadow.
const LOGO: [&str; 6] = [
    "███████╗██████╗ ██████╗  ██████╗",
    "██╔════╝██╔══██╗██╔══██╗██╔════╝",
    "█████╗  ██████╔╝██████╔╝██║     ",
    "██╔══╝  ██╔══██╗██╔═══╝ ██║     ",
    "███████╗██║  ██║██║     ╚██████╗",
    "╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝",
];
const LOGO_WIDTH: u16 = 32;
/// Columns between the mark and the letters.
const MARK_GAP: u16 = 3;
/// The mark's width, as a column count.
#[allow(clippy::cast_possible_truncation)]
const MARK_WIDTH: u16 = mark::WIDTH as u16;
/// Logo, blank, tagline, rack lights, blank, status.
const HEIGHT: u16 = 11;
/// Room for the orbit and the planet as well.
const SCENE_WIDTH: u16 = 66;
const SCENE_HEIGHT: u16 = 24;
/// The orbit's half-width and half-height, in cells.
const ORBIT: (f32, f32) = (30.0, 6.4);

/// The stars fade in over this long.
const FADE_MS: f32 = 600.0;
/// The orbit is traced over this long.
const ORBIT_MS: f32 = 900.0;
/// The planet rises over this long.
const RISE_MS: f32 = 1500.0;
/// The letters assemble left to right over this long.
const REVEAL_MS: f32 = 1050.0;
/// Then a band of light crosses them.
const SHIMMER_MS: f32 = 800.0;
/// The tagline starts typing here, one character this often.
const TAGLINE_AT_MS: f32 = 750.0;
const TAGLINE_CHAR_MS: f32 = 30.0;
/// The rack lights come on one by one from here, one this often.
const RACK_AT_MS: f32 = 1100.0;
const RACK_LIGHT_MS: f32 = 40.0;
const RACK_LIGHTS: u16 = 16;
/// The last moment of the animation.
pub const END: Duration = Duration::from_millis(2200);
/// One splash in this many has a UFO pass by.
pub const UFO_ONE_IN: u32 = 128;
/// One splash in this many has a meteor shower.
pub const SHOWER_ONE_IN: u32 = 32;
/// Of the rest, one in this many has a single shooting star.
pub const SHOOTING_STAR_ONE_IN: u32 = 10;

/// What crosses the sky on a splash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sky {
    /// Nothing.
    Clear,
    /// One shooting star.
    Star,
    /// A meteor shower.
    Shower,
    /// A UFO.
    Ufo,
}

impl Sky {
    /// Rolls the dice for this splash. `ERPC_SPLASH_SKY` set to `clear`,
    /// `star` or `shower` picks one instead, to see a rare one on demand.
    #[must_use]
    pub fn roll(look: Look) -> Self {
        if !look.animate {
            return Self::Clear;
        }
        match std::env::var("ERPC_SPLASH_SKY").as_deref() {
            Ok("ufo") => return Self::Ufo,
            Ok("shower") => return Self::Shower,
            Ok("star") => return Self::Star,
            Ok("clear") => return Self::Clear,
            _ => {}
        }
        if one_in(UFO_ONE_IN) {
            Self::Ufo
        } else if one_in(SHOWER_ONE_IN) {
            Self::Shower
        } else if one_in(SHOOTING_STAR_ONE_IN) {
            Self::Star
        } else {
            Self::Clear
        }
    }

    const fn meteors(self) -> &'static [Meteor] {
        match self {
            Self::Clear | Self::Ufo => &[],
            Self::Star => &[STAR],
            Self::Shower => &SHOWER,
        }
    }
}

/// One meteor's flight.
#[derive(Debug, Clone, Copy)]
struct Meteor {
    /// When it sets off.
    at_ms: f32,
    /// Where along the top it starts, as a fraction of the width.
    from: f32,
    /// How many rows below the top of the sky it starts.
    drop: f32,
    /// How long it takes to cross.
    ms: f32,
    /// How many cells of tail it trails.
    tail: u16,
}

const STAR: Meteor = Meteor {
    at_ms: 250.0,
    from: 0.92,
    drop: 0.0,
    ms: 420.0,
    tail: 18,
};

/// A shower: eight, one after another, from different places.
const SHOWER: [Meteor; 8] = [
    Meteor {
        at_ms: 120.0,
        from: 0.97,
        drop: 0.0,
        ms: 380.0,
        tail: 16,
    },
    Meteor {
        at_ms: 240.0,
        from: 0.80,
        drop: 1.0,
        ms: 330.0,
        tail: 12,
    },
    Meteor {
        at_ms: 330.0,
        from: 1.02,
        drop: 2.0,
        ms: 420.0,
        tail: 18,
    },
    Meteor {
        at_ms: 450.0,
        from: 0.88,
        drop: 0.5,
        ms: 360.0,
        tail: 14,
    },
    Meteor {
        at_ms: 560.0,
        from: 0.70,
        drop: 1.5,
        ms: 320.0,
        tail: 10,
    },
    Meteor {
        at_ms: 650.0,
        from: 0.99,
        drop: 1.0,
        ms: 400.0,
        tail: 16,
    },
    Meteor {
        at_ms: 760.0,
        from: 0.84,
        drop: 2.0,
        ms: 340.0,
        tail: 12,
    },
    Meteor {
        at_ms: 880.0,
        from: 0.93,
        drop: 0.0,
        ms: 380.0,
        tail: 14,
    },
];

/// How long "signed in" stays on screen before the console takes over.
const HOLD: Duration = Duration::from_millis(600);

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/// The words on the splash, in the operator's language.
pub struct Words<'a> {
    /// One line under the name.
    pub tagline: &'a str,
    /// Shown while signing in.
    pub connecting: &'a str,
    /// Shown before the account once signed in.
    pub signed_in: &'a str,
}

/// Where signing in has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status<'a> {
    /// Still going.
    Connecting,
    /// Done, as this account.
    SignedIn(&'a str),
}

/// How the splash ended.
pub enum Played<T> {
    /// Signed in; the console can start.
    Ready(T),
    /// Signing in failed, for this reason.
    Failed(String),
    /// The operator pressed Ctrl-C.
    Cancelled,
}

/// Shows the splash until `connect` finishes and the animation has played
/// (or been skipped with a key). `connect` gives back what the console
/// needs and the account to show.
///
/// # Errors
///
/// Returns an error when the terminal cannot be drawn to.
pub async fn play<T>(
    terminal: &mut DefaultTerminal,
    look: Look,
    words: &Words<'_>,
    connect: impl Future<Output = Result<(T, String), String>>,
) -> std::io::Result<Played<T>> {
    let sky = Sky::roll(look);
    frames(
        look.animate,
        connect,
        EventStream::new(),
        |moment, now, status| {
            terminal
                .draw(|frame| draw(frame, look, words, moment, now, status, sky))
                .map(drop)
        },
    )
    .await
}

/// [`play`] without the terminal: `show` is handed each frame's moment,
/// time since the start and status, and `events` the keys. Frames come
/// only while `connect` is waiting rather than working, so it must not
/// block the thread.
pub(crate) async fn frames<T>(
    animate: bool,
    connect: impl Future<Output = Result<(T, String), String>>,
    events: impl Stream<Item = std::io::Result<Event>>,
    mut show: impl FnMut(Duration, Duration, Status<'_>) -> std::io::Result<()>,
) -> std::io::Result<Played<T>> {
    let start = Instant::now();
    let mut skipped = !animate;
    let mut connect = std::pin::pin!(connect);
    let mut connected: Option<(T, String, Instant)> = None;
    let mut events = std::pin::pin!(events);
    let mut tick = tokio::time::interval(Duration::from_millis(16));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let now = start.elapsed();
        let moment = if skipped { END } else { now.min(END) };
        let status = match &connected {
            Some((_, label, _)) => Status::SignedIn(label),
            None => Status::Connecting,
        };
        show(moment, now, status)?;

        let hold = if skipped { HOLD / 2 } else { HOLD };
        if moment >= END
            && connected
                .as_ref()
                .is_some_and(|(_, _, at)| at.elapsed() >= hold)
            && let Some((value, _, _)) = connected.take()
        {
            return Ok(Played::Ready(value));
        }

        tokio::select! {
            _ = tick.tick() => {}
            result = &mut connect, if connected.is_none() => match result {
                Ok((value, label)) => connected = Some((value, label, Instant::now())),
                Err(message) => return Ok(Played::Failed(message)),
            },
            Some(Ok(Event::Key(key))) = events.next() => {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
                    return Ok(Played::Cancelled);
                }
                skipped = true;
            }
        }
    }
}

/// Draws the splash as it is `moment` into the animation. `now` keeps the
/// things that never stop -- stars, satellites, lights, the spinner --
/// moving after the animation has ended.
pub fn draw(
    frame: &mut Frame,
    look: Look,
    words: &Words<'_>,
    moment: Duration,
    now: Duration,
    status: Status<'_>,
    sky: Sky,
) {
    let area = frame.area();
    let ms = moment.as_secs_f32() * 1000.0;
    let clock = now.as_secs_f32();
    let buf = frame.buffer_mut();
    let status_spans = status_spans(look, words, status, now);

    // Too small for the letters: the name and the status, nothing else.
    if area.width < LOGO_WIDTH + 2 || area.height < HEIGHT {
        let top = area.y + area.height.saturating_sub(2) / 2;
        centered(
            buf,
            area,
            top,
            &[(
                "ERPC".to_owned(),
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )],
        );
        if area.height > 1 {
            centered(buf, area, top + 1, &status_spans);
        }
        uncolor(buf, look);
        return;
    }

    let top = area.y + (area.height - HEIGHT) / 2;
    // The mark sits to the left of the letters when there is room, and the
    // two are centred together.
    let mark = mark::rows(look);
    let lead = if !mark.is_empty() && area.width >= LOGO_WIDTH + MARK_GAP + MARK_WIDTH + 2 {
        MARK_WIDTH + MARK_GAP
    } else {
        0
    };
    let left = area.x + (area.width - LOGO_WIDTH - lead) / 2 + lead;
    let whole_scene = area.width >= SCENE_WIDTH && area.height >= SCENE_HEIGHT;
    if look.color {
        stars(buf, area, look, ms, clock);
        for meteor in sky.meteors() {
            shooting_star(buf, area, look, top, ms, meteor);
        }
        if sky == Sky::Ufo {
            ufo(buf, area, look, top, ms, clock);
        }
        if whole_scene {
            planet(buf, area, look, top, ms, clock);
            let centre = (
                f32::from(area.x) + f32::from(area.width) / 2.0,
                f32::from(top) + 2.5,
            );
            orbit(buf, area, look, centre, ms, clock);
        }
    }
    if lead > 0 {
        // The mark's top pixel row is empty: drawn a row higher, its base
        // sits level with the foot of the letters' faces rather than their
        // shadows, and its point rises a little above them.
        draw_mark(
            buf,
            look,
            &mark,
            left - lead,
            top.saturating_sub(1),
            lead,
            ms,
        );
    }
    logo(buf, look, left, top, lead, ms);
    tagline(buf, area, look, words, top + 7, ms);
    if look.color {
        rack(buf, area, look, left, top + 8, ms, clock);
    }
    centered(buf, area, top + 10, &status_spans);
    uncolor(buf, look);
}

fn status_spans(
    look: Look,
    words: &Words<'_>,
    status: Status<'_>,
    now: Duration,
) -> Vec<(String, Style)> {
    let dim = Style::new().fg(gray(look, 120));
    match status {
        Status::Connecting => {
            #[allow(clippy::cast_possible_truncation)]
            let spin = SPINNER[(now.as_millis() / 80) as usize % SPINNER.len()];
            vec![
                (format!("{spin} "), Style::new().fg(Color::Cyan)),
                (words.connecting.to_owned(), dim),
            ]
        }
        Status::SignedIn(account) => vec![
            ("✓ ".to_owned(), Style::new().fg(Color::Green)),
            (format!("{} ", words.signed_in), dim),
            (
                account.to_owned(),
                Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
        ],
    }
}

/// Writes `spans` centred on row `y`.
fn centered(buf: &mut Buffer, area: Rect, y: u16, spans: &[(String, Style)]) {
    let width: usize = spans
        .iter()
        .map(|(text, _)| Line::from(text.as_str()).width())
        .sum();
    let width = u16::try_from(width).unwrap_or(area.width).min(area.width);
    let mut x = area.x + (area.width - width) / 2;
    for (text, style) in spans {
        x = buf
            .set_stringn(x, y, text, usize::from(area.right() - x), *style)
            .0;
    }
}

/// Puts one symbol at a position that may be off the screen.
fn put(buf: &mut Buffer, area: Rect, (x, y): (i32, i32), symbol: &str, style: Style) {
    let (Ok(x), Ok(y)) = (u16::try_from(x), u16::try_from(y)) else {
        return;
    };
    if area.contains(ratatui::layout::Position::new(x, y))
        && let Some(cell) = buf.cell_mut((x, y))
    {
        cell.set_symbol(symbol).set_style(style);
    }
}

/// Without colour, everything drawn keeps its shape and loses its colour.
fn uncolor(buf: &mut Buffer, look: Look) {
    if !look.color {
        for cell in &mut buf.content {
            cell.fg = Color::Reset;
            cell.bg = Color::Reset;
        }
    }
}

/// Two layers of stars drifting left at different speeds, twinkling.
fn stars(buf: &mut Buffer, area: Rect, look: Look, ms: f32, clock: f32) {
    let fade = (ms / FADE_MS).min(1.0);
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            for (layer, speed, per_thousand) in [(0, 1.5, 20), (1, 4.0, 5)] {
                #[allow(clippy::cast_possible_truncation)]
                let drift = (clock * speed) as i32;
                let seed = hash(i32::from(x) + drift, i32::from(y), layer);
                if seed % 1000 >= per_thousand {
                    continue;
                }
                #[allow(clippy::cast_precision_loss)]
                let phase = (seed >> 10) as f32 / 1000.0;
                #[allow(clippy::cast_precision_loss)]
                let rate = 1.2 + ((seed >> 20) & 7) as f32 * 0.4;
                let twinkle = 0.65 + 0.35 * (clock * rate + phase).sin();
                let (symbol, brightness) = match layer {
                    0 => ("·", 120.0),
                    _ if seed.is_multiple_of(7) => ("✦", 235.0),
                    _ => ("•", 190.0),
                };
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let level = (brightness * twinkle * fade) as u8;
                put(
                    buf,
                    area,
                    (i32::from(x), i32::from(y)),
                    symbol,
                    Style::new().fg(starlight(look, level)),
                );
                break;
            }
        }
    }
}

/// A shooting star: across the top of the sky from the right, fast and
/// dipping a little, a gold head with a streak that thins and fades behind
/// it, once. It passes behind the station.
fn shooting_star(buf: &mut Buffer, area: Rect, look: Look, top: u16, ms: f32, meteor: &Meteor) {
    let progress = (ms - meteor.at_ms) / meteor.ms;
    if !(0.0..=1.0).contains(&progress) {
        return;
    }
    let (width, height) = (f32::from(area.width), f32::from(area.height));
    let from = (
        f32::from(area.x) + width * meteor.from,
        f32::from(area.y) + (height * 0.04).max(1.0) + meteor.drop,
    );
    let distance = width * 0.6;
    // It dips only as far as the open sky above the orbit allows, at most
    // four rows, so it never crosses the name.
    let ceiling = f32::from(top) - ORBIT.1 + 1.0;
    let dip = (ceiling - from.1).clamp(0.0, 4.0) / distance;
    let at = |back: f32| {
        let along = (progress * distance - back).max(0.0);
        #[allow(clippy::cast_possible_truncation)]
        let cell = (
            (from.0 - along).round() as i32,
            (from.1 + along * dip).round() as i32,
        );
        cell
    };
    // Bright at first, fading as it burns out.
    let burn = 1.0 - (progress - 0.7).max(0.0) / 0.3;
    for step in (1..=meteor.tail).rev() {
        let back = f32::from(step);
        if back > progress * distance {
            continue;
        }
        let strength = (1.0 - f32::from(step) / f32::from(meteor.tail + 1)) * burn;
        let symbol = match step {
            1..=3 => "━",
            4..=9 => "─",
            _ => "·",
        };
        // Pale gold by the head, deeper gold down the tail.
        let color = if look.truecolor {
            let warm = |near: f32, far: f32| {
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let value = ((far + (near - far) * strength) * strength.sqrt())
                    .round()
                    .clamp(0.0, 255.0) as u8;
                value
            };
            Color::Rgb(warm(255.0, 235.0), warm(230.0, 150.0), warm(150.0, 40.0))
        } else if strength > 0.5 {
            Color::Indexed(220)
        } else {
            Color::Indexed(136)
        };
        put(buf, area, at(back), symbol, Style::new().fg(color));
    }
    let head = if look.truecolor {
        let glow = |c: f32| {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let value = (c * burn).round().clamp(0.0, 255.0) as u8;
            value
        };
        Color::Rgb(glow(255.0), glow(244.0), glow(200.0))
    } else {
        Color::Indexed(230)
    };
    put(
        buf,
        area,
        at(0.0),
        "✦",
        Style::new().fg(head).add_modifier(Modifier::BOLD),
    );
}

/// The UFO, two rows of half blocks: a glass dome over a silver hull.
const UFO: [&str; 2] = ["  ▄▆▆▄  ", "▄██████▄"];
/// It comes in from the left, hovers, then is gone to the right, over
/// this long.
const UFO_AT_MS: f32 = 200.0;
/// The rim lights' colours: red, amber, cyan, and their 256-colour twins.
const UFO_LIGHTS: [(f32, f32, f32, u8); 3] = [
    (255.0, 80.0, 80.0, 203),
    (255.0, 220.0, 60.0, 221),
    (80.0, 230.0, 255.0, 81),
];
const UFO_MS: f32 = 1200.0;

/// A UFO: in from the left, a pause above the station with a little
/// wobble and its lights running round the rim, then off to the right far
/// faster than it came.
fn ufo(buf: &mut Buffer, area: Rect, look: Look, top: u16, ms: f32, clock: f32) {
    let progress = (ms - UFO_AT_MS) / UFO_MS;
    if !(0.0..=1.0).contains(&progress) {
        return;
    }
    let width = f32::from(area.width);
    // Arrive (eased in), hover, then leave in a dash.
    let across = if progress < 0.35 {
        let p = progress / 0.35;
        0.38 * (1.0 - (1.0 - p).powi(3))
    } else if progress < 0.75 {
        0.38 + (progress - 0.35) * 0.1
    } else {
        let p = (progress - 0.75) / 0.25;
        0.42 + p * p * 0.75
    };
    let left = f32::from(area.x) - 8.0 + across * (width + 8.0);
    let wobble = if (0.35..0.75).contains(&progress) {
        (clock * 9.0).sin().round()
    } else {
        0.0
    };
    // In the sky above the orbit, where the shooting stars go.
    let row = (f32::from(top) - ORBIT.1 - 1.5).max(f32::from(area.y) + 1.0) + wobble;
    #[allow(clippy::cast_possible_truncation)]
    let (left, row) = (left.round() as i32, row.round() as i32);
    let dome = Style::new().fg(mix(look, (140.0, 255.0, 200.0), 1.0, 121));
    let hull = Style::new().fg(mix(look, (190.0, 198.0, 212.0), 1.0, 250));
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let turn = (clock * 12.0) as usize;
    for (dy, line) in (0_i32..).zip(UFO) {
        for (dx, ch) in (0_usize..).zip(line.chars()) {
            if ch == ' ' {
                continue;
            }
            let style = if dy == 0 {
                dome
            } else if (1..=6).contains(&dx) {
                // The rim lights chase each other round.
                let (r, g, b, indexed) = UFO_LIGHTS[(dx + turn) % UFO_LIGHTS.len()];
                if (dx + turn).is_multiple_of(2) {
                    Style::new().fg(mix(look, (r, g, b), 1.0, indexed))
                } else {
                    hull
                }
            } else {
                hull
            };
            let symbol = ch.to_string();
            let dx = i32::try_from(dx).unwrap_or(0);
            put(buf, area, (left + dx, row + dy), &symbol, style);
        }
    }
}

/// True one time in `n`, from the standard library's per-process random
/// keys, which is plenty for deciding whether a star falls.
fn one_in(n: u32) -> bool {
    use std::hash::{BuildHasher as _, Hasher as _};
    if n <= 1 {
        return true;
    }
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
    );
    hasher.finish().is_multiple_of(u64::from(n))
}

/// The planet's edge, rising from below, with the lights of data centres
/// on its night side.
fn planet(buf: &mut Buffer, area: Rect, look: Look, top: u16, ms: f32, clock: f32) {
    let rise = 1.0 - (1.0 - (ms / RISE_MS).min(1.0)).powi(3);
    let horizon = f32::from(top) + 13.0 + (1.0 - rise) * 6.0;
    let middle = f32::from(area.x) + f32::from(area.width) / 2.0;
    let half = f32::from(area.width) / 2.0;
    for x in area.left()..area.right() {
        let across = (f32::from(x) + 0.5 - middle) / half;
        #[allow(clippy::cast_possible_truncation)]
        let edge = (horizon + across * across * 5.0).floor() as i32;
        let glow = 1.0 - across.abs() * 0.5;
        for y in edge.max(i32::from(area.y))..i32::from(area.bottom()) {
            let depth = y - edge;
            let at = (i32::from(x), y);
            if depth == 0 {
                put(
                    buf,
                    area,
                    at,
                    "▁",
                    Style::new().fg(mix(look, (40.0, 150.0, 255.0), glow, 39)),
                );
                continue;
            }
            #[allow(clippy::cast_precision_loss)]
            let shade = (1.0 - depth as f32 * 0.12).max(0.35);
            let ground = Style::new().bg(mix(look, (8.0, 22.0, 58.0), shade, 17));
            let seed = hash(i32::from(x), y, 7);
            #[allow(clippy::cast_precision_loss)]
            let blink = (clock * 1.7 + (seed >> 8) as f32 / 97.0).sin() > -0.4;
            if depth >= 1 && seed % 100 < 5 && rise > 0.5 && blink {
                let light = if seed.is_multiple_of(3) {
                    mix(look, (90.0, 220.0, 255.0), 1.0, 81)
                } else {
                    mix(look, (255.0, 185.0, 80.0), 1.0, 214)
                };
                put(buf, area, at, "·", ground.fg(light));
            } else {
                put(buf, area, at, " ", ground);
            }
        }
    }
}

/// The orbit around the name, traced once, then three satellites going
/// round it with trails of data behind them.
fn orbit(buf: &mut Buffer, area: Rect, look: Look, centre: (f32, f32), ms: f32, clock: f32) {
    let at = |angle: f32| {
        #[allow(clippy::cast_possible_truncation)]
        let point = (
            (centre.0 + ORBIT.0 * angle.cos()).round() as i32,
            (centre.1 + ORBIT.1 * angle.sin()).round() as i32,
        );
        point
    };
    let traced = (ms / ORBIT_MS).min(1.0) * TAU;
    let path = Style::new().fg(mix(look, (55.0, 80.0, 125.0), 1.0, 60));
    for step in 0..240_u16 {
        let angle = f32::from(step) / 240.0 * TAU;
        if angle > traced {
            break;
        }
        put(buf, area, at(angle - FRAC_PI_2), "·", path);
    }
    if ms < ORBIT_MS * 0.6 {
        return;
    }
    for satellite in 0..3_u8 {
        let angle = clock * 0.8 + f32::from(satellite) * TAU / 3.0;
        for trail in (1..=6_u8).rev() {
            let strength = 1.0 - f32::from(trail) / 7.0;
            put(
                buf,
                area,
                at(angle - f32::from(trail) * 0.045),
                "•",
                Style::new().fg(mix(
                    look,
                    (0.0, 229.0, 255.0),
                    strength,
                    if strength > 0.5 { 45 } else { 24 },
                )),
            );
        }
        put(
            buf,
            area,
            at(angle),
            "◆",
            Style::new()
                .fg(mix(look, (210.0, 250.0, 255.0), 1.0, 195))
                .add_modifier(Modifier::BOLD),
        );
    }
}

/// The mark, assembling on the same front as the letters, ahead of them.
fn draw_mark(
    buf: &mut Buffer,
    look: Look,
    mark: &[Vec<ratatui::text::Span<'static>>],
    left: u16,
    top: u16,
    lead: u16,
    ms: f32,
) {
    let glow = Style::new().fg(mix(look, (200.0, 250.0, 255.0), 1.0, 159));
    for (row, spans) in (0_u16..).zip(mark) {
        for (col, span) in (0_u16..).zip(spans) {
            let behind = front(ms, row, lead) - f32::from(col);
            // A space with no colour behind it is where the mark is empty.
            if behind < 0.0 || (span.content == " " && span.style.bg.is_none()) {
                continue;
            }
            let Some(cell) = buf.cell_mut((left + col, top + row)) else {
                continue;
            };
            cell.reset();
            if behind < 2.0 {
                cell.set_symbol("▓").set_style(glow);
            } else {
                cell.set_symbol(&span.content).set_style(span.style);
            }
        }
    }
}

/// Where the assembling front is, `ms` in, on `row`, counted in columns
/// from the left of whatever is drawn -- the mark, when there is one, and
/// then the letters. Lower rows run a little behind; by the end of the
/// reveal it is past everything.
fn front(ms: f32, row: u16, lead: u16) -> f32 {
    let span = f32::from(LOGO_WIDTH + lead);
    (ms / REVEAL_MS).min(1.0) * (span + 14.0) - 4.0 - f32::from(row) * 1.2
}

/// The name, assembling itself from bits, left to right.
fn logo(buf: &mut Buffer, look: Look, left: u16, top: u16, lead: u16, ms: f32) {
    for (row, text) in (0_u16..).zip(LOGO) {
        for (col, ch) in (0_u16..).zip(text.chars()) {
            let Some(cell) = buf.cell_mut((left + col, top + row)) else {
                continue;
            };
            let Some((symbol, style)) = letter(look, row, col, ch, ms, lead) else {
                continue;
            };
            cell.reset();
            cell.set_symbol(&symbol).set_style(style);
        }
    }
}

/// One character of the logo, `ms` milliseconds in, or nothing while the
/// assembling front has not reached it.
fn letter(look: Look, row: u16, col: u16, ch: char, ms: f32, lead: u16) -> Option<(String, Style)> {
    let behind = front(ms, row, lead) - f32::from(lead + col);
    let (row, col) = (f32::from(row), f32::from(col));
    let width = f32::from(LOGO_WIDTH);
    if behind < 0.0 {
        return None;
    }
    if ch == ' ' {
        return Some((" ".to_owned(), Style::new()));
    }
    if behind < 3.0 {
        let glow = Style::new().fg(mix(look, (200.0, 250.0, 255.0), 1.0, 159));
        if behind < 1.6 {
            // Bits, changing every few frames.
            #[allow(clippy::cast_possible_truncation)]
            let seed = hash(col as i32, row as i32, (ms / 45.0) as i32);
            let bit = if seed & 1 == 0 { "0" } else { "1" };
            return Some((bit.to_owned(), glow));
        }
        return Some(("▓".to_owned(), glow));
    }

    let solid = ch == '█';
    // A band of light crosses the letters, on a slant, after the reveal.
    let band = ((ms - REVEAL_MS) / SHIMMER_MS).clamp(0.0, 1.0) * (width + 26.0) - 8.0;
    let light = if ms > REVEAL_MS && ms < REVEAL_MS + SHIMMER_MS && solid {
        (1.0 - ((col + row * 2.0) - band).abs() / 3.0).max(0.0)
    } else {
        0.0
    };
    // White faces with grey shadows; the band of light tints them cyan as
    // it passes.
    let color = if look.truecolor {
        let base = if solid {
            (245.0, 247.0, 250.0)
        } else {
            (72.0, 76.0, 90.0)
        };
        let tint = (110.0, 225.0, 255.0);
        let blend = |from: f32, to: f32| {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let value = (from + (to - from) * light).round().clamp(0.0, 255.0) as u8;
            value
        };
        Color::Rgb(
            blend(base.0, tint.0),
            blend(base.1, tint.1),
            blend(base.2, tint.2),
        )
    } else if light > 0.3 {
        Color::Indexed(159)
    } else if solid {
        Color::Indexed(255)
    } else {
        Color::Indexed(239)
    };
    Some((ch.to_string(), Style::new().fg(color)))
}

/// The tagline types itself out, then the version appears beside it. It is
/// placed where the whole line will sit, so it grows rightwards instead of
/// shifting as it types.
fn tagline(buf: &mut Buffer, area: Rect, look: Look, words: &Words<'_>, y: u16, ms: f32) {
    let width = |text: &str| Line::from(text).width();
    // The version only where there is room for it as well.
    let version = Some(format!("  v{}", env!("CARGO_PKG_VERSION")))
        .filter(|v| width(words.tagline) + width(v) <= usize::from(area.width))
        .unwrap_or_default();
    let full = width(&format!("{}{version}", words.tagline));
    let full = u16::try_from(full).unwrap_or(area.width).min(area.width);
    let mut x = area.x + (area.width - full) / 2;
    let total = words.tagline.chars().count();
    // A long tagline types faster, so the whole of it is out by the time
    // the band of light has crossed the letters.
    #[allow(clippy::cast_precision_loss)]
    let per_char =
        TAGLINE_CHAR_MS.min((REVEAL_MS + SHIMMER_MS - TAGLINE_AT_MS) / total.max(1) as f32);
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let typed = (((ms - TAGLINE_AT_MS) / per_char).max(0.0) as usize).min(total);
    let shown: String = words.tagline.chars().take(typed).collect();
    let room = |x: u16| usize::from(area.right().saturating_sub(x));
    x = buf
        .set_stringn(x, y, &shown, room(x), Style::new().fg(gray(look, 230)))
        .0;
    if typed < total {
        if ms >= TAGLINE_AT_MS {
            buf.set_stringn(x, y, "▌", room(x), Style::new().fg(Color::Cyan));
        }
    } else {
        buf.set_stringn(x, y, &version, room(x), Style::new().fg(gray(look, 110)));
    }
}

/// A row of rack lights under the name, coming on one by one, then
/// flickering with traffic.
fn rack(buf: &mut Buffer, area: Rect, look: Look, left: u16, y: u16, ms: f32, clock: f32) {
    // The rack's own row: the orbit passes behind it, not through it.
    for x in left..(left + LOGO_WIDTH).min(area.right()) {
        if let Some(cell) = buf.cell_mut((x, y)) {
            cell.reset();
        }
    }
    for light in 0..RACK_LIGHTS {
        if ms < RACK_AT_MS + f32::from(light) * RACK_LIGHT_MS {
            continue;
        }
        let period = 0.16 + f32::from(light % 5) * 0.07;
        #[allow(clippy::cast_possible_truncation)]
        let state = hash(i32::from(light), (clock / period) as i32, 3) % 6;
        let color = match state {
            0 => gray(look, 60),
            1..=3 => mix(look, (70.0, 230.0, 140.0), 1.0, 42),
            4 => mix(look, (0.0, 200.0, 255.0), 1.0, 45),
            _ => mix(look, (255.0, 180.0, 60.0), 1.0, 214),
        };
        put(
            buf,
            area,
            (i32::from(left + 1 + light * 2), i32::from(y)),
            "▪",
            Style::new().fg(color),
        );
    }
}

/// `rgb` scaled by `strength`, or `indexed` on a 256-colour terminal.
fn mix(look: Look, (r, g, b): (f32, f32, f32), strength: f32, indexed: u8) -> Color {
    if look.truecolor {
        let scale = |c: f32| {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let v = (c * strength).round().clamp(0.0, 255.0) as u8;
            v
        };
        Color::Rgb(scale(r), scale(g), scale(b))
    } else {
        Color::Indexed(indexed)
    }
}

/// A grey of this brightness, from the 24 greys on a 256-colour terminal.
fn gray(look: Look, level: u8) -> Color {
    if look.truecolor {
        Color::Rgb(level, level, level)
    } else {
        Color::Indexed(232 + level / 11)
    }
}

/// Starlight: grey with a little blue in it.
fn starlight(look: Look, level: u8) -> Color {
    if look.truecolor {
        Color::Rgb(
            level.saturating_sub(15),
            level.saturating_sub(5),
            level.saturating_add(10),
        )
    } else {
        Color::Indexed(232 + level / 11)
    }
}

/// A well-mixed number from a position, so the sky looks random but is
/// the same every time it is drawn.
fn hash(a: i32, b: i32, c: i32) -> u32 {
    let mut h = a.cast_unsigned().wrapping_mul(0x9E37_79B1)
        ^ b.cast_unsigned().wrapping_mul(0x85EB_CA77)
        ^ c.cast_unsigned().wrapping_mul(0xC2B2_AE3D);
    h ^= h >> 15;
    h = h.wrapping_mul(0x2C1B_3C6D);
    h ^= h >> 12;
    h
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::{END, LOGO, Sky, Status, Words, draw};
    use crate::tui::Look;

    const WORDS: Words<'static> = Words {
        tagline: "Building the Financial Internet for the Agentic Era.",
        connecting: "connecting",
        signed_in: "signed in as",
    };
    const LOOK: Look = Look {
        color: true,
        truecolor: true,
        animate: true,
    };

    fn screen(width: u16, height: u16, moment: Duration, status: Status<'_>) -> String {
        screen_saying(&WORDS, width, height, moment, status)
    }

    fn screen_saying(
        words: &Words<'_>,
        width: u16,
        height: u16,
        moment: Duration,
        status: Status<'_>,
    ) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("test terminal");
        terminal
            .draw(|f| draw(f, LOOK, words, moment, moment, status, Sky::Clear))
            .expect("draw");
        let buffer = terminal.backend().buffer();
        buffer
            .content
            .chunks(usize::from(buffer.area.width))
            .map(|row| {
                row.iter()
                    .map(ratatui::buffer::Cell::symbol)
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_last_moment_shows_the_whole_name_the_tagline_and_the_account() {
        let shown = screen(100, 30, END, Status::SignedIn("alice@example.com"));
        for row in LOGO {
            assert!(shown.contains(row), "{row}\n{shown}");
        }
        assert!(
            shown.contains("Building the Financial Internet for the Agentic Era."),
            "{shown}"
        );
        assert!(shown.contains("signed in as alice@example.com"), "{shown}");
        assert!(shown.contains('◆'), "the satellites are out\n{shown}");
    }

    #[test]
    fn a_long_tagline_is_typed_out_by_the_time_the_light_has_crossed() {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let crossed = Duration::from_millis((super::REVEAL_MS + super::SHIMMER_MS) as u64);
        let shown = screen(100, 30, crossed, Status::Connecting);
        assert!(shown.contains(WORDS.tagline), "{shown}");
    }

    #[test]
    fn a_narrow_terminal_keeps_the_tagline_whole_and_leaves_out_the_version() {
        let shown = screen(56, 14, END, Status::Connecting);
        assert!(shown.contains(WORDS.tagline), "{shown}");
        let cut_short = format!("{}  v", WORDS.tagline);
        assert!(!shown.contains(&cut_short), "{shown}");
    }

    #[test]
    fn the_splash_draws_in_chinese_and_russian() {
        use crate::i18n::speaking;
        use erpc_core::i18n::Lang;
        for lang in [Lang::Zh, Lang::Ru] {
            let (tagline, connecting, signed_in) = speaking(lang, || {
                (
                    t!("ai.splash.tagline"),
                    t!("ai.splash.connecting"),
                    t!("ai.splash.signed_in"),
                )
            });
            let words = Words {
                tagline: &tagline,
                connecting: &connecting,
                signed_in: &signed_in,
            };
            // A wide character's second cell is drawn as a space.
            let squeezed = |text: &str| text.replace(' ', "");
            for (width, height) in [(100, 30), (56, 14)] {
                let shown = screen_saying(&words, width, height, END, Status::Connecting);
                for row in LOGO {
                    assert!(shown.contains(row), "{lang:?} {width}\n{shown}");
                }
                let rows: Vec<String> = shown.lines().map(squeezed).collect();
                assert!(
                    rows.iter().any(|r| r.contains(&squeezed(&tagline))),
                    "{lang:?} {width}: the tagline is whole\n{shown}"
                );
                assert!(
                    rows.iter().any(|r| r.contains(&squeezed(&connecting))),
                    "{shown}"
                );
                for row in shown.lines() {
                    assert_eq!(row.chars().count(), usize::from(width), "{row}");
                }
            }
            let shown = screen_saying(&words, 100, 30, END, Status::SignedIn("alice@example.com"));
            assert!(
                squeezed(&shown).contains(&squeezed(&format!("{signed_in} alice@example.com"))),
                "{shown}"
            );
        }
    }

    #[test]
    fn the_first_moment_shows_no_letters_yet() {
        let shown = screen(100, 30, Duration::ZERO, Status::Connecting);
        assert!(!shown.contains('█'), "{shown}");
        assert!(shown.contains("connecting"), "{shown}");
    }

    #[test]
    fn halfway_through_the_left_is_drawn_and_the_right_is_not() {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let halfway = Duration::from_millis((super::REVEAL_MS / 2.0) as u64);
        let shown = screen(100, 30, halfway, Status::Connecting);
        let first = shown
            .lines()
            .find(|l| l.contains('█'))
            .expect("some letters");
        assert!(!first.contains(LOGO[0]), "{first}");
    }

    #[test]
    fn a_medium_terminal_has_the_name_without_the_orbit() {
        let shown = screen(50, 14, END, Status::Connecting);
        assert!(shown.contains(LOGO[0]), "{shown}");
        assert!(!shown.contains('◆'), "{shown}");
    }

    #[test]
    fn a_small_terminal_gets_the_name_and_the_status() {
        let shown = screen(30, 6, END, Status::Connecting);
        assert!(
            shown.contains("ERPC") && shown.contains("connecting"),
            "{shown}"
        );
        assert!(!shown.contains('█'), "{shown}");
    }

    #[test]
    fn a_shooting_star_crosses_the_sky_while_it_falls_and_is_gone_after() {
        let words = &WORDS;
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("test terminal");
        let star_count = |terminal: &Terminal<TestBackend>| {
            terminal
                .backend()
                .buffer()
                .content
                .iter()
                .filter(|c| {
                    c.symbol() == "✦" && c.modifier.contains(ratatui::style::Modifier::BOLD)
                })
                .count()
        };
        let falling = Duration::from_millis(450);
        terminal
            .draw(|f| {
                draw(
                    f,
                    LOOK,
                    words,
                    falling,
                    falling,
                    Status::Connecting,
                    Sky::Star,
                );
            })
            .expect("draw");
        assert_eq!(star_count(&terminal), 1, "the head is drawn while it falls");
        terminal
            .draw(|f| {
                draw(
                    f,
                    LOOK,
                    words,
                    falling,
                    falling,
                    Status::Connecting,
                    Sky::Clear,
                );
            })
            .expect("draw");
        assert_eq!(star_count(&terminal), 0, "no star when none falls");
        terminal
            .draw(|f| draw(f, LOOK, words, END, END, Status::Connecting, Sky::Star))
            .expect("draw");
        assert_eq!(star_count(&terminal), 0, "gone by the end");
    }

    #[test]
    fn a_shower_has_several_stars_in_the_sky_at_once() {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("test terminal");
        let moment = Duration::from_millis(520);
        terminal
            .draw(|f| {
                draw(
                    f,
                    LOOK,
                    &WORDS,
                    moment,
                    moment,
                    Status::Connecting,
                    Sky::Shower,
                );
            })
            .expect("draw");
        let heads = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .filter(|c| c.symbol() == "✦" && c.modifier.contains(ratatui::style::Modifier::BOLD))
            .count();
        assert!(heads >= 3, "{heads} heads");
    }

    #[test]
    fn a_shower_is_rarer_than_a_single_star() {
        const { assert!(super::SHOWER_ONE_IN > super::SHOOTING_STAR_ONE_IN) };
        const { assert!(super::UFO_ONE_IN > super::SHOWER_ONE_IN) };
        let still = Look {
            animate: false,
            ..LOOK
        };
        assert_eq!(Sky::roll(still), Sky::Clear);
    }

    #[test]
    fn a_ufo_hovers_over_the_station_and_is_gone_by_the_end() {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).expect("test terminal");
        let hull = |terminal: &Terminal<TestBackend>| {
            terminal.backend().buffer().content.chunks(100).any(|row| {
                row.iter()
                    .map(ratatui::buffer::Cell::symbol)
                    .collect::<String>()
                    .contains("▄██████▄")
            })
        };
        let hovering = Duration::from_millis(800);
        terminal
            .draw(|f| {
                draw(
                    f,
                    LOOK,
                    &WORDS,
                    hovering,
                    hovering,
                    Status::Connecting,
                    Sky::Ufo,
                );
            })
            .expect("draw");
        assert!(hull(&terminal), "the UFO is in the sky while it hovers");
        terminal
            .draw(|f| draw(f, LOOK, &WORDS, END, END, Status::Connecting, Sky::Ufo))
            .expect("draw");
        assert!(!hull(&terminal), "and gone by the end");
    }
}
