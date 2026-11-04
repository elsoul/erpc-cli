// SPDX-FileCopyrightText: 2026 ELSOUL LABO B.V.
// SPDX-License-Identifier: Apache-2.0

//! Where a monthly or yearly card subscription is bought: the dashboard.
//!
//! user-api makes the dashboard's checkout as a session embedded in the
//! dashboard's own page, so erpc has no payment link of its own to hand
//! over. What it can do is open the dashboard where the product is
//! bought. The page is fixed here, never taken from the model, so the
//! tool cannot be made to open anything else.

use erpc_core::i18n::Lang;
use serde_json::{Value, json};

/// Opens a page in the person's browser, or says why it did not.
pub trait Browser {
    /// Opens `url`.
    ///
    /// # Errors
    ///
    /// Returns why no browser was opened: an SSH session, no display, or
    /// the opener failing.
    fn open(&self, url: &str) -> Result<(), String>;
}

/// The dashboard's home, where products are bought, in `lang`. The
/// dashboard has a page in every language erpc speaks.
#[must_use]
pub fn home_url(lang: Lang) -> String {
    format!("https://dashboard.erpc.global/{}/user", lang.code())
}

/// `open_dashboard`: opens the dashboard's home in the browser and
/// returns its address, so the model can give the link when no browser
/// opened.
#[must_use]
pub fn open_dashboard(browser: Option<&dyn Browser>) -> Value {
    let url = home_url(crate::i18n::lang());
    let opened = browser.map_or_else(
        || Err("this run opens no browser: no one is at a terminal to see it".to_owned()),
        |b| b.open(&url),
    );
    match opened {
        Ok(()) => json!({ "url": url, "opened": true }),
        Err(why) => json!({ "url": url, "opened": false, "notOpenedBecause": why }),
    }
}

/// The address in an `open_dashboard` result that did not open, for the
/// front end to show itself: the link the person sees is then the one erpc
/// built, not only the model's words. Only an address [`home_url`] makes
/// is given back, so no other tool's result can put a link there.
#[must_use]
pub fn unopened(content: &str) -> Option<String> {
    let value: Value = serde_json::from_str(content).ok()?;
    if value.get("opened")? != &Value::Bool(false) {
        return None;
    }
    let url = value.get("url")?.as_str()?;
    Lang::ALL.into_iter().map(home_url).find(|home| home == url)
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use erpc_core::i18n::Lang;

    use super::{Browser, home_url, open_dashboard, unopened};

    /// Records what it was asked to open; refuses when `refuse` is set.
    #[derive(Default)]
    struct Recorded {
        opened: RefCell<Vec<String>>,
        refuse: Option<&'static str>,
    }

    impl Browser for Recorded {
        fn open(&self, url: &str) -> Result<(), String> {
            self.opened.borrow_mut().push(url.to_owned());
            self.refuse.map_or(Ok(()), |why| Err(why.to_owned()))
        }
    }

    #[test]
    fn the_home_is_on_the_dashboard_in_the_persons_language() {
        assert_eq!(home_url(Lang::En), "https://dashboard.erpc.global/en/user");
        assert_eq!(home_url(Lang::Ja), "https://dashboard.erpc.global/ja/user");
        for lang in Lang::ALL {
            let url = home_url(lang);
            erpc_core::endpoints::ensure_service_url(&url).expect("a declared host");
        }
    }

    #[test]
    fn the_dashboard_is_opened_and_its_address_returned() {
        let browser = Recorded::default();
        let out = crate::i18n::speaking(Lang::Ja, || open_dashboard(Some(&browser)));
        assert_eq!(out["opened"], true);
        assert_eq!(out["url"], "https://dashboard.erpc.global/ja/user");
        assert_eq!(
            *browser.opened.borrow(),
            ["https://dashboard.erpc.global/ja/user"]
        );
    }

    #[test]
    fn without_a_browser_the_address_is_still_given_with_the_reason() {
        let browser = Recorded {
            refuse: Some("this is an SSH session"),
            ..Recorded::default()
        };
        let out = open_dashboard(Some(&browser));
        assert_eq!(out["opened"], false);
        assert_eq!(out["url"], "https://dashboard.erpc.global/en/user");
        assert_eq!(out["notOpenedBecause"], "this is an SSH session");

        let out = open_dashboard(None);
        assert_eq!(out["opened"], false);
        assert_eq!(out["url"], "https://dashboard.erpc.global/en/user");
    }

    #[test]
    fn only_an_unopened_dashboard_address_is_shown_by_the_front_end() {
        let refused = Recorded {
            refuse: Some("no display"),
            ..Recorded::default()
        };
        let not_opened = crate::i18n::speaking(Lang::Ru, || open_dashboard(Some(&refused)));
        assert_eq!(
            unopened(&not_opened.to_string()).as_deref(),
            Some("https://dashboard.erpc.global/ru/user")
        );

        let opened = open_dashboard(Some(&Recorded::default()));
        assert_eq!(unopened(&opened.to_string()), None);
        // Another address, or anything but such a result, is not shown.
        assert_eq!(
            unopened(r#"{"opened":false,"url":"https://dashboard.erpc.global/en/user/billing"}"#),
            None
        );
        // The scheme apart, so the endpoint gate does not read a host.
        let elsewhere = format!(
            r#"{{"opened":false,"url":"{}evil.example/en/user"}}"#,
            "https://"
        );
        assert_eq!(unopened(&elsewhere), None);
        assert_eq!(unopened("not json"), None);
        assert_eq!(
            unopened(r#"{"url":"https://dashboard.erpc.global/en/user"}"#),
            None
        );
    }
}
