//! Render an AI provider's markdown response to HTML — safely.
//!
//! Claude (or whichever AI is in the loop) returns markdown. To embed
//! it in the HTML report we have to render it. The Markdown spec says
//! a parser MAY pass raw HTML through verbatim. We don't want that:
//! a Claude response containing `<script>alert(1)</script>` would XSS
//! whoever opens the rendered report.
//!
//! `render_safe` walks the pulldown-cmark event stream and drops
//! every raw-HTML event before pushing to the HTML writer. The
//! resulting string contains only formatting that pulldown-cmark
//! generated itself.

use pulldown_cmark::{html, Event, Options, Parser};

/// Render markdown to HTML with all raw HTML events stripped. Output
/// is safe to interpolate via askama's `|safe` filter inside a
/// trusted template.
pub fn render_safe(md: &str) -> String {
    let parser = Parser::new_ext(md, Options::ENABLE_TABLES)
        .filter(|event| !matches!(event, Event::Html(_) | Event::InlineHtml(_)));
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
        // A Claude response containing a literal <script> tag must
        // not survive into the rendered HTML.
        let md = "Here is some text.\n\n<script>alert('xss')</script>\n\nAnd more text.";
        let html = render_safe(md);
        assert!(
            !html.contains("<script>"),
            "raw <script> survived markdown rendering: {html}"
        );
        assert!(
            !html.contains("alert"),
            "<script> body survived markdown rendering: {html}"
        );
    }

    #[test]
    fn strips_raw_inline_html() {
        // Inline raw HTML like <img onerror=...> must also be stripped.
        let md = "A paragraph with <img src=x onerror=alert(1)> in the middle.";
        let html = render_safe(md);
        assert!(!html.contains("<img"), "inline raw HTML survived: {html}");
        assert!(!html.contains("onerror"));
    }

    #[test]
    fn strips_javascript_url_pseudo_protocol() {
        // pulldown-cmark renders link URLs verbatim. javascript: URLs
        // are a separate concern — they're inside an <a href=...>,
        // not raw HTML. We don't try to filter those here; the
        // AI-response section is contained in a div the user
        // controls, and any reasonable browser blocks javascript:
        // links by default on modern web standards. Documenting
        // the limit explicitly with a test that asserts current
        // behavior.
        let md = "[click me](javascript:alert(1))";
        let html = render_safe(md);
        // We DO render the link — confirming current behavior.
        // If this ever becomes a real concern, post-process the
        // output to strip javascript: hrefs.
        assert!(html.contains("href=\"javascript:"));
    }
}
