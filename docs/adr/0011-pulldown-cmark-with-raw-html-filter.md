# ADR-0011: pulldown-cmark with raw-HTML event filter for AI markdown

## Status
Accepted (v0.3)

## Context
The `analyze --ai` path (ADR-0007) gets a markdown-formatted text
response back from the `claude -p` subprocess and embeds it in the HTML
report as an "AI analysis" section. The naive implementation would do:

```rust
let html = format!("<div class=\"ai-content\">{response}</div>");
```

This is unsafe. The `claude` process is a local binary the user trusts
to run, but its *output* is text that originated from an AI model.
An adversarially crafted PCAP — one that causes the model to include
inline HTML in its response — could inject:

- `<script>alert(document.cookie)</script>` — stored XSS in the report
- `<iframe src="...">` — exfiltration via side-channel
- `<img onerror="...">` — JavaScript execution in older browsers
- `<style>` overrides — visual deception

Because the HTML report is a self-contained file that users save and
share (including emailing to asset owners, opening in corporate browsers),
a stored XSS payload in the report would survive beyond the otsniff
session.

Three approaches:

1. **Naive: embed response as-is** — trivially unsafe; XSS via AI
   response payload is a realistic attack vector given prompt injection
   in PCAP payloads.

2. **HTML-escape the whole response** — safe against XSS, but converts
   the AI's markdown to literal text (`**bold**`, `# Header`, etc.)
   rather than rendering it. Ugly and unreadable for the user.

3. **Parse as markdown, strip raw-HTML events, render safe HTML** —
   renders the AI's intended formatting while eliminating the injection
   vector. Markdown nodes (bold, headers, code blocks, lists) render
   correctly; any literal HTML in the response is stripped before rendering.

## Decision
Use `pulldown-cmark` to parse the AI response as a Markdown event
stream, filter out all `Event::Html` (raw HTML) events, then render
the remaining events to HTML. This is implemented in
`src/ai/html_render.rs::render_safe`.

```rust
pub fn render_safe(markdown: &str) -> String {
    let parser = pulldown_cmark::Parser::new(markdown);
    let safe_events = parser.filter(|event| {
        !matches!(event, pulldown_cmark::Event::Html(_))
    });
    let mut html_output = String::new();
    pulldown_cmark::html::push_html(&mut html_output, safe_events);
    html_output
}
```

## Rationale

- **Defense in depth.** The leak detector (ADR-0007) already blocks
  un-scrubbed PCAPs from reaching the AI; `render_safe` blocks any
  AI-originated HTML from reaching the report. Two independent layers,
  different threat models.
- **Markdown intent preserved.** Headings, bold, code blocks, lists,
  and blockquotes all render correctly. The AI can produce well-structured
  analysis and the user sees formatted output.
- **No custom HTML needed.** The system prompt explicitly asks Claude to
  produce pure markdown. Users who extend the prompt should follow the
  same guidance. If a user overrides the prompt and Claude returns a
  `<details>` block, it is silently dropped — acceptable trade-off for
  safety.
- **Minimal dependency.** `pulldown-cmark` is already in the dependency
  tree (the markdown report renderer uses it). No new crate is needed.

## Threat model

The adversary is a specially crafted PCAP that, when analysed, causes
the AI model to include raw HTML in its response. This is a prompt
injection attack: PCAP payload bytes → observation text → AI prompt →
AI response containing HTML → rendered in the report. The attack is
low-sophistication: an operator can plant `<script>` tags in Modbus
payload bytes with minimal effort.

`render_safe` breaks the final step of this chain regardless of what
the AI model says. The constraint is enforced at render time, not at
prompt-engineering time.

## Sentinel test

`tests/snapshot.rs::ai_response_with_html_tags_does_not_emit_raw_html`
passes a string containing `<script>alert('xss')</script>` and several
other raw-HTML patterns through `render_safe` and asserts that the
output contains no `<script`, `<iframe`, `<img`, or `<style` substrings.
This test must pass on every commit that touches `html_render.rs` or the
AI render path.

## Alternatives considered

- **Custom HTML sanitiser (ammonia crate)** — would allow safe subset
  of HTML tags (e.g., `<em>`, `<strong>`) through. Rejected: adds a
  dependency with its own allowlist maintenance burden; the Claude model
  generates clean markdown when asked, so we don't need to pass any HTML
  through.
- **Content Security Policy header** — not applicable to a saved HTML
  file; CSP requires a server to set the header. The report is a static
  file.
- **Sandboxed iframe for AI section** — would isolate the AI content
  from the rest of the report DOM. Complex, breaks the self-contained
  design goal, and still requires blocking script execution within the
  sandbox.

## Consequences

- AI responses containing literal HTML (e.g., a `<details>` block for
  a collapsible section) are stripped silently. The system prompt should
  guide Claude to produce pure markdown.
- `render_safe` is the canonical entry point for any markdown-to-HTML
  conversion in the AI path. Future features that embed AI text in the
  report must use it, not a raw `pulldown_cmark::html::push_html` call.
- The sentinel test is a load-bearing safety test; removing or weakening
  it is an ADR-grade change.
