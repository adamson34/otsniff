# ADR-0003: askama templating with pre-formatted view structs

## Status
Accepted

## Context
The HTML report needs templating. Options:
1. `askama` — compile-time templates, type-checked
2. `tera` — runtime Jinja-style templates
3. `minijinja` — runtime, smaller surface than tera
4. `format!` / `write!` directly — no template engine

We also needed to decide where to do formatting work (severity → CSS class,
byte → human string, role enum → label): in the template via custom
filters, or in Rust before passing data in.

## Decision
Use `askama` (option 1) with **pre-formatted view structs**. All formatting
is done in Rust; templates do plain substitution and HTML escaping only.

## Rationale
- askama gives us compile-time guarantees: missing fields, typos in field
  names, and missing escape hooks all surface at `cargo build` rather
  than at report-render time.
- Custom askama filters are namespace-fragile (the lookup mechanism has
  changed across askama versions and is implementation-defined). The
  first iteration of the report used `mod filters` and ran into resolution
  issues; pre-formatting in Rust sidestepped the entire category of bug.
- Templates remain trivial — the only logic is `{% for %}` and `{% if %}`.
- Snapshot testing the report output (see ADR-0004) is straightforward
  because the view structs are deterministic.

## Consequences
- Adding a new field to a section requires touching three places: the
  view struct, the population code in `render_html`, and the template.
  Acceptable for a single template; would be painful with many.
- The template itself is dumb HTML, easy to hand off to a designer if
  we ever want a visual refresh.

## Alternatives considered
- **`format!` directly** — rejected: HTML escaping by hand is error-prone,
  and the sections (findings, inventory, top flows) would become a
  maintenance hazard.
- **`tera` runtime** — rejected: runtime errors instead of compile-time,
  and we don't need template hot-reload.
