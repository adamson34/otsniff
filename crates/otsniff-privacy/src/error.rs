//! Error type for the `otsniff-privacy` crate.

#[derive(thiserror::Error, Debug)]
pub enum PrivacyError {
    /// The fail-closed leak detector caught a real value that reached (or
    /// was about to reach) an AI provider. `message` is redacted before
    /// construction (see `leak_detector::ensure_clean`) so it never carries
    /// the raw leaked value.
    #[error("{kind}: {message}")]
    Leak { kind: String, message: String },

    /// A `ScrubMap`'s internal structure is corrupted -- empty pseudonym or
    /// real value, a non-canonically-shaped pseudonym, a duplicate real
    /// value across pseudonyms (`ScrubMap::validate`), or a pseudonym
    /// collision while merging a baseline map (`merge_family`). This is a
    /// distinct error class from `Leak`: it is a structural/data-integrity
    /// fault in a map loaded from disk, not a privacy-invariant trip, and
    /// callers (otsniff's `OtError`) route it to a different exit code /
    /// message shape than `Leak` (F-ADV: a corrupted-map message that
    /// interpolates a raw value must never be labeled "privacy invariant
    /// tripped").
    #[error("{message}")]
    MapCorrupt { kind: String, message: String },
}
