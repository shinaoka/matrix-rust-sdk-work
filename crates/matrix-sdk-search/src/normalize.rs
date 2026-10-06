// Copyright 2026 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Search text normalization, shared by indexing and querying.
//!
//! The client verifies matches with the same normalization applied to both the
//! body and the query, so the persistent index must enumerate candidates for
//! normalization-equivalent text, not only for byte-identical text.

use unicode_casefold::{Locale, UnicodeCaseFold, Variant};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

/// Normalize searchable text: NFKC, full case folding, and dash unification.
///
/// Normalization is applied per grapheme, exactly like the desktop client's
/// verifier, so a multi-grapheme sequence is never composed across a grapheme
/// boundary (which would make the indexed text and the verified text disagree).
pub(crate) fn normalize_search_text(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    for grapheme in value.graphemes(true) {
        for ch in grapheme.nfkc().case_fold_with(Variant::Full, Locale::NonTurkic) {
            normalized.push(match ch {
                '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}'
                | '\u{2212}' | '\u{fe58}' | '\u{ff0d}' => '-',
                other => other,
            });
        }
    }
    normalized
}
