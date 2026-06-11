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

use serde::{Deserialize, Serialize};

/// Configuration for a Matrix search index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchIndexConfig {
    /// The tokenizer to use for message body text.
    #[serde(default)]
    pub tokenizer: SearchTokenizer,
}

impl SearchIndexConfig {
    /// Create a search index configuration with Tantivy's default text tokenizer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a search index configuration with an ngram tokenizer.
    pub fn ngram(min_gram: usize, max_gram: usize) -> Self {
        Self { tokenizer: SearchTokenizer::ngram(min_gram, max_gram) }
    }

    pub(crate) fn body_tokenizer_name(&self) -> String {
        self.tokenizer.name()
    }

    pub(crate) fn ngram_tokenizer(&self) -> Option<(String, usize, usize)> {
        self.tokenizer
            .ngram_bounds()
            .map(|(min_gram, max_gram)| (self.body_tokenizer_name(), min_gram, max_gram))
    }
}

impl Default for SearchIndexConfig {
    fn default() -> Self {
        Self { tokenizer: SearchTokenizer::default() }
    }
}

/// Tokenizer configuration for Matrix search indexes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SearchTokenizer {
    /// Use Tantivy's default text tokenizer.
    Default,
    /// Use a Tantivy ngram tokenizer over message body text.
    Ngram {
        /// The shortest ngram token length to emit.
        min_gram: usize,
        /// The longest ngram token length to emit.
        max_gram: usize,
    },
}

impl SearchTokenizer {
    /// Create an ngram tokenizer configuration.
    pub fn ngram(min_gram: usize, max_gram: usize) -> Self {
        Self::Ngram { min_gram, max_gram }
    }

    pub(crate) fn name(&self) -> String {
        match self {
            Self::Default => "default".to_owned(),
            Self::Ngram { min_gram, max_gram } => {
                format!("matrix_ngram_{min_gram}_{max_gram}")
            }
        }
    }

    pub(crate) fn ngram_bounds(&self) -> Option<(usize, usize)> {
        match self {
            Self::Default => None,
            Self::Ngram { min_gram, max_gram } => Some((*min_gram, *max_gram)),
        }
    }
}

impl Default for SearchTokenizer {
    fn default() -> Self {
        Self::Default
    }
}
