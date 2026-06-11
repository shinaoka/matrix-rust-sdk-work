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

use serde::{Deserialize, Deserializer, Serialize, de};
use thiserror::Error;

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
    pub fn ngram(min_gram: usize, max_gram: usize) -> Result<Self, NgramConfigError> {
        Ok(Self { tokenizer: SearchTokenizer::ngram(min_gram, max_gram)? })
    }

    pub(crate) fn body_tokenizer_name(&self) -> String {
        self.tokenizer.name()
    }

    pub(crate) fn ngram_tokenizer(&self) -> Option<(String, usize, usize)> {
        self.tokenizer
            .ngram_config()
            .map(|config| (self.body_tokenizer_name(), config.min_gram(), config.max_gram()))
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
    Ngram(NgramConfig),
}

impl SearchTokenizer {
    /// Create an ngram tokenizer configuration.
    pub fn ngram(min_gram: usize, max_gram: usize) -> Result<Self, NgramConfigError> {
        Ok(Self::Ngram(NgramConfig::new(min_gram, max_gram)?))
    }

    pub(crate) fn name(&self) -> String {
        match self {
            Self::Default => "default".to_owned(),
            Self::Ngram(config) => {
                let min_gram = config.min_gram();
                let max_gram = config.max_gram();
                format!("matrix_ngram_{min_gram}_{max_gram}")
            }
        }
    }

    pub(crate) fn ngram_config(&self) -> Option<&NgramConfig> {
        match self {
            Self::Default => None,
            Self::Ngram(config) => Some(config),
        }
    }
}

impl Default for SearchTokenizer {
    fn default() -> Self {
        Self::Default
    }
}

/// Configuration for a Tantivy ngram tokenizer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NgramConfig {
    min_gram: usize,
    max_gram: usize,
}

impl NgramConfig {
    /// Create a validated ngram tokenizer configuration.
    pub fn new(min_gram: usize, max_gram: usize) -> Result<Self, NgramConfigError> {
        if min_gram == 0 {
            return Err(NgramConfigError::MinGramZero);
        }

        if min_gram > max_gram {
            return Err(NgramConfigError::MinGramGreaterThanMaxGram { min_gram, max_gram });
        }

        Ok(Self { min_gram, max_gram })
    }

    /// The shortest ngram token length to emit.
    pub fn min_gram(&self) -> usize {
        self.min_gram
    }

    /// The longest ngram token length to emit.
    pub fn max_gram(&self) -> usize {
        self.max_gram
    }
}

impl<'de> Deserialize<'de> for NgramConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawNgramConfig {
            min_gram: usize,
            max_gram: usize,
        }

        let raw = RawNgramConfig::deserialize(deserializer)?;
        Self::new(raw.min_gram, raw.max_gram).map_err(de::Error::custom)
    }
}

/// An error from invalid ngram tokenizer configuration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NgramConfigError {
    /// The minimum ngram token length is zero.
    #[error("min_gram must be greater than 0")]
    MinGramZero,

    /// The minimum ngram token length is greater than the maximum length.
    #[error(
        "min_gram must not be greater than max_gram (min_gram: {min_gram}, max_gram: {max_gram})"
    )]
    MinGramGreaterThanMaxGram {
        /// The invalid minimum ngram token length.
        min_gram: usize,
        /// The invalid maximum ngram token length.
        max_gram: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::{NgramConfig, NgramConfigError, SearchIndexConfig, SearchTokenizer};

    #[test]
    fn ngram_config_rejects_zero_min_gram() {
        assert_eq!(NgramConfig::new(0, 4), Err(NgramConfigError::MinGramZero));
    }

    #[test]
    fn ngram_config_rejects_min_gram_greater_than_max_gram() {
        assert_eq!(
            NgramConfig::new(5, 4),
            Err(NgramConfigError::MinGramGreaterThanMaxGram { min_gram: 5, max_gram: 4 })
        );
    }

    #[test]
    fn ngram_search_index_config_constructor_rejects_invalid_bounds() {
        assert_eq!(SearchIndexConfig::ngram(0, 4), Err(NgramConfigError::MinGramZero));
    }

    #[test]
    fn ngram_search_tokenizer_constructor_rejects_invalid_bounds() {
        assert_eq!(
            SearchTokenizer::ngram(5, 4),
            Err(NgramConfigError::MinGramGreaterThanMaxGram { min_gram: 5, max_gram: 4 })
        );
    }

    #[test]
    fn ngram_config_deserialization_rejects_zero_min_gram() {
        let err =
            serde_json::from_str::<SearchTokenizer>(r#"{"Ngram":{"min_gram":0,"max_gram":4}}"#)
                .expect_err("invalid ngram config should not deserialize");

        assert!(err.to_string().contains("min_gram must be greater than 0"));
    }

    #[test]
    fn ngram_config_deserialization_rejects_min_gram_greater_than_max_gram() {
        let err =
            serde_json::from_str::<SearchTokenizer>(r#"{"Ngram":{"min_gram":5,"max_gram":4}}"#)
                .expect_err("invalid ngram config should not deserialize");

        assert!(err.to_string().contains("min_gram must not be greater than max_gram"));
    }

    #[test]
    fn ngram_config_serializes_as_tokenizer_variant() {
        let config = SearchIndexConfig::ngram(2, 4).expect("ngram bounds should be valid");

        assert_eq!(
            serde_json::to_string(&config).expect("config should serialize"),
            r#"{"tokenizer":{"Ngram":{"min_gram":2,"max_gram":4}}}"#
        );
    }
}
