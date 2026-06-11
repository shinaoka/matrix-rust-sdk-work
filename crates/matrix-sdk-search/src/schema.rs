// Copyright 2024 The Matrix.org Foundation C.I.C.
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

use ruma::events::room::message::{MessageType, OriginalSyncRoomMessageEvent, Relation};
use tantivy::{
    DateTime, TantivyDocument, doc,
    schema::{
        DateOptions, DateTimePrecision, Field, INDEXED, STORED, STRING, Schema, TEXT, TextOptions,
    },
};

use crate::{
    config::{SearchIndexConfig, SearchTokenizer},
    error::{IndexError, IndexSchemaError},
};

pub(crate) trait MatrixSearchIndexSchema {
    fn default_search_fields(&self) -> Vec<Field>;
    fn primary_key(&self) -> Field;
    fn deletion_key(&self) -> Field;
    fn get_field_name(&self, field: Field) -> &str;
    fn as_tantivy_schema(&self) -> Schema;
    fn make_doc(&self, event: OriginalSyncRoomMessageEvent) -> Result<TantivyDocument, IndexError>;
}

#[derive(Debug, Clone)]
pub(crate) struct RoomMessageSchema {
    inner: Schema,
    /// The event id of this event (primary key).
    event_id_field: Field,
    /// The event id of the event that this event affects.
    /// Used by edits to refer to the event they edited (deletion key).
    original_event_id_field: Field,
    body_field: Field,
    date_field: Field,
    sender_field: Field,
    default_search_fields: Vec<Field>,
}

impl RoomMessageSchema {
    pub(crate) fn new_with_config(config: &SearchIndexConfig) -> Self {
        let mut schema = Schema::builder();
        let event_id_field = schema.add_text_field("event_id", STORED | STRING);
        let original_event_id_field = schema.add_text_field("original_event_id", STRING);
        let body_field = schema.add_text_field("body", body_text_options(config));

        let date_options =
            DateOptions::from(INDEXED).set_fast().set_precision(DateTimePrecision::Seconds);

        let date_field = schema.add_date_field("date", date_options);
        let sender_field = schema.add_text_field("sender", STRING);

        let default_search_fields = vec![body_field];

        let schema = schema.build();

        Self {
            inner: schema,
            event_id_field,
            original_event_id_field,
            body_field,
            date_field,
            sender_field,
            default_search_fields,
        }
    }

    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::new_with_config(&SearchIndexConfig::default())
    }

    #[cfg(test)]
    pub(crate) fn body_field(&self) -> Field {
        self.body_field
    }
}

impl MatrixSearchIndexSchema for RoomMessageSchema {
    fn default_search_fields(&self) -> Vec<Field> {
        self.default_search_fields.clone()
    }

    fn primary_key(&self) -> Field {
        self.event_id_field
    }

    fn deletion_key(&self) -> Field {
        self.original_event_id_field
    }

    fn get_field_name(&self, field: Field) -> &str {
        self.inner.get_field_name(field)
    }

    fn as_tantivy_schema(&self) -> Schema {
        self.inner.clone()
    }

    /// Given an [`OriginalSyncRoomMessageEvent`] return a
    /// [`TantivyDocument`].
    fn make_doc(&self, event: OriginalSyncRoomMessageEvent) -> Result<TantivyDocument, IndexError> {
        let body = match &event.content.msgtype {
            MessageType::Text(content) => Ok(content.body.clone()),
            _ => Err(IndexError::MessageTypeNotSupported),
        }?;

        let mut document = doc!(
            self.event_id_field => event.event_id.to_string(),
            self.body_field => body,
            self.date_field =>
                DateTime::from_timestamp_millis(
                    event.origin_server_ts.get().into()),
            self.sender_field => event.sender.to_string(),
        );

        if let Some(Relation::Replacement(replacement_data)) = &event.content.relates_to {
            document.add_text(self.original_event_id_field, replacement_data.event_id.clone());
        } else {
            document.add_text(self.original_event_id_field, event.event_id);
        }

        Ok(document)
    }
}

fn body_text_options(config: &SearchIndexConfig) -> TextOptions {
    match &config.tokenizer {
        SearchTokenizer::Default => TEXT,
        SearchTokenizer::Ngram(_) => {
            let tokenizer_name = config.body_tokenizer_name();
            let indexing_options = TEXT
                .get_indexing_options()
                .expect("TEXT should have indexing options")
                .clone()
                .set_tokenizer(&tokenizer_name);

            TEXT.set_indexing_options(indexing_options)
        }
    }
}

impl TryFrom<Schema> for RoomMessageSchema {
    type Error = IndexSchemaError;

    fn try_from(schema: Schema) -> Result<RoomMessageSchema, Self::Error> {
        let event_id_field = schema.get_field("event_id")?;
        let original_event_id_field = schema.get_field("original_event_id")?;
        let body_field = schema.get_field("body")?;
        let date_field = schema.get_field("date")?;
        let sender_field = schema.get_field("sender")?;

        let default_search_fields = vec![body_field];

        Ok(Self {
            inner: schema,
            event_id_field,
            original_event_id_field,
            body_field,
            date_field,
            sender_field,
            default_search_fields,
        })
    }
}

#[cfg(test)]
mod tests {
    use tantivy::schema::FieldType;

    use super::{MatrixSearchIndexSchema, RoomMessageSchema};
    use crate::config::SearchIndexConfig;

    fn body_tokenizer(schema: &RoomMessageSchema) -> String {
        let tantivy_schema = schema.as_tantivy_schema();
        let field_entry = tantivy_schema.get_field_entry(schema.body_field());

        let FieldType::Str(text_options) = field_entry.field_type() else {
            panic!("body field should be a text field");
        };

        text_options
            .get_indexing_options()
            .expect("body field should be indexed")
            .tokenizer()
            .to_owned()
    }

    #[test]
    fn default_schema_uses_default_body_tokenizer() {
        let schema = RoomMessageSchema::new();

        assert_eq!(body_tokenizer(&schema), "default");
    }

    #[test]
    fn ngram_schema_uses_named_body_tokenizer() {
        let config = SearchIndexConfig::ngram(2, 4).expect("ngram bounds should be valid");
        let schema = RoomMessageSchema::new_with_config(&config);

        assert_eq!(body_tokenizer(&schema), "matrix_ngram_2_4");
    }
}
