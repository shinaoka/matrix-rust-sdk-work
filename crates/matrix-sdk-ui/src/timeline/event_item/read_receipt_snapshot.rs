// Copyright 2026 The Koushi contributors.
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

use std::{fmt, sync::OnceLock};

use imbl::{OrdMap, Vector};
use indexmap::IndexMap;
use ruma::{OwnedUserId, UserId, events::receipt::Receipt};

/// An immutable, cheaply cloned receipt collection in insertion/swap-remove order.
///
/// Reading this collection does not materialize the compatibility `IndexMap`.
/// Clones share tree/vector storage; mutations copy affected nodes. No previous-version
/// chain is retained.
///
/// ```
/// use matrix_sdk_ui::timeline::ReadReceiptSnapshot;
/// use ruma::{user_id, events::receipt::Receipt};
/// let user = user_id!("@reader:example.org");
/// let receipts = ReadReceiptSnapshot::from([(user.to_owned(), Receipt::default())]);
/// let cloned = receipts.clone();
/// assert_eq!(cloned.len(), 1);
/// assert!(!cloned.is_empty());
/// assert_eq!(cloned.iter().next().unwrap().0.as_str(), user.as_str());
/// assert!(std::ptr::eq(receipts.get(user).unwrap(), cloned.get(user).unwrap()));
/// ```
#[derive(Default)]
pub struct ReadReceiptSnapshot {
    by_user: OrdMap<OwnedUserId, (usize, Receipt)>,
    order: Vector<OwnedUserId>,
    legacy: OnceLock<IndexMap<OwnedUserId, Receipt>>,
}

impl Clone for ReadReceiptSnapshot {
    fn clone(&self) -> Self {
        Self { by_user: self.by_user.clone(), order: self.order.clone(), legacy: OnceLock::new() }
    }
}

impl ReadReceiptSnapshot {
    /// Number of readers in the collection.
    pub fn len(&self) -> usize {
        self.by_user.len()
    }

    /// Whether the collection contains no readers.
    pub fn is_empty(&self) -> bool {
        self.by_user.is_empty()
    }

    /// Borrow a reader's receipt without materializing the full compatibility map.
    pub fn get(&self, user_id: &UserId) -> Option<&Receipt> {
        self.by_user.get(user_id).map(|(_, receipt)| receipt)
    }

    /// Borrow receipts in the same order as the full-map accessor.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&OwnedUserId, &Receipt)> {
        self.order
            .iter()
            .map(|user_id| (user_id, self.get(user_id).expect("ordered receipt is indexed")))
    }

    pub(in crate::timeline) fn insert(
        &mut self,
        user_id: OwnedUserId,
        receipt: Receipt,
    ) -> Option<Receipt> {
        let slot = if let Some((slot, _)) = self.by_user.get(&user_id) {
            *slot
        } else {
            let slot = self.order.len();
            self.order.push_back(user_id.clone());
            slot
        };
        self.legacy.take();
        self.by_user.insert(user_id, (slot, receipt)).map(|(_, receipt)| receipt)
    }

    pub(in crate::timeline) fn swap_remove(&mut self, user_id: &UserId) -> Option<Receipt> {
        let (slot, receipt) = self.by_user.remove(user_id)?;
        let last = self.order.pop_back().expect("receipt order matches its index");
        if slot < self.order.len() {
            self.order.set(slot, last.clone());
            self.by_user.get_mut(&last).expect("last receipt is indexed").0 = slot;
        }
        self.legacy.take();
        Some(receipt)
    }

    pub(in crate::timeline) fn as_index_map(&self) -> &IndexMap<OwnedUserId, Receipt> {
        self.legacy.get_or_init(|| {
            self.iter().map(|(user_id, receipt)| (user_id.clone(), receipt.clone())).collect()
        })
    }
}

impl FromIterator<(OwnedUserId, Receipt)> for ReadReceiptSnapshot {
    fn from_iter<T: IntoIterator<Item = (OwnedUserId, Receipt)>>(iter: T) -> Self {
        let mut result = Self::default();
        for (user_id, receipt) in iter {
            result.insert(user_id, receipt);
        }
        result
    }
}

impl From<IndexMap<OwnedUserId, Receipt>> for ReadReceiptSnapshot {
    fn from(receipts: IndexMap<OwnedUserId, Receipt>) -> Self {
        receipts.into_iter().collect()
    }
}

impl<const N: usize> From<[(OwnedUserId, Receipt); N]> for ReadReceiptSnapshot {
    fn from(receipts: [(OwnedUserId, Receipt); N]) -> Self {
        receipts.into_iter().collect()
    }
}

impl fmt::Debug for ReadReceiptSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_map().entries(self.iter()).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_same(actual: &ReadReceiptSnapshot, expected: &IndexMap<OwnedUserId, Receipt>) {
        assert_json_diff::assert_json_eq!(actual.as_index_map(), expected);
        assert_eq!(
            actual.as_index_map().keys().collect::<Vec<_>>(),
            expected.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn shared_clone_and_mutations_preserve_indexmap_order_and_cached_values() {
        let users: Vec<OwnedUserId> =
            (0..1500).map(|i| format!("@reader-{i}:example.org").parse().unwrap()).collect();
        let mut expected: IndexMap<_, _> =
            users.iter().cloned().map(|user| (user, Receipt::default())).collect();
        let mut actual: ReadReceiptSnapshot = expected.clone().into();
        assert_same(&actual, &expected);
        let original = actual.clone();
        assert!(actual.by_user.ptr_eq(&original.by_user));
        assert!(original.legacy.get().is_none(), "clone must not copy the full-map cache");
        assert_eq!(original.iter().count(), 1500);
        assert!(
            original.legacy.get().is_none(),
            "direct iteration must not materialize the full-map cache"
        );

        let receipt_fields =
            |receipt: Option<Receipt>| receipt.map(|receipt| (receipt.ts, receipt.thread));
        for index in [0, 1, 1499, 32, 700] {
            assert_eq!(
                receipt_fields(actual.swap_remove(&users[index])),
                receipt_fields(expected.swap_remove(&users[index]))
            );
            assert_same(&actual, &expected);
            for (slot, user) in actual.order.iter().enumerate() {
                assert_eq!(actual.by_user.get(user).unwrap().0, slot);
            }
        }
        let replacement = Receipt::new(ruma::MilliSecondsSinceUnixEpoch(1_u32.into()));
        for index in [42, 0, 1499] {
            assert_eq!(
                receipt_fields(actual.insert(users[index].clone(), replacement.clone())),
                receipt_fields(expected.insert(users[index].clone(), replacement.clone()))
            );
            assert_same(&actual, &expected);
        }
        assert!(actual.swap_remove(&users[700]).is_none());
        assert_same(&actual, &expected);
        assert_eq!(original.len(), 1500);
        assert!(original.as_index_map().values().all(|receipt| receipt.ts.is_none()
            && receipt.thread == ruma::events::receipt::ReceiptThread::Unthreaded));
    }
}
