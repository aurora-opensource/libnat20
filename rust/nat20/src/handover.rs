/*
 * Copyright 2026 Aurora Operations, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
 *
 * This work is dual licensed.
 * You may use it under Apache-2.0 or GPL-2.0 at your option.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * OR
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see
 * <https://www.gnu.org/licenses/>.
 */

//! The DICE handover structure: the certificate chain a boot stage leaves
//! for the next.
//!
//! The format is specified in `HANDOVER.md`. In short: a 16-byte header
//! (magic `"DICE"`, version 1, header size 16, offset of the CBOR break
//! byte; integers little-endian) followed by a CBOR indefinite-length array
//! of tagged certificates, device identity first.
//!
//! [`HandoverStruct`] wraps a caller-provided region. A stage that starts
//! the chain calls [`HandoverStruct::init`]; a stage that inherits one calls
//! [`HandoverStruct::used_size`] to check it and then appends. Entries are
//! appended either from a finished buffer ([`HandoverStruct::append_entry`])
//! or written in place ([`HandoverStruct::reserve_entry`]), which avoids a
//! second certificate-sized buffer.

use crate::error::Error;
use core::ops::{Deref, DerefMut};

/// Tag for the COSE_Sign1 structure in the handover entries.
pub const TAG_COSE_SIGN1: &[u8] = &[0xD2];

/// CBOR initial byte opening an indefinite-length array.
const CBOR_ARRAY_INDEFINITE: u8 = 0x9F;
/// CBOR break byte, closing an indefinite-length item.
const CBOR_BREAK: u8 = 0xFF;

/// The handover header.
///
/// `#[repr(C)]` over `[u8; 4]` and three `u32`, so every bit pattern is a
/// valid value and caller memory may be reinterpreted as one before it is
/// validated. The integers are stored little-endian, whatever the host; the
/// accessors convert.
#[repr(C)]
pub struct HandoverHeader {
    /// Magic number, `b"DICE"`.
    magic: [u8; 4],
    /// Version of the handover structure, 1.
    version: u32,
    /// Size of this header in bytes, 16.
    header_size: u32,
    /// Offset of the CBOR break byte that closes the entry array, relative
    /// to the start of this header.
    terminator_offset: u32,
}

impl HandoverHeader {
    fn version(&self) -> u32 {
        u32::from_le(self.version)
    }

    fn set_version(&mut self, v: u32) {
        self.version = v.to_le();
    }

    fn header_size(&self) -> u32 {
        u32::from_le(self.header_size)
    }

    fn set_header_size(&mut self, v: u32) {
        self.header_size = v.to_le();
    }

    fn terminator_offset(&self) -> u32 {
        u32::from_le(self.terminator_offset)
    }

    fn set_terminator_offset(&mut self, v: u32) {
        self.terminator_offset = v.to_le();
    }
}

/// Size of [`HandoverHeader`], which is also the distance between an
/// absolute offset in the header and the corresponding content index.
const HDR: usize = core::mem::size_of::<HandoverHeader>();

/// A region reserved in the handover content for an entry that is being
/// written in place.
///
/// Dereferences to the entry's payload (after any tag). [`commit`] keeps the
/// entry; dropping the proxy without committing releases the region and
/// restores the structure to what it was before the reservation.
///
/// [`commit`]: ReservedRegionProxy::commit
pub struct ReservedRegionProxy<'s, 'a> {
    handover: &'s mut HandoverStruct<'a>,
    /// Content index where the reservation (including any tag) starts.
    reset_offset: usize,
    /// Content index where the payload starts.
    offset: usize,
    /// Size of the payload in bytes.
    size: usize,
    /// Whether the entry is kept when the proxy is dropped.
    committed: bool,
}

impl ReservedRegionProxy<'_, '_> {
    /// Keeps the entry.
    pub fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for ReservedRegionProxy<'_, '_> {
    fn drop(&mut self) {
        if !self.committed {
            // Clear the region including the terminator reserve_entry wrote
            // right after it, then put the terminator back where the
            // reservation started.
            let end = self.offset + self.size;
            self.handover.content[self.reset_offset..=end].fill(0);
            self.handover.content[self.reset_offset] = CBOR_BREAK;
            // `new` bounded the content so that every index fits in u32.
            self.handover
                .header
                .set_terminator_offset((self.reset_offset + HDR) as u32);
        }
    }
}

impl Deref for ReservedRegionProxy<'_, '_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.handover.content[self.offset..self.offset + self.size]
    }
}

impl DerefMut for ReservedRegionProxy<'_, '_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.handover.content[self.offset..self.offset + self.size]
    }
}

/// A read-only view of a handover structure over a caller-provided header
/// and the content that immediately follows it, for checking a handover
/// that may sit in read-only memory.
#[derive(Clone, Copy)]
pub struct HandoverRef<'a> {
    header: &'a HandoverHeader,
    content: &'a [u8],
}

impl<'a> HandoverRef<'a> {
    /// Wraps a header and the content that follows it.
    ///
    /// Nothing is read. The offsets in the format only make sense if
    /// `content` starts right after `header`, so a non-contiguous pair is
    /// rejected, as is a region whose offsets would not fit the header's
    /// 32-bit fields.
    pub fn new(header: &'a HandoverHeader, content: &'a [u8]) -> Result<Self, Error> {
        let header_end = (header as *const HandoverHeader as usize) + HDR;
        if header_end != content.as_ptr() as usize {
            return Err(Error::InvalidHandoverHeader);
        }
        if content.len() > u32::MAX as usize - HDR {
            return Err(Error::InvalidArgument);
        }
        Ok(HandoverRef { header, content })
    }

    /// Checks the structure and returns the content index of the
    /// terminator.
    ///
    /// Checks the header, and that the content opens an indefinite-length
    /// array and the byte at the terminator offset closes it. Entries are
    /// not parsed.
    // Inlined: it is short, and every public operation starts with it.
    #[inline(always)]
    fn validate(&self) -> Result<usize, Error> {
        let h = self.header;
        if h.magic != *b"DICE" || h.version() != 1 || h.header_size() as usize != HDR {
            return Err(Error::InvalidHandoverHeader);
        }
        // Bounded on both sides: every later index derives from this, and
        // an unbounded value could make index arithmetic wrap.
        let terminator = (h.terminator_offset() as usize)
            .checked_sub(HDR)
            .filter(|&t| t > 0 && t < self.content.len())
            .ok_or(Error::InvalidHandoverHeader)?;
        if self.content[0] != CBOR_ARRAY_INDEFINITE || self.content[terminator] != CBOR_BREAK {
            return Err(Error::InvalidHandoverHeader);
        }
        Ok(terminator)
    }

    /// Validates a handover left by an earlier stage and returns the number
    /// of bytes in use: header, entries and terminator.
    ///
    /// Checks the header, and that the content opens an indefinite-length
    /// array and the byte at the terminator offset closes it — what a stage
    /// taking over a handover it did not write must check. Entries are not
    /// parsed.
    ///
    /// # Errors
    ///
    /// `InvalidHandoverHeader` if the structure is malformed.
    pub fn used_size(&self) -> Result<usize, Error> {
        Ok(HDR + self.validate()? + 1)
    }
}

/// A handover structure over a caller-provided header and the content that
/// immediately follows it.
pub struct HandoverStruct<'a> {
    header: &'a mut HandoverHeader,
    content: &'a mut [u8],
}

impl<'a> HandoverStruct<'a> {
    /// Wraps a header and the content that follows it, with the checks of
    /// [`HandoverRef::new`].
    pub fn new(header: &'a mut HandoverHeader, content: &'a mut [u8]) -> Result<Self, Error> {
        HandoverRef::new(header, content)?;
        Ok(HandoverStruct { header, content })
    }

    /// Borrows the structure read-only.
    pub fn view(&self) -> HandoverRef<'_> {
        HandoverRef {
            header: self.header,
            content: self.content,
        }
    }

    /// Starts a new, empty handover, discarding whatever the region held.
    ///
    /// Writes the header and an empty indefinite-length array.
    ///
    /// # Errors
    ///
    /// `InvalidHandoverHeader` if the content cannot hold the array opener
    /// and terminator (2 bytes).
    pub fn init(&mut self) -> Result<(), Error> {
        if self.content.len() < 2 {
            return Err(Error::InvalidHandoverHeader);
        }
        self.header.magic = *b"DICE";
        self.header.set_version(1);
        self.header.set_header_size(HDR as u32);
        self.header.set_terminator_offset(HDR as u32 + 1);
        self.content[0] = CBOR_ARRAY_INDEFINITE;
        self.content[1] = CBOR_BREAK;
        Ok(())
    }

    /// See [`HandoverRef::used_size`].
    pub fn used_size(&self) -> Result<usize, Error> {
        self.view().used_size()
    }

    /// Makes room for `size` bytes at the end of the entry array, returning
    /// the content index where they start. Writes the new terminator and
    /// advances the header; the room itself is left for the caller to fill.
    fn grow(&mut self, size: usize) -> Result<usize, Error> {
        let start = self.view().validate()?;
        // The new terminator lands at `start + size`, which must still be
        // inside the content.
        let end = start
            .checked_add(size)
            .filter(|&end| end < self.content.len())
            .ok_or(Error::InsufficientBuffer {
                required: start.saturating_add(size).saturating_add(1),
            })?;
        self.content[end] = CBOR_BREAK;
        // `new` bounded the content so that every index fits in u32.
        self.header.set_terminator_offset((end + HDR) as u32);
        Ok(start)
    }

    /// Appends `entry`, which must be one complete CBOR item (typically a
    /// tagged certificate).
    ///
    /// # Errors
    ///
    /// * `InvalidHandoverHeader` if the structure is malformed.
    /// * `InsufficientBuffer` if the entry and its terminator do not fit;
    ///   `required` is the content size that would be needed.
    pub fn append_entry(&mut self, entry: &[u8]) -> Result<(), Error> {
        let start = self.grow(entry.len())?;
        self.content[start..start + entry.len()].copy_from_slice(entry);
        Ok(())
    }

    /// Reserves room for an entry of `tag` followed by `entry_size` payload
    /// bytes, to be written in place through the returned proxy.
    ///
    /// The tag is written immediately. The caller must fill exactly
    /// `entry_size` bytes, such that tag and payload form one CBOR item, and
    /// then [`commit`](ReservedRegionProxy::commit); dropping the proxy
    /// instead rolls the reservation back.
    ///
    /// # Errors
    ///
    /// * `InvalidHandoverHeader` if the structure is malformed.
    /// * `InvalidArgument` if `entry_size` is zero.
    /// * `InsufficientBuffer` if the entry and its terminator do not fit.
    pub fn reserve_entry<'s>(
        &'s mut self,
        entry_size: usize,
        tag: Option<&[u8]>,
    ) -> Result<ReservedRegionProxy<'s, 'a>, Error> {
        if entry_size == 0 {
            return Err(Error::InvalidArgument);
        }
        let tag = tag.unwrap_or(&[]);
        let total = entry_size
            .checked_add(tag.len())
            .ok_or(Error::InvalidArgument)?;
        let start = self.grow(total)?;
        self.content[start..start + tag.len()].copy_from_slice(tag);
        Ok(ReservedRegionProxy {
            handover: self,
            reset_offset: start,
            offset: start + tag.len(),
            size: entry_size,
            committed: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A handover region laid out the way the format requires: the content
    /// immediately follows the header.
    ///
    /// Two stack locals cannot be used for this. Nothing orders or packs
    /// separate locals, so whether they end up adjacent is up to the compiler
    /// -- and `HandoverStruct::new` rejects the pair when they are not.
    /// `repr(C)` gives the guarantee instead: the header is 4-aligned and
    /// `[u8; N]` is 1-aligned, so `content` lands at offset `HDR` with no
    /// padding in between.
    #[repr(C)]
    struct Region<const N: usize> {
        header: HandoverHeader,
        content: [u8; N],
    }

    impl<const N: usize> Region<N> {
        /// An un-initialised region, as found in fresh SRAM.
        fn blank() -> Self {
            Region {
                header: HandoverHeader {
                    magic: [0; 4],
                    version: 0,
                    header_size: 0,
                    terminator_offset: 0,
                },
                content: [0; N],
            }
        }

        /// A region stamped as a valid, empty handover, for tests that then
        /// corrupt one field.
        fn stamped() -> Self {
            let mut r = Self::blank();
            r.header.magic = *b"DICE";
            r.header.set_version(1);
            r.header.set_header_size(HDR as u32);
            r.header.set_terminator_offset(HDR as u32 + 1);
            // As far as the content reaches: a too-small one must still
            // fail validation on the header.
            if let Some(b) = r.content.get_mut(0) {
                *b = CBOR_ARRAY_INDEFINITE;
            }
            if let Some(b) = r.content.get_mut(1) {
                *b = CBOR_BREAK;
            }
            r
        }

        /// Borrows the region as a `HandoverStruct`. Contiguity holds by
        /// construction, so a failure here is a bug in the helper.
        fn handover(&mut self) -> HandoverStruct<'_> {
            HandoverStruct::new(&mut self.header, &mut self.content)
                .expect("a repr(C) region is contiguous by construction")
        }

        /// Borrows the region as an initialised `HandoverStruct`.
        fn initialized(&mut self) -> HandoverStruct<'_> {
            let mut h = self.handover();
            h.init().expect("content is large enough for the skeleton");
            h
        }
    }

    /// The `content` index that `terminator_offset` designates. Every test
    /// that appends or reserves checks that this index really holds the CBOR
    /// terminator, which is the invariant the header/content split is easy to
    /// get wrong about.
    fn term_index(h: &HandoverStruct) -> usize {
        (h.header.terminator_offset() - h.header.header_size()) as usize
    }

    /// The offsets in the format are meaningless unless the content directly
    /// follows the header, so a caller that gets the layout wrong must be
    /// turned away rather than silently writing at bogus offsets.
    #[test]
    fn new_rejects_a_non_contiguous_region() {
        let mut region = Region::<64>::blank();
        // Skipping the first content byte puts the slice one byte past the end
        // of the header -- a deterministic gap, unlike two stack locals.
        let skewed = HandoverStruct::new(&mut region.header, &mut region.content[1..]);
        assert!(matches!(skewed, Err(Error::InvalidHandoverHeader)));

        // The same region without the skew is accepted.
        assert!(HandoverStruct::new(&mut region.header, &mut region.content).is_ok());
    }

    /// `init` writes two bytes of CBOR skeleton, so it must refuse a region
    /// that cannot hold them rather than panic.
    #[test]
    fn init_rejects_content_too_small_for_the_skeleton() {
        let mut region = Region::<1>::blank();
        assert_eq!(
            region.handover().init(),
            Err(Error::InvalidHandoverHeader),
            "one byte cannot hold both the array indicator and the terminator"
        );

        let mut region = Region::<2>::blank();
        assert_eq!(region.handover().init(), Ok(()), "two bytes is the minimum");
    }

    #[test]
    fn init_writes_header_and_cbor_skeleton() {
        let mut region = Region::<64>::blank();
        let h = region.initialized();

        assert_eq!(h.header.magic, *b"DICE");
        assert_eq!(h.header.version(), 1);
        assert_eq!(h.header.header_size() as usize, HDR);
        assert_eq!(h.content[0], 0x9F, "indefinite-length array indicator");
        assert_eq!(h.content[1], 0xFF, "terminator");
        // The terminator sits at content index 1, i.e. absolute offset HDR + 1.
        assert_eq!(h.header.terminator_offset() as usize, HDR + 1);
        assert_eq!(term_index(&h), 1);
        assert_eq!(h.view().validate().map(drop), Ok(()));
    }

    /// The header is little-endian on every host, as the format specifies.
    #[test]
    fn init_writes_a_little_endian_header() {
        let mut region = Region::<64>::blank();
        region.initialized();
        // `to_ne_bytes` is the field's in-memory representation.
        let h = &region.header;
        assert_eq!(h.magic, *b"DICE");
        assert_eq!(h.version.to_ne_bytes(), [1, 0, 0, 0]);
        assert_eq!(h.header_size.to_ne_bytes(), [16, 0, 0, 0]);
        assert_eq!(h.terminator_offset.to_ne_bytes(), [17, 0, 0, 0]);
    }

    /// A reservation borrows the structure only for the proxy's lifetime,
    /// so one `HandoverStruct` can take several entries in sequence.
    #[test]
    fn one_handover_takes_successive_reservations() {
        let mut region = Region::<64>::blank();
        let mut h = region.initialized();
        let mut r = h.reserve_entry(1, None).unwrap();
        r[0] = 0x01;
        r.commit();
        let mut r = h.reserve_entry(1, None).unwrap();
        r[0] = 0x02;
        r.commit();
        assert_eq!(&h.content[..4], &[0x9F, 0x01, 0x02, 0xFF]);
    }

    #[test]
    fn append_entry_packs_entries_back_to_back() {
        let mut region = Region::<64>::blank();
        let mut h = region.initialized();

        h.append_entry(&[0x01, 0x02]).unwrap();
        assert_eq!(&h.content[..4], &[0x9F, 0x01, 0x02, 0xFF]);
        assert_eq!(h.header.terminator_offset() as usize, HDR + 3);
        assert_eq!(h.content[term_index(&h)], 0xFF);

        h.append_entry(&[0x03]).unwrap();
        assert_eq!(&h.content[..5], &[0x9F, 0x01, 0x02, 0x03, 0xFF]);
        assert_eq!(h.header.terminator_offset() as usize, HDR + 4);
        assert_eq!(h.content[term_index(&h)], 0xFF);
    }

    /// `terminator_offset` is absolute (relative to the start of the header),
    /// while `content` is indexed from the end of the header. Regression test
    /// for treating the two as interchangeable.
    #[test]
    fn terminator_offset_is_absolute_not_a_content_index() {
        let mut region = Region::<64>::blank();
        let mut h = region.initialized();
        h.append_entry(&[0xAA; 5]).unwrap();

        let absolute = h.header.terminator_offset() as usize;
        assert!(absolute > HDR, "offset must include the header");
        // Reading the absolute offset as a content index would land here...
        assert_ne!(absolute, term_index(&h));
        // ...and that is not where the terminator is.
        assert_eq!(h.content[term_index(&h)], 0xFF);
    }

    #[test]
    fn validate_rejects_a_blank_region() {
        let mut region = Region::<64>::blank();
        assert_eq!(
            region.handover().view().validate().map(drop),
            Err(Error::InvalidHandoverHeader)
        );
    }

    /// A named corruption to apply to an otherwise valid header.
    type CorruptionCase = (&'static str, fn(&mut HandoverHeader));

    #[test]
    fn validate_rejects_corrupt_header_fields() {
        let cases: [CorruptionCase; 4] = [
            ("magic", |h| h.magic = *b"XICE"),
            ("version", |h| h.set_version(2)),
            ("header_size", |h| h.set_header_size(HDR as u32 + 4)),
            // Pointing at the header itself leaves no room for content.
            ("terminator_offset", |h| h.set_terminator_offset(HDR as u32)),
        ];

        for (name, corrupt) in cases {
            let mut region = Region::<64>::stamped();
            assert_eq!(
                region.handover().view().validate().map(drop),
                Ok(()),
                "{name}: precondition"
            );
            corrupt(&mut region.header);
            assert_eq!(
                region.handover().view().validate().map(drop),
                Err(Error::InvalidHandoverHeader),
                "{name}"
            );
        }
    }

    /// A `terminator_offset` past the end of `content` must be rejected up
    /// front: every later offset computation derives from it, and on a 32-bit
    /// target `adjusted + size` can wrap rather than trip the bounds check.
    #[test]
    fn validate_rejects_terminator_past_end_of_content() {
        let mut region = Region::<64>::stamped();
        region.header.set_terminator_offset((HDR + 64) as u32);
        assert_eq!(
            region.handover().view().validate().map(drop),
            Err(Error::InvalidHandoverHeader)
        );

        // One byte lower is the last in-bounds position.
        region.header.set_terminator_offset((HDR + 63) as u32);
        region.content[63] = CBOR_BREAK;
        assert_eq!(region.handover().view().validate().map(drop), Ok(()));
    }

    #[test]
    fn append_entry_validates_before_touching_content() {
        let mut region = Region::<64>::blank();
        assert_eq!(
            region.handover().append_entry(&[0x01]),
            Err(Error::InvalidHandoverHeader),
            "an un-initialised region must not be appended to"
        );
        assert_eq!(region.content, [0u8; 64], "content must be untouched");
    }

    #[test]
    fn append_entry_reports_the_required_size() {
        let mut region = Region::<8>::blank();
        let mut h = region.initialized();

        // Terminator at content index 1, so a 16-byte entry needs 1 + 16 bytes
        // plus one for the new terminator.
        assert_eq!(
            h.append_entry(&[0xAA; 16]),
            Err(Error::InsufficientBuffer { required: 18 })
        );
        assert_eq!(h.header.terminator_offset() as usize, HDR + 1, "unchanged");
    }

    /// The entry itself fits exactly, but the terminator that must follow it
    /// does not. The reserved byte for the terminator has to be part of the
    /// bounds check.
    #[test]
    fn append_entry_leaves_room_for_the_terminator() {
        let mut region = Region::<8>::blank();
        let mut h = region.initialized();

        // content index 1 + 7 bytes == content.len(): the entry fits, the
        // terminator at index 8 does not.
        assert_eq!(
            h.append_entry(&[0xAA; 7]),
            Err(Error::InsufficientBuffer { required: 9 })
        );

        // One byte less is the largest entry that does fit.
        assert_eq!(h.append_entry(&[0xAA; 6]), Ok(()));
        assert_eq!(h.content[term_index(&h)], 0xFF);
        assert_eq!(term_index(&h), 7);
    }

    #[test]
    fn reserve_entry_rejects_a_zero_sized_entry() {
        let mut region = Region::<64>::blank();
        assert!(matches!(
            region.initialized().reserve_entry(0, None),
            Err(Error::InvalidArgument)
        ));
    }

    #[test]
    fn reserve_entry_validates_before_touching_content() {
        let mut region = Region::<64>::blank();
        assert!(matches!(
            region.handover().reserve_entry(4, None),
            Err(Error::InvalidHandoverHeader)
        ));
        assert_eq!(region.content, [0u8; 64], "content must be untouched");
    }

    #[test]
    fn reserve_entry_leaves_room_for_the_terminator() {
        let mut region = Region::<8>::blank();
        // Tag (1) + entry (6) starting at content index 1 fills the buffer
        // exactly, leaving nowhere for the terminator.
        assert!(matches!(
            region.initialized().reserve_entry(6, Some(TAG_COSE_SIGN1)),
            Err(Error::InsufficientBuffer { required: 9 })
        ));
    }

    #[test]
    fn reserve_entry_writes_tag_and_exposes_the_payload() {
        let mut region = Region::<64>::blank();
        {
            let mut h = region.initialized();
            let mut r = h.reserve_entry(3, Some(TAG_COSE_SIGN1)).unwrap();
            assert_eq!(r.len(), 3, "the proxy exposes the payload, not the tag");
            r.copy_from_slice(&[0xAA, 0xBB, 0xCC]);
            r.commit();
        }
        // Tag then payload then terminator, starting at content index 1.
        assert_eq!(&region.content[..6], &[0x9F, 0xD2, 0xAA, 0xBB, 0xCC, 0xFF]);
        // 1 (skeleton) + 1 (tag) + 3 (payload) == content index 5.
        assert_eq!(region.header.terminator_offset() as usize, HDR + 5);
    }

    #[test]
    fn reserve_entry_without_a_tag_exposes_the_whole_region() {
        let mut region = Region::<64>::blank();
        {
            let mut h = region.initialized();
            let mut r = h.reserve_entry(2, None).unwrap();
            r.copy_from_slice(&[0x11, 0x22]);
            r.commit();
        }
        assert_eq!(&region.content[..4], &[0x9F, 0x11, 0x22, 0xFF]);
        assert_eq!(region.header.terminator_offset() as usize, HDR + 3);
    }

    /// Dropping the proxy uncommitted must restore the structure to exactly
    /// what it looked like before the reservation: same terminator offset, and
    /// no bytes left over from the abandoned region.
    #[test]
    fn dropping_an_uncommitted_reservation_rolls_back() {
        let mut region = Region::<64>::blank();
        {
            let mut h = region.initialized();
            let mut r = h.reserve_entry(3, Some(TAG_COSE_SIGN1)).unwrap();
            r.copy_from_slice(&[0xAA, 0xBB, 0xCC]);
            // no commit
        }
        assert_eq!(
            region.header.terminator_offset() as usize,
            HDR + 1,
            "offset restored"
        );
        assert_eq!(
            region.content[1], 0xFF,
            "terminator back at content index 1"
        );
        assert_eq!(
            &region.content[2..8],
            &[0u8; 6],
            "nothing left of the abandoned region, including its terminator"
        );
    }

    /// The rolled-back region must be reusable, and the second entry must land
    /// where the first one started.
    #[test]
    fn a_rolled_back_reservation_is_reusable() {
        let mut region = Region::<64>::blank();
        {
            let mut h = region.initialized();
            drop(h.reserve_entry(8, Some(TAG_COSE_SIGN1)).unwrap());
        }
        region.handover().append_entry(&[0x42]).unwrap();

        assert_eq!(&region.content[..3], &[0x9F, 0x42, 0xFF]);
        assert_eq!(region.header.terminator_offset() as usize, HDR + 2);
    }

    /// Two certificates are appended in sequence in a real boot, so a
    /// committed reservation must not poison the structure for the next one.
    #[test]
    fn reservations_and_appends_compose() {
        let mut region = Region::<64>::blank();
        {
            let mut h = region.initialized();
            let mut r = h.reserve_entry(2, Some(TAG_COSE_SIGN1)).unwrap();
            r.copy_from_slice(&[0x01, 0x02]);
            r.commit();
        }
        {
            let mut h = region.handover();
            h.append_entry(&[0xD2, 0x03]).unwrap();
            assert_eq!(h.content[term_index(&h)], 0xFF);
        }
        assert_eq!(
            &region.content[..7],
            &[0x9F, 0xD2, 0x01, 0x02, 0xD2, 0x03, 0xFF]
        );
        assert_eq!(region.header.terminator_offset() as usize, HDR + 6);
    }

    #[test]
    fn used_size_counts_header_entries_and_terminator() {
        let mut r = Region::<64>::blank();
        let mut h = r.initialized();
        assert_eq!(h.used_size(), Ok(HDR + 2));
        h.append_entry(&[0xd2, 0x80, 0x00]).unwrap();
        assert_eq!(h.used_size(), Ok(HDR + 5));

        // The terminator may sit in the very last byte of the content.
        let mut r = Region::<5>::blank();
        let mut h = r.initialized();
        h.append_entry(&[0xd2, 0x80, 0x00]).unwrap();
        assert_eq!(h.used_size(), Ok(HDR + 5));
    }

    #[test]
    fn used_size_rejects_what_validate_rejects() {
        let mut r = Region::<64>::stamped();
        r.header.set_version(2);
        assert_eq!(r.handover().used_size(), Err(Error::InvalidHandoverHeader));
        let mut r = Region::<1>::stamped();
        assert_eq!(r.handover().used_size(), Err(Error::InvalidHandoverHeader));
        let mut r = Region::<64>::stamped();
        r.header.set_terminator_offset(u32::MAX);
        assert_eq!(r.handover().used_size(), Err(Error::InvalidHandoverHeader));
    }

    #[test]
    fn missing_cbor_delimiters_are_rejected() {
        // The content does not open an indefinite-length array.
        let mut r = Region::<64>::blank();
        r.initialized();
        r.content[0] = 0x80;
        assert_eq!(r.handover().used_size(), Err(Error::InvalidHandoverHeader));

        // The offset is in range but the byte there is not a CBOR break.
        let mut r = Region::<64>::blank();
        r.initialized().append_entry(&[0xd2, 0x80, 0x00]).unwrap();
        let t = r.header.terminator_offset();
        r.header.set_terminator_offset(t - 1);
        assert_eq!(r.handover().used_size(), Err(Error::InvalidHandoverHeader));

        // Neither is extended.
        let before = r.content;
        assert_eq!(
            r.handover().append_entry(&[0x01]),
            Err(Error::InvalidHandoverHeader)
        );
        assert!(matches!(
            r.handover().reserve_entry(1, None),
            Err(Error::InvalidHandoverHeader)
        ));
        assert_eq!(r.content, before);
    }

    #[test]
    fn a_read_only_view_validates() {
        let mut r = Region::<64>::blank();
        r.initialized().append_entry(&[0xd2, 0x80, 0x00]).unwrap();
        let view = HandoverRef::new(&r.header, &r.content).unwrap();
        assert_eq!(view.used_size(), Ok(HDR + 5));
    }
}
