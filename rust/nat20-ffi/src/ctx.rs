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

//! The DICE context: open-DICE input accumulated in caller-owned memory.
//!
//! Measurements become available in several places during a boot — the code
//! hash where the next stage is verified, configuration and authority
//! elsewhere again — so the input has to be collected somewhere before the
//! certificate commits it. This crate keeps no global for that. The C caller
//! provides a byte buffer, [`DiceCtx::init`] stamps it, and every entry point
//! takes it back as a `uint8_t *`.
//!
//! That keeps the library reentrant and instantiable (several contexts can
//! exist at once) and leaves the storage decision — `.bss`, stack, or
//! anywhere else — to the integrator.
//!
//! # Validity
//!
//! The buffer is stamped with a magic and version, checked on every access,
//! so using a context that was never initialised is a reported
//! `InvalidArgument` rather than silent garbage. That check is why
//! zero-filled memory is *not* accepted as an empty context: `.bss` being
//! zeroed would otherwise make "forgot to initialise" indistinguishable from
//! "initialised and empty", and stack storage would read as whatever was
//! there before.

use crate::cbuf::CBuf;
use nat20::open_dice::Mode;
use nat20::Error;

/// Stamped into a context by [`DiceCtx::init`] and verified on every access.
const CTX_MAGIC: [u8; 4] = *b"N20C";

/// Layout version of [`DiceCtx`]; bumped if the structure ever changes.
const CTX_VERSION: u32 = 1;

/// Open-DICE input for the next boot stage, held in caller-owned memory.
///
/// `#[repr(C)]` over integers and [`CBuf`], so every bit pattern is a valid
/// value. That is what makes it sound to reinterpret the caller's bytes as
/// this type before knowing whether it was ever initialised — the magic check
/// then decides whether the contents are *meaningful*.
#[repr(C)]
pub(crate) struct DiceCtx {
    /// [`CTX_MAGIC`] once initialised.
    magic: [u8; 4],
    /// [`CTX_VERSION`] once initialised.
    version: u32,
    /// Size of this structure as the library sees it, for diagnostics.
    size: u32,
    /// Open-DICE mode, held as an integer because an out-of-range
    /// discriminant would make the enum itself invalid; converted on use.
    mode: u32,
    /// Measurement of the next stage's code.
    pub(crate) code_hash: CBuf,
    /// Free-form detail about the code the hash covers.
    pub(crate) code_descriptor: CBuf,
    /// Measurement of the next stage's configuration.
    pub(crate) configuration_hash: CBuf,
    /// The configuration the hash covers, which the verifier reads back.
    pub(crate) configuration_descriptor: CBuf,
    /// Measurement of the key or policy that authorised the next stage.
    pub(crate) authority_hash: CBuf,
    /// Free-form detail about the authority the hash covers.
    pub(crate) authority_descriptor: CBuf,
    /// Profile name claim; should be UTF-8, written verbatim.
    pub(crate) profile_name: CBuf,
    /// Secret mixed into the next-stage CDI without appearing in the
    /// certificate.
    pub(crate) hidden: CBuf,
}

impl DiceCtx {
    /// Bytes a caller must provide. The C header publishes a constant at
    /// least this large; [`DiceCtx::init`] rejects anything smaller.
    pub(crate) const fn required_size() -> usize {
        core::mem::size_of::<DiceCtx>()
    }

    /// Alignment a caller must provide.
    pub(crate) const fn required_align() -> usize {
        core::mem::align_of::<DiceCtx>()
    }

    /// Stamps a caller-provided buffer as an empty context.
    ///
    /// Rejects null, misaligned, or undersized buffers. Any previous
    /// contents are overwritten without being dropped, so re-initialising a
    /// context that still holds adopted buffers leaks their destructors —
    /// call [`DiceCtx::cleanup`] first if that is a possibility.
    ///
    /// # Safety
    /// `raw` must be null (rejected) or valid for writes of `size` bytes and
    /// unaliased for as long as the context is in use.
    pub(crate) unsafe fn init(raw: *mut u8, size: usize) -> Result<(), Error> {
        if raw.is_null()
            || size < Self::required_size()
            || !(raw as usize).is_multiple_of(Self::required_align())
        {
            return Err(Error::InvalidArgument);
        }

        // SAFETY: the checks above establish that `raw` is non-null, aligned
        // and large enough. `write` initialises without reading or dropping
        // whatever was there, which is required because the caller's memory
        // may hold anything at this point.
        core::ptr::write(
            raw.cast::<DiceCtx>(),
            DiceCtx {
                magic: CTX_MAGIC,
                version: CTX_VERSION,
                size: Self::required_size() as u32,
                mode: 0,
                code_hash: CBuf::empty(),
                code_descriptor: CBuf::empty(),
                configuration_hash: CBuf::empty(),
                configuration_descriptor: CBuf::empty(),
                authority_hash: CBuf::empty(),
                authority_descriptor: CBuf::empty(),
                profile_name: CBuf::empty(),
                hidden: CBuf::empty(),
            },
        );
        Ok(())
    }

    /// Borrows an initialised context out of caller memory.
    ///
    /// # Safety
    /// `raw` must be null (rejected) or valid for reads and writes of
    /// [`DiceCtx::required_size`] bytes, unaliased for the returned borrow.
    /// The returned lifetime is unconstrained, so keeping the region alive
    /// is the caller's contract.
    pub(crate) unsafe fn from_raw<'a>(raw: *mut u8) -> Result<&'a mut DiceCtx, Error> {
        if raw.is_null() || !(raw as usize).is_multiple_of(Self::required_align()) {
            return Err(Error::InvalidArgument);
        }
        let ctx = raw.cast::<DiceCtx>();

        // SAFETY: non-null and aligned, per the checks above, and readable
        // per the contract. Only the stamp is read here, through raw place
        // projections, so no reference to a possibly never-initialised
        // structure exists before the stamp vouches for it.
        let (magic, version) = ((*ctx).magic, (*ctx).version);
        if magic != CTX_MAGIC || version != CTX_VERSION {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: the stamp shows `init` wrote a complete `DiceCtx` here;
        // exclusivity is the caller's contract.
        Ok(&mut *ctx)
    }

    /// Releases every buffer the context adopted and invalidates it, so a
    /// later use without re-initialising is rejected.
    ///
    /// # Safety
    /// Same requirements as [`DiceCtx::from_raw`]. Afterwards no buffer
    /// registered in this context is referenced any more.
    pub(crate) unsafe fn cleanup(raw: *mut u8) -> Result<(), Error> {
        let ctx = Self::from_raw(raw)?;
        // Assigning runs `CBuf::drop` on the previous value, which invokes
        // the C destructor of every adopted buffer.
        ctx.code_hash = CBuf::empty();
        ctx.code_descriptor = CBuf::empty();
        ctx.configuration_hash = CBuf::empty();
        ctx.configuration_descriptor = CBuf::empty();
        ctx.authority_hash = CBuf::empty();
        ctx.authority_descriptor = CBuf::empty();
        ctx.profile_name = CBuf::empty();
        ctx.hidden = CBuf::empty();
        ctx.mode = 0;
        ctx.magic = [0; 4];
        Ok(())
    }

    /// Sets the open-DICE mode from its C encoding.
    pub(crate) fn set_mode(&mut self, mode: u8) -> Result<(), Error> {
        if mode > 3 {
            return Err(Error::InvalidArgument);
        }
        self.mode = mode as u32;
        Ok(())
    }

    /// The open-DICE mode as the library's enum.
    pub(crate) fn mode(&self) -> Result<Mode, Error> {
        match self.mode {
            0 => Ok(Mode::NotConfigured),
            1 => Ok(Mode::Normal),
            2 => Ok(Mode::Debug),
            3 => Ok(Mode::Recovery),
            _ => Err(Error::InvalidArgument),
        }
    }
}
