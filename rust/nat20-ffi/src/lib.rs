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

//! C ABI for the nat20 Rust library, intended for linking into boot firmware.
//!
//! See `include/nat20_rust.h` for the C-side contract. The API is
//! deliberately coarse-grained: the two boot-stage operations (self-signed
//! device-identity CWT; next-stage CWT + next CDI) plus a public-key helper.
//! No key handles cross the FFI boundary.
//!
//! # The DICE context
//!
//! Open-DICE measurements become available at different points in a boot, so
//! they are accumulated in a context before the certificate commits them.
//! The library holds no global state: the C caller provides the storage,
//! [`n20r_ctx_init`] stamps it, and the `n20r_set_*` functions and
//! [`n20r_issue_next_stage_cwt`] take it back as a `uint8_t *`. Every access
//! verifies the stamp, so using an uninitialised context is a reported
//! `InvalidArgument` rather than silent garbage. [`n20r_ctx_cleanup`]
//! releases any adopted buffers and invalidates the stamp.
//!
//! Each setter takes a (pointer, size) pair and an optional destructor: with
//! a destructor the buffer is adopted and released when the field is
//! replaced or the context is cleaned up; without one it is borrowed and
//! must stay valid, and must not be mutated, until that same point. A null
//! pointer clears the field. Fields never set are empty.
//!
//! Certificates are not returned in a caller buffer: both issue functions
//! append them to a DICE handover (`HANDOVER.md`) as entries, sizing each
//! entry to the certificate before writing it in place, so there is no
//! size-negotiation call and nothing is moved afterwards. The wire bytes are
//! identical to those C libnat20 produces.

// Unit tests link std on the host; every other build is no_std.
#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]

use core::mem::{align_of, size_of};
use core::slice;

use nat20::cbor::{write_bytes, write_header, write_map_header, write_text_bytes, Major};
use nat20::crypto::Seed32;
use nat20::derive::{attest_key_seed, issue_device_id_cwt, issue_next_stage_cwt, CdiSecret};
use nat20::handover::{HandoverHeader, HandoverStruct, TAG_COSE_SIGN1};
use nat20::open_dice::OpenDiceInput;
use nat20::stream::WStream;
use nat20::Ed25519Signer as _;
use nat20::Error;

mod cbuf;
mod ctx;

use cbuf::{CBuf, CDrop};
use ctx::DiceCtx;

/// Context size published to C as `N20R_DICE_CTX_SIZE`.
///
/// Deliberately larger than the structure needs, so the header stays stable
/// across layout changes; [`n20r_ctx_init`] rejects a buffer smaller than the
/// structure actually requires, and the assertion at the end of this file
/// keeps the two in step.
pub const N20R_DICE_CTX_SIZE: usize = 256;

#[cfg(feature = "mono-crypto")]
fn crypto_backend() -> Result<nat20::crypto::mono::MonoCrypto, Error> {
    nat20::crypto::mono::MonoCrypto::new()
        .map_err(|_| Error::Crypto(nat20::CryptoError::InitializationFailed))
}

#[cfg(all(feature = "soft-crypto", not(feature = "mono-crypto")))]
fn crypto_backend() -> Result<nat20::crypto::soft::SoftCrypto, Error> {
    Ok(nat20::crypto::soft::SoftCrypto)
}

/// Error codes returned across the C ABI.
///
/// `InsufficientBuffer` has the same numeric value as the C library's
/// `n20_error_insufficient_buffer_size_e` (3).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum N20rError {
    /// Success.
    Ok = 0,
    /// The handover region cannot fit another entry of the required size.
    InsufficientBuffer = 3,
    /// A pointer/size/enum argument violates the documented contract, or the
    /// context was never initialised.
    InvalidArgument = 4,
    /// The crypto backend failed.
    Crypto = 5,
    /// A certificate came out a different size than its size query
    /// predicted; nothing was appended.
    CertificateSizeMismatch = 6,
}

fn into_n20r_error(e: Error) -> N20rError {
    match e {
        Error::InsufficientBuffer { .. } => N20rError::InsufficientBuffer,
        // A caller-supplied region that is not a well-formed handover
        // structure is an argument that violates the documented contract.
        Error::InvalidArgument | Error::InvalidHandoverHeader => N20rError::InvalidArgument,
        Error::Crypto(_) => N20rError::Crypto,
        Error::CertificateSizeMismatch => N20rError::CertificateSizeMismatch,
    }
}

fn status<T>(res: Result<T, Error>) -> N20rError {
    res.map_or_else(into_n20r_error, |_| N20rError::Ok)
}

/// Bytes of stack each secret-handling entry point zeroes before it
/// returns: the deepest use `tools/stack-probe.sh` measures for the backend
/// on armv7 Thumb-2 (2224 bytes on Monocypher, 6576 on the soft backend,
/// both in `n20r_issue_next_stage_cwt`), plus margin. The probe fails if a
/// call ever outgrows it.
#[cfg(feature = "mono-crypto")]
pub const N20R_STACK_SCRUB_SIZE: usize = 3072;
/// See the `mono-crypto` variant.
#[cfg(not(feature = "mono-crypto"))]
pub const N20R_STACK_SCRUB_SIZE: usize = 8192;

/// Runs `f`, an entry point's body that handles secrets, then zeroes the
/// stack it used, on success and on error alike.
///
/// The secret containers wipe themselves on drop, but moves, register spills
/// and the crypto backends' own locals leave copies in dead stack frames that
/// no destructor sees. `f` runs in a frame of its own below this one
/// ([`run_unscrubbed`] is never inlined), so whatever it leaves lies within
/// [`N20R_STACK_SCRUB_SIZE`] bytes below this frame, which `zeroize_stack`
/// then overwrites. This is best effort: it relies on `inline(never)` being
/// honoured and on the size covering the real depth, both of which the stack
/// probe checks on the target. Registers are not cleared.
///
/// The `nat20_no_stack_scrub` cfg exists only so the probe can show what is
/// left without the scrub; never set it in a real build.
fn scrubbed(f: impl FnOnce() -> Result<(), Error>) -> N20rError {
    let rc = run_unscrubbed(f);
    #[cfg(not(nat20_no_stack_scrub))]
    zeroize::zeroize_stack::<N20R_STACK_SCRUB_SIZE>();
    rc
}

/// See [`scrubbed`].
#[inline(never)]
fn run_unscrubbed(f: impl FnOnce() -> Result<(), Error>) -> N20rError {
    status(f())
}

/// Prepares a caller-provided buffer for use as a DICE context.
///
/// Must be called before any `n20r_set_*` or [`n20r_issue_next_stage_cwt`]
/// call that names this buffer. Rejects a null, misaligned or undersized
/// buffer with `InvalidArgument`: the buffer must be aligned for a pointer,
/// and `size` must cover the context structure — a buffer of
/// [`N20R_DICE_CTX_SIZE`] bytes always does, whatever the current layout.
///
/// Re-initialising a context that still holds adopted buffers discards their
/// destructors — call [`n20r_ctx_cleanup`] first if that is possible.
///
/// # Safety
/// `ctx` must be null (rejected) or valid for writes of `size` bytes, and
/// must stay valid and unaliased for as long as the context is in use.
#[no_mangle]
pub unsafe extern "C" fn n20r_ctx_init(ctx: *mut u8, size: usize) -> N20rError {
    // SAFETY: the requirements are this function's own, passed through.
    status(DiceCtx::init(ctx, size))
}

/// Releases every buffer the context adopted and invalidates it.
///
/// Runs the destructor of each adopted field, forgets the borrowed ones, and
/// clears the stamp, so a later use without re-initialising is rejected.
///
/// # Safety
/// `ctx` must be null (rejected) or a context previously prepared by
/// [`n20r_ctx_init`]. Afterwards none of the caller's registered buffers are
/// referenced any more.
#[no_mangle]
pub unsafe extern "C" fn n20r_ctx_cleanup(ctx: *mut u8) -> N20rError {
    // SAFETY: the requirements are this function's own, passed through.
    status(DiceCtx::cleanup(ctx))
}

/// Defines `n20r_set_<field>`, which registers a buffer in a context field.
macro_rules! buffer_setter {
    ($(#[$doc:meta])* $name:ident => $field:ident) => {
        $(#[$doc])*
        ///
        /// # Safety
        /// `ctx` must be a context prepared by [`n20r_ctx_init`]. `data` must
        /// be null (clearing the field), or point to `size` readable bytes
        /// that stay valid and unmodified until the field is replaced or the
        /// context is cleaned up. A non-null `drop` transfers ownership and
        /// is invoked exactly once with `data` at that point. Ownership
        /// transfers only on `Ok`; on an error `drop` is not called and the
        /// buffer stays the caller's.
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            ctx: *mut u8,
            data: *const u8,
            size: usize,
            drop: Option<CDrop>,
        ) -> N20rError {
            // SAFETY: both calls inherit this function's documented contract.
            // Assigning drops the previous value, running its destructor.
            status(DiceCtx::from_raw(ctx).map(|ctx| {
                ctx.$field = CBuf::from_raw_parts(data, size, drop);
            }))
        }
    };
}

buffer_setter!(
    /// Sets the code hash: the measurement of the next stage's code.
    n20r_set_code_hash => code_hash
);
buffer_setter!(
    /// Sets the code descriptor: free-form detail about the code the hash
    /// covers.
    n20r_set_code_descriptor => code_descriptor
);
buffer_setter!(
    /// Sets the configuration hash: the measurement of the next stage's
    /// configuration.
    n20r_set_configuration_hash => configuration_hash
);
buffer_setter!(
    /// Sets the configuration descriptor: the configuration the hash covers,
    /// or, without a hash, the inline configuration value itself.
    n20r_set_configuration_descriptor => configuration_descriptor
);
buffer_setter!(
    /// Sets the authority hash: the measurement of the key or policy that
    /// authorised the next stage.
    n20r_set_authority_hash => authority_hash
);
buffer_setter!(
    /// Sets the authority descriptor: free-form detail about the authority
    /// the hash covers.
    n20r_set_authority_descriptor => authority_descriptor
);
buffer_setter!(
    /// Sets the profile name claim. Should be UTF-8; written verbatim, not
    /// validated.
    n20r_set_profile_name => profile_name
);
buffer_setter!(
    /// Sets the hidden input: a secret mixed into the next-stage CDI
    /// derivation without appearing in the certificate.
    n20r_set_hidden => hidden
);

/// Sets the open-DICE mode: 0 not-configured, 1 normal, 2 debug, 3 recovery.
///
/// Any other value is rejected with `InvalidArgument` and leaves the previous
/// mode in place. A context that never sets a mode reports not-configured.
///
/// # Safety
/// `ctx` must be a context prepared by [`n20r_ctx_init`].
#[no_mangle]
pub unsafe extern "C" fn n20r_set_mode(ctx: *mut u8, mode: u8) -> N20rError {
    // SAFETY: inherits this function's documented contract.
    status(DiceCtx::from_raw(ctx).and_then(|ctx| ctx.set_mode(mode)))
}

/// Interprets a (pointer, size) pair as a slice. A null pointer is an empty
/// slice whatever the size, as it is for the context setters.
///
/// # Safety
/// A non-null `ptr` must point to `size` readable bytes for `'a`.
unsafe fn slice_arg<'a>(ptr: *const u8, size: usize) -> &'a [u8] {
    if ptr.is_null() {
        &[]
    } else {
        // SAFETY: non-null, and the caller guarantees `size` readable bytes
        // for `'a`.
        slice::from_raw_parts(ptr, size)
    }
}

/// Copies the 32-byte root CDI out of caller memory into `cdi`, a zeroizing
/// container, directly rather than through a temporary.
///
/// # Safety
/// `ptr` must be null (rejected) or point to 32 readable bytes.
unsafe fn cdi_arg(ptr: *const u8, cdi: &mut CdiSecret) -> Result<(), Error> {
    if ptr.is_null() {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: null was rejected above, and the caller guarantees 32 readable
    // bytes. The slice is only read, and is dropped before returning.
    cdi.as_mut_bytes()
        .copy_from_slice(slice::from_raw_parts(ptr, 32));
    Ok(())
}

/// Rejects a handover region that is null, too small for the header, or
/// misaligned for it.
fn check_handover_region(raw: *const u8, raw_size: usize) -> Result<(), Error> {
    if raw.is_null()
        || raw_size < size_of::<HandoverHeader>()
        || !(raw as usize).is_multiple_of(align_of::<HandoverHeader>())
    {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Splits a caller-supplied region into a [`HandoverHeader`] and the content
/// that follows it. Rejects a null region, one too small for the header, and
/// one misaligned for it. Nothing is read or written.
///
/// # Safety
/// `raw` must be null (rejected) or valid for reads and writes of `raw_size`
/// bytes, unaliased for as long as the returned [`HandoverStruct`] lives.
unsafe fn handover_arg<'b>(raw: *mut u8, raw_size: usize) -> Result<HandoverStruct<'b>, Error> {
    check_handover_region(raw, raw_size)?;
    // SAFETY: null was rejected above; the rest is exactly this function's
    // own contract, which its caller guarantees.
    let raw = slice::from_raw_parts_mut(raw, raw_size);
    let (header, content) = raw.split_at_mut(size_of::<HandoverHeader>());
    // SAFETY: `header` is exactly one header long and aligned for it (checked
    // above). `HandoverHeader` is `repr(C)` over `[u8; 4]` and three `u32`,
    // so every bit pattern is a valid value; whether the contents are
    // meaningful is for the handover code to check.
    let header = &mut *header.as_mut_ptr().cast::<HandoverHeader>();
    // One slice was split, so header and content are contiguous.
    HandoverStruct::new(header, content)
}

/// Issues a certificate into a handover entry: queries its exact size with
/// `issue(None)`, reserves an entry tagged COSE_Sign1 of that size, writes
/// the certificate into it with `issue(Some(entry))`, and commits it. On any
/// error the handover is left as it was.
fn issue_into(
    handover: &mut HandoverStruct,
    mut issue: impl FnMut(Option<&mut [u8]>) -> Result<usize, Error>,
) -> Result<(), Error> {
    let size = match issue(None) {
        Err(Error::InsufficientBuffer { required }) => required,
        Err(e) => return Err(e),
        // A size query that yields no size: the size contract is broken.
        Ok(_) => return Err(Error::CertificateSizeMismatch),
    };
    let mut entry = handover.reserve_entry(size, Some(TAG_COSE_SIGN1))?;
    let written = issue(Some(&mut entry))?;
    // The certificate is written backward from the end of the buffer, so a
    // short one would leave a gap at the front of the entry.
    if written != size {
        return Err(Error::CertificateSizeMismatch);
    }
    entry.commit();
    Ok(())
}

/// Issues the self-signed device-identity CWT from the 32-byte root CDI and
/// appends it to the handover.
///
/// This **initialises** the handover, discarding anything already in it, so
/// it must be called first; [`n20r_issue_next_stage_cwt`] then appends to the
/// same region. It takes no DICE context: the device identity derives from
/// the CDI alone. All arguments are checked before the region is touched;
/// once they pass, the region is initialised even if issuing then fails,
/// which leaves an empty handover.
///
/// # Safety
/// Pointer/size arguments must satisfy the contract in `nat20_rust.h`.
#[no_mangle]
pub unsafe extern "C" fn n20r_issue_device_id_cwt(
    cdi: *const u8,
    profile_name: *const u8,
    profile_name_size: usize,
    handover: *mut u8,
    handover_size: usize,
) -> N20rError {
    scrubbed(|| {
        // Every argument is checked before `init()` discards the region's
        // contents, so a bad call leaves an existing chain intact. After
        // that the region is this call's: the device identity always starts
        // the chain.

        let mut root_cdi = CdiSecret::default();
        // SAFETY: the caller guarantees `cdi` is null or points to 32
        // readable bytes.
        cdi_arg(cdi, &mut root_cdi)?;
        // SAFETY: the caller guarantees `profile_name` is null or points to
        // `profile_name_size` readable bytes for the duration of the call.
        // Empty omits the claim.
        let profile = slice_arg(profile_name, profile_name_size);
        let profile = (!profile.is_empty()).then_some(profile);
        // SAFETY: the caller guarantees `handover`/`handover_size` describe a
        // writable region that nothing else accesses during the call, which
        // is what `handover_arg` requires; the struct does not outlive it.
        let mut handover = handover_arg(handover, handover_size)?;
        let mut crypto = crypto_backend()?;

        handover.init()?;
        issue_into(&mut handover, |buf| {
            issue_device_id_cwt(&mut crypto, &root_cdi, profile, buf)
        })
    })
}

/// Derives the next-stage CDI and issues the next-stage CWT, signed by the
/// device-identity key, appending it to the handover.
///
/// The certificate carries the open-DICE claims held in `ctx`. The handover
/// must already hold the chain (see [`n20r_issue_device_id_cwt`]).
/// `next_cdi_out` is written only on success.
///
/// # Safety
/// `ctx` must be a context prepared by [`n20r_ctx_init`], and every buffer
/// registered in it must still satisfy the contract documented on the
/// setters. The other pointer/size arguments must satisfy the contract in
/// `nat20_rust.h`.
#[no_mangle]
pub unsafe extern "C" fn n20r_issue_next_stage_cwt(
    ctx: *mut u8,
    cdi: *const u8,
    next_cdi_out: *mut u8,
    handover: *mut u8,
    handover_size: usize,
) -> N20rError {
    scrubbed(|| {
        if next_cdi_out.is_null() {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: the caller guarantees `ctx` is a context prepared by
        // `n20r_ctx_init`.
        let ctx = DiceCtx::from_raw(ctx)?;
        let mut root_cdi = CdiSecret::default();
        // SAFETY: as in `n20r_issue_device_id_cwt`.
        cdi_arg(cdi, &mut root_cdi)?;
        // SAFETY: as in `n20r_issue_device_id_cwt`.
        let mut handover = handover_arg(handover, handover_size)?;
        // SAFETY: every buffer registered in the context must still be valid
        // and unmodified — the setters' contract, inherited here. The borrows
        // end with this call.
        let dice_input = OpenDiceInput {
            code_hash: ctx.code_hash.as_slice(),
            code_descriptor: ctx.code_descriptor.as_slice(),
            configuration_hash: ctx.configuration_hash.as_slice(),
            configuration_descriptor: ctx.configuration_descriptor.as_slice(),
            authority_hash: ctx.authority_hash.as_slice(),
            authority_descriptor: ctx.authority_descriptor.as_slice(),
            mode: ctx.mode()?,
            profile_name: ctx.profile_name.as_slice(),
            hidden: ctx.hidden.as_slice(),
        };
        let mut crypto = crypto_backend()?;

        let mut next_cdi = CdiSecret::default();
        issue_into(&mut handover, |buf| {
            issue_next_stage_cwt(&mut crypto, &root_cdi, &dice_input, &mut next_cdi, buf)
        })?;
        // SAFETY: null was rejected at the top, and the caller guarantees 32
        // writable bytes that no other argument overlaps.
        slice::from_raw_parts_mut(next_cdi_out, 32).copy_from_slice(next_cdi.as_bytes());
        Ok(())
    })
}

/// Writes the 32-byte device-identity public key for the given root CDI
/// (e.g. for provisioning).
///
/// # Safety
/// `cdi` must point to 32 readable bytes and `public_key_out` to 32
/// writable bytes.
#[no_mangle]
pub unsafe extern "C" fn n20r_device_id_public_key(
    cdi: *const u8,
    public_key_out: *mut u8,
) -> N20rError {
    scrubbed(|| {
        if public_key_out.is_null() {
            return Err(Error::InvalidArgument);
        }
        let mut root_cdi = CdiSecret::default();
        // SAFETY: the caller guarantees `cdi` is null or points to 32
        // readable bytes.
        cdi_arg(cdi, &mut root_cdi)?;
        let mut crypto = crypto_backend()?;
        let mut seed = Seed32::default();
        attest_key_seed(&mut crypto, &root_cdi, &mut seed)?;
        let mut pk = [0u8; 32];
        crypto.public_key(&seed, &mut pk)?;
        // SAFETY: null was rejected above, and the caller guarantees 32
        // writable bytes.
        slice::from_raw_parts_mut(public_key_out, 32).copy_from_slice(&pk);
        Ok(())
    })
}

/// Validates a DICE handover left by an earlier stage, and reports how many
/// bytes of it are in use.
///
/// Checks the header and that the content is a CBOR indefinite-length array
/// closed at the terminator offset (see `HANDOVER.md`); entries are not
/// parsed. On success `*used` is the number of bytes in use: header, entries
/// and terminator. A malformed structure, including a region too small for
/// the header or misaligned for it, returns `InvalidArgument` with `*used`
/// unchanged. The region is not modified.
///
/// # Safety
/// `handover` must be null (rejected) or point to `handover_size` readable
/// bytes that nothing writes during the call. `used` must be null (rejected)
/// or point to a writable `usize`.
#[no_mangle]
pub unsafe extern "C" fn n20r_handover_validate(
    handover: *const u8,
    handover_size: usize,
    used: *mut usize,
) -> N20rError {
    status((|| {
        if used.is_null() {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: the caller guarantees `handover`/`handover_size` describe a
        // readable region that nothing writes during the call, which is what
        // `handover_ref_arg` requires; the view does not outlive it.
        let n = handover_ref_arg(handover, handover_size)?.used_size()?;
        // SAFETY: non-null, and the caller guarantees it is writable.
        *used = n;
        Ok(())
    })())
}

/// Splits a caller-supplied region into a read-only [`HandoverHeader`] and
/// the content that follows it, as [`handover_arg`] does.
///
/// # Safety
/// `raw` must be null (rejected) or valid for reads of `raw_size` bytes that
/// nothing writes for as long as the returned view lives.
unsafe fn handover_ref_arg<'b>(
    raw: *const u8,
    raw_size: usize,
) -> Result<nat20::handover::HandoverRef<'b>, Error> {
    check_handover_region(raw, raw_size)?;
    // SAFETY: null was rejected above; the rest is exactly this function's
    // own contract, which its caller guarantees.
    let raw = slice::from_raw_parts(raw, raw_size);
    let (header, content) = raw.split_at(size_of::<HandoverHeader>());
    // SAFETY: as in `handover_arg`: one header long, aligned for it, and
    // every bit pattern is a valid `HandoverHeader`.
    let header = &*header.as_ptr().cast::<HandoverHeader>();
    // One slice was split, so header and content are contiguous.
    nat20::handover::HandoverRef::new(header, content)
}

/// `N20R_CBOR_UINT`: the entry's value is `uint_value`.
pub const N20R_CBOR_UINT: u32 = 0;
/// `N20R_CBOR_BYTES`: the entry's value is the byte string `data`/`size`.
pub const N20R_CBOR_BYTES: u32 = 2;
/// `N20R_CBOR_TEXT`: the entry's value is the UTF-8 text string `data`/`size`.
pub const N20R_CBOR_TEXT: u32 = 3;

/// One key-value pair of a map encoded by [`n20r_encode_cbor_map`], laid out
/// as `n20r_cbor_map_entry_t` in `nat20_rust.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct N20rCborMapEntry {
    /// The unsigned integer key.
    pub key: u64,
    /// The value when `kind` is `N20R_CBOR_UINT`.
    pub uint_value: u64,
    /// The value when `kind` is `N20R_CBOR_BYTES` or `N20R_CBOR_TEXT`.
    pub data: *const u8,
    /// Length of `data` in bytes.
    pub size: usize,
    /// One of the `N20R_CBOR_*` constants: the CBOR major type of the value.
    pub kind: u32,
}

/// Writes `entries` as a CBOR map, last pair first because the stream writes
/// backward.
///
/// # Safety
/// Every entry must have a valid `kind`, and the `data` of each bytes or text
/// entry must be null or point to `size` readable bytes.
unsafe fn encode_cbor_map(s: &mut WStream, entries: &[N20rCborMapEntry]) {
    for e in entries.iter().rev() {
        let bytes = if e.kind == N20R_CBOR_UINT {
            &[][..]
        } else {
            // SAFETY: guaranteed by our caller.
            slice_arg(e.data, e.size)
        };
        match e.kind {
            N20R_CBOR_UINT => write_header(s, Major::Uint, e.uint_value),
            N20R_CBOR_BYTES => write_bytes(s, bytes),
            // Text is written verbatim, not validated (see write_text_bytes).
            _ => write_text_bytes(s, bytes),
        }
        write_header(s, Major::Uint, e.key);
    }
    write_map_header(s, entries.len() as u64);
}

/// Encodes a CBOR map with unsigned integer keys, such as an open-DICE code
/// or configuration descriptor, into `out`.
///
/// The keys must be strictly ascending, which makes the encoding
/// deterministic (RFC 8949 section 4.2.1). On input `*size` is the capacity
/// of `out`; on success it is the encoded length, and the map starts at
/// `out[0]`. If `out` is null or too small, `*size` is set to the exact
/// length needed and `InsufficientBuffer` is returned with nothing written.
/// Unordered keys or an unknown `kind` return `InvalidArgument` with `*size`
/// unchanged. A null `data` is an empty string, whatever its `size`.
///
/// # Safety
/// `size` must point to a readable and writable `usize`. `entries` must point
/// to `count` readable entries, or may be null when `count` is 0. The `data`
/// of each bytes or text entry must be null or point to `size` readable
/// bytes (text should be UTF-8; it is written verbatim). `out` must be null
/// or point to `*size` writable bytes that do not overlap any entry's data.
#[no_mangle]
pub unsafe extern "C" fn n20r_encode_cbor_map(
    entries: *const N20rCborMapEntry,
    count: usize,
    out: *mut u8,
    size: *mut usize,
) -> N20rError {
    status((|| -> Result<(), Error> {
        if size.is_null() || (entries.is_null() && count != 0) {
            return Err(Error::InvalidArgument);
        }
        let entries = if count == 0 {
            &[]
        } else {
            // SAFETY: non-null, and the caller guarantees `count` readable
            // entries.
            slice::from_raw_parts(entries, count)
        };
        for (i, e) in entries.iter().enumerate() {
            let valid_kind = matches!(e.kind, N20R_CBOR_UINT | N20R_CBOR_BYTES | N20R_CBOR_TEXT);
            if !valid_kind || (i > 0 && e.key <= entries[i - 1].key) {
                return Err(Error::InvalidArgument);
            }
        }

        let mut counter = WStream::counting();
        // SAFETY: the entries were validated above, and the caller
        // guarantees their data.
        encode_cbor_map(&mut counter, entries);
        let required = counter.written();
        // SAFETY: non-null, and the caller guarantees it is readable and
        // writable.
        let capacity = *size;
        *size = required;
        if out.is_null() || capacity < required {
            return Err(Error::InsufficientBuffer { required });
        }
        // SAFETY: non-null, and the caller guarantees `capacity` >= `required`
        // writable bytes that overlap no input. Writing into exactly
        // `required` bytes puts the backward-written map at offset 0.
        let out = slice::from_raw_parts_mut(out, required);
        encode_cbor_map(&mut WStream::new(out), entries);
        Ok(())
    })())
}

// Compile-time locks on the C-visible ABI (checked on every build, including
// cross builds, so they guard the actual target layout).
const _: () = {
    assert!(core::mem::size_of::<N20rError>() == 4);
    // n20r_cbor_map_entry_t in nat20_rust.h.
    assert!(size_of::<N20rCborMapEntry>() == if size_of::<usize>() == 4 { 32 } else { 40 });
    // `N20R_DICE_CTX_SIZE` in nat20_rust.h must cover the real structure.
    assert!(DiceCtx::required_size() <= N20R_DICE_CTX_SIZE);
};

/// Panic handler: this crate produces a final staticlib artifact, so it must
/// supply one (there is no std). `panic-loop` spins forever (and prints
/// nothing — it must not depend on any environment symbols);
/// `panic-putc-hang` prints the panic message and location through the
/// environment's `putc()` and then calls its `hang()`, as U-Boot provides
/// them.
///
/// Note: in artifacts built with `-Cpanic=immediate-abort` (the size-
/// constrained variant, `SLIM=1` with `tools/build-firmware-lib.sh`), panic
/// sites compile to a trap instruction (`udf`) and this handler is never
/// invoked; the message only appears in plain `abort` builds. Rendering
/// the message costs a few KiB of `core::fmt` machinery.
#[cfg(all(feature = "panic-loop", not(feature = "panic-putc-hang")))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(feature = "panic-putc-hang")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write as _;

    extern "C" {
        fn putc(c: core::ffi::c_char);
        fn hang() -> !;
    }

    struct Console;
    impl core::fmt::Write for Console {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            for byte in s.bytes() {
                // SAFETY: the feature's contract: the environment's putc
                // takes any byte value and has no preconditions.
                unsafe { putc(byte as core::ffi::c_char) };
            }
            Ok(())
        }
    }

    // PanicInfo's Display prints "panicked at <file>:<line>:<col>: <msg>".
    let _ = writeln!(Console, "rust: {}", info);
    // SAFETY: the feature's contract: the environment's hang() takes no
    // arguments, never returns, and may be called at any point. Diverging
    // here is what makes this a valid `-> !` panic handler.
    unsafe { hang() }
}

#[cfg(test)]
mod cbor_map_tests;
#[cfg(test)]
mod ctx_tests;
#[cfg(test)]
mod handover_tests;
#[cfg(test)]
mod tests;
