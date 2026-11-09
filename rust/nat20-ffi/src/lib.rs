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
//! deliberately coarse-grained: the two boot-stage operations (device-identity
//! COSE_Key; next-stage CWT + next CDI) plus a public-key helper.
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
//!
//! # Crypto
//!
//! The integrator plugs in the crypto backend as a table of functions,
//! [`N20rCrypto`] (`n20r_crypto_t`), passed to every call that needs it.
//! Keys are opaque handles of that backend, so the library never sees a
//! secret: the root CDI comes in as a handle, and the next CDI goes out as
//! one. The backend must keep the contract in `nat20_rust.h`, which
//! includes wiping what it leaves on the stack, and needs at most three
//! key slots (`nat20::MIN_KEY_SLOTS`). The `soft-crypto` feature adds a
//! ready-made software backend ([`soft`]).

// Unit tests link std on the host; every other build is no_std.
#![cfg_attr(not(test), no_std)]
#![deny(missing_docs)]
// A panic would cut short the wiping of secrets (see nat20::crypto), so
// none may be written; these lints catch the obvious ones.
#![cfg_attr(
    not(test),
    deny(
        clippy::indexing_slicing,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic
    )
)]

use core::mem::{align_of, size_of};
use core::slice;

use nat20::derive::{attest_public_key, issue_device_id_key, issue_next_stage_cwt};
use nat20::handover::{HandoverHeader, HandoverStruct, TAG_COSE_SIGN1, TAG_DEVICE_ID_COSE_KEY};
use nat20::open_dice::OpenDiceInput;
use nat20::{Crypto as _, Error};

mod cbuf;
pub mod crypto;
mod ctx;
#[cfg(feature = "soft-crypto")]
pub mod soft;

use crypto::{CCrypto, CKey};
pub use crypto::{N20rCrypto, N20rKey, N20rSlice};

use cbuf::{CBuf, CDrop};
use ctx::DiceCtx;

/// Context size published to C as `N20R_DICE_CTX_SIZE`.
///
/// Deliberately larger than the structure needs, so the header stays stable
/// across layout changes; [`n20r_ctx_init`] rejects a buffer smaller than the
/// structure actually requires, and the assertion at the end of this file
/// keeps the two in step.
pub const N20R_DICE_CTX_SIZE: usize = 256;

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
    let (header, content) = raw
        .split_at_mut_checked(size_of::<HandoverHeader>())
        .ok_or(Error::InvalidArgument)?;
    // SAFETY: `header` is exactly one header long and aligned for it (checked
    // above). `HandoverHeader` is `repr(C)` over `[u8; 4]` and three `u32`,
    // so every bit pattern is a valid value; whether the contents are
    // meaningful is for the handover code to check.
    let header = &mut *header.as_mut_ptr().cast::<HandoverHeader>();
    // One slice was split, so header and content are contiguous.
    HandoverStruct::new(header, content)
}

/// Issues a chain entry into the handover: queries its exact size with
/// `issue(None)`, reserves an entry tagged `tag` of that size, writes
/// the certificate into it with `issue(Some(entry))`, and commits it. On any
/// error the handover is left as it was.
fn issue_into(
    handover: &mut HandoverStruct,
    tag: &[u8],
    mut issue: impl FnMut(Option<&mut [u8]>) -> Result<usize, Error>,
) -> Result<(), Error> {
    let size = match issue(None) {
        Err(Error::InsufficientBuffer { required }) => required,
        Err(e) => return Err(e),
        // A size query that yields no size: the size contract is broken.
        Ok(_) => return Err(Error::CertificateSizeMismatch),
    };
    let mut entry = handover.reserve_entry(size, Some(tag))?;
    let written = issue(Some(&mut entry))?;
    // The certificate is written backward from the end of the buffer, so a
    // short one would leave a gap at the front of the entry.
    if written != size {
        return Err(Error::CertificateSizeMismatch);
    }
    entry.commit();
    Ok(())
}

/// Starts the chain with the device identity: the attestation public key
/// of the root CDI, a key of `crypto`, as a COSE_Key under tag 80152.
///
/// This **initialises** the handover, discarding anything already in it, so
/// it must be called first; [`n20r_issue_next_stage_cwt`] then appends to the
/// same region. It takes no DICE context: the device identity derives from
/// the CDI alone. All arguments are checked before the region is touched;
/// once they pass, the region is initialised even if issuing then fails,
/// which leaves an empty handover. `cdi` stays the caller's.
///
/// # Safety
/// `crypto` must be null (rejected) or a table that meets the contract in
/// `nat20_rust.h`, and `cdi` a key of it. Pointer/size arguments must
/// satisfy the contract in `nat20_rust.h`.
#[no_mangle]
pub unsafe extern "C" fn n20r_issue_device_id_key(
    crypto: *const N20rCrypto,
    cdi: N20rKey,
    handover: *mut u8,
    handover_size: usize,
) -> N20rError {
    status((|| {
        // Every argument is checked before `init()` discards the region's
        // contents, so a bad call leaves an existing chain intact. After
        // that the region is this call's: the device identity always starts
        // the chain.

        // SAFETY: the caller guarantees `crypto` is null or a valid table.
        let mut crypto = CCrypto::from_raw(crypto)?;
        let root_cdi = CKey(cdi);
        // SAFETY: the caller guarantees `handover`/`handover_size` describe a
        // writable region that nothing else accesses during the call, which
        // is what `handover_arg` requires; the struct does not outlive it.
        let mut handover = handover_arg(handover, handover_size)?;

        handover.init()?;
        issue_into(&mut handover, TAG_DEVICE_ID_COSE_KEY, |buf| {
            issue_device_id_key(&mut crypto, &root_cdi, buf)
        })
    })())
}

/// Derives the next-stage CDI and issues the next-stage CWT, signed by the
/// device-identity key, appending it to the handover.
///
/// The certificate carries the open-DICE claims held in `ctx`. The handover
/// must already hold the chain (see [`n20r_issue_device_id_key`]). On
/// success `*next_cdi_out` is the next CDI, a key of `crypto` that the
/// caller owns and frees; on error it is unchanged and every key the call
/// derived is freed. `cdi` stays the caller's.
///
/// # Safety
/// `crypto` and `cdi` as for [`n20r_issue_device_id_key`]. `ctx` must be a
/// context prepared by [`n20r_ctx_init`], and every buffer registered in it
/// must still satisfy the contract documented on the setters. The other
/// pointer/size arguments must satisfy the contract in `nat20_rust.h`.
#[no_mangle]
pub unsafe extern "C" fn n20r_issue_next_stage_cwt(
    crypto: *const N20rCrypto,
    ctx: *mut u8,
    cdi: N20rKey,
    next_cdi_out: *mut N20rKey,
    handover: *mut u8,
    handover_size: usize,
) -> N20rError {
    status((|| {
        if next_cdi_out.is_null() {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: as in `n20r_issue_device_id_key`.
        let mut crypto = CCrypto::from_raw(crypto)?;
        let root_cdi = CKey(cdi);
        // SAFETY: the caller guarantees `ctx` is a context prepared by
        // `n20r_ctx_init`.
        let ctx = DiceCtx::from_raw(ctx)?;
        // SAFETY: as in `n20r_issue_device_id_key`.
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
        // The size query derives no key; the real issue hands one back.
        let mut next_cdi = None;
        let result = issue_into(&mut handover, TAG_COSE_SIGN1, |buf| {
            let (n, key) = issue_next_stage_cwt(&mut crypto, &root_cdi, &dice_input, buf)?;
            next_cdi = Some(key);
            Ok(n)
        });
        match (result, next_cdi) {
            (Ok(()), Some(key)) => {
                // SAFETY: null was rejected at the top, and the caller
                // guarantees it is writable.
                *next_cdi_out = key.0;
                Ok(())
            }
            (result, key) => {
                if let Some(key) = key {
                    crypto.key_free(key);
                }
                result.and(Err(Error::CertificateSizeMismatch))
            }
        }
    })())
}

/// Writes the 32-byte device-identity public key for the root CDI, a key of
/// `crypto` (e.g. for provisioning).
///
/// # Safety
/// `crypto` and `cdi` as for [`n20r_issue_device_id_key`];
/// `public_key_out` must be null (rejected) or point to 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn n20r_device_id_public_key(
    crypto: *const N20rCrypto,
    cdi: N20rKey,
    public_key_out: *mut u8,
) -> N20rError {
    status((|| {
        if public_key_out.is_null() {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: as in `n20r_issue_device_id_key`.
        let mut crypto = CCrypto::from_raw(crypto)?;
        // SAFETY: null was rejected above, and the caller guarantees 32
        // writable bytes; `[u8; 32]` has alignment 1.
        let public_key = &mut *public_key_out.cast::<[u8; 32]>();
        attest_public_key(&mut crypto, &CKey(cdi), public_key)?;
        Ok(())
    })())
}

// Compile-time locks on the C-visible ABI (checked on every build, including
// cross builds, so they guard the actual target layout).
const _: () = {
    assert!(core::mem::size_of::<N20rError>() == 4);
    // `N20R_DICE_CTX_SIZE` in nat20_rust.h must cover the real structure.
    assert!(DiceCtx::required_size() <= N20R_DICE_CTX_SIZE);
    // n20r_slice_t and n20r_crypto_t in nat20_rust.h: pointers and sizes.
    assert!(size_of::<N20rSlice>() == 2 * size_of::<usize>());
    assert!(size_of::<N20rCrypto>() == 6 * size_of::<usize>());
};

/// Panic handler: this crate produces a final staticlib artifact, so it must
/// supply one (there is no std). `panic-loop` spins forever (and prints
/// nothing — it must not depend on any environment symbols).
#[cfg(feature = "panic-loop")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[cfg(test)]
mod ctx_tests;
#[cfg(test)]
mod tests;
