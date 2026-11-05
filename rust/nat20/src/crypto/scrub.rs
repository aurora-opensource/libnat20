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

//! Wiping what a crypto backend operation leaves behind.
//!
//! [`scrubbed`] is how the built-in backends meet the invariant stated in
//! [`crate::crypto`]: once an operation returns, nothing it derived is left
//! in the stack below its caller or in the registers a call may clobber.

// The register clearing is inline assembly, the only way to do it.
#![allow(unsafe_code)]

/// Runs `body`, one backend operation, then wipes what it left behind: the
/// `N` bytes of stack below the caller's frame, where `body`'s frames were,
/// and the registers a call may clobber.
///
/// `body` runs in a frame of its own below the caller's, so `N` must cover
/// the deepest stack `body` reaches; for the built-in backends,
/// `tools/stack-probe.sh` checks that on the target. `body` must not panic:
/// a panic never returns here, so nothing would be wiped. The
/// `nat20_no_stack_scrub` cfg exists only so the probe can show what the
/// scrub removes; never set it in a real build.
#[inline(always)]
pub fn scrubbed<const N: usize, R>(body: impl FnOnce() -> R) -> R {
    let result = run_unscrubbed(body);
    #[cfg(not(nat20_no_stack_scrub))]
    {
        zeroize::zeroize_stack::<N>();
        clear_scratch_registers();
    }
    result
}

/// See [`scrubbed`]: never inlined, so `body`'s locals live in frames below
/// the caller's.
#[inline(never)]
fn run_unscrubbed<R>(body: impl FnOnce() -> R) -> R {
    body()
}

/// Zeroes the registers a callee may clobber (AAPCS: r0-r3 and r12), which
/// can still hold bytes of a secret the operation computed on. Callee-saved
/// registers are restored by every callee, so they hold the caller's values
/// again. The targets nat20 supports are soft-float, so no FP registers are
/// involved. A no-op on other architectures.
#[cfg(not(nat20_no_stack_scrub))]
#[inline(always)]
fn clear_scratch_registers() {
    #[cfg(target_arch = "arm")]
    // SAFETY: only writes the listed registers, which are declared as
    // clobbered outputs, so the compiler keeps nothing live in them across
    // the block. No memory or stack access.
    unsafe {
        core::arch::asm!(
            "movs r0, #0",
            "movs r1, #0",
            "movs r2, #0",
            "movs r3, #0",
            "mov r12, r0",
            out("r0") _,
            out("r1") _,
            out("r2") _,
            out("r3") _,
            out("r12") _,
            options(nomem, nostack),
        );
    }
}
