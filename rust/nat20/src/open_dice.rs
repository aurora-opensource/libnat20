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

//! Open Profile for DICE input types, mirroring `n20_open_dice_input_s`
//! (`include/nat20/open_dice.h`).

/// The DICE mode of the target environment
/// (`n20_open_dice_modes_t`; serialized as a single byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// The mode has not been determined.
    NotConfigured = 0,
    /// Normal, verified operation.
    Normal = 1,
    /// Debug facilities are enabled.
    Debug = 2,
    /// Recovery / maintenance mode.
    Recovery = 3,
}

/// Measurements and configuration of the next boot stage.
///
/// All slices are borrowed; empty slices mean "absent" and the corresponding
/// CWT claims are omitted. `hidden` participates in CDI derivation but never
/// appears in the certificate.
#[derive(Clone, Copy)]
pub struct OpenDiceInput<'a> {
    /// Hash of the code of the target environment.
    pub code_hash: &'a [u8],
    /// Descriptor of the code (informational, certificate only).
    pub code_descriptor: &'a [u8],
    /// Hash of the configuration data. If empty, `configuration_descriptor`
    /// is used directly in the CDI derivation instead.
    pub configuration_hash: &'a [u8],
    /// Configuration descriptor. When used inline (no configuration hash),
    /// any size constraint is the profile's to impose, not the library's:
    /// the Open Profile for DICE requires exactly 64 bytes, other DICE
    /// profiles relax that.
    pub configuration_descriptor: &'a [u8],
    /// Hash of the authority that verified the target environment.
    pub authority_hash: &'a [u8],
    /// Descriptor of the authority (informational, certificate only).
    pub authority_descriptor: &'a [u8],
    /// The DICE mode of the target environment.
    pub mode: Mode,
    /// Profile name claim; empty omits it. Should be UTF-8; written verbatim
    /// without validation (see [`crate::cbor::write_text_bytes`]).
    pub profile_name: &'a [u8],
    /// Additional secret input to the CDI derivation (never certified).
    pub hidden: &'a [u8],
}

impl Default for OpenDiceInput<'_> {
    fn default() -> Self {
        OpenDiceInput {
            code_hash: &[],
            code_descriptor: &[],
            configuration_hash: &[],
            configuration_descriptor: &[],
            authority_hash: &[],
            authority_descriptor: &[],
            mode: Mode::NotConfigured,
            profile_name: &[],
            hidden: &[],
        }
    }
}
