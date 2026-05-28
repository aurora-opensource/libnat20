#!/bin/sh

# Copyright 2026 Aurora Operations, Inc.
#
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0
#
# This work is dual licensed.
# You may use it under Apache-2.0 or GPL-2.0 at your option.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# OR
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see
# <https://www.gnu.org/licenses/>.

set -euo pipefail

SCRIPT_DIR="$(dirname "$0")"
export OPENSSL_CONF="${SCRIPT_DIR}/openssl_dice.cnf"

modprobe nat20sw
mount -t securityfs none /sys/kernel/security

echo -n "Test message for ECA EE cert" > message.txt

nat20cli cdi-cert \
    --key-type p256 \
    --parent-key-type p256 \
    --output cdi_0.der \
    --certificate-format x509 \
    --code-desc 795375622d322e332e343a33386334353963666164666132623839353333363939353465313266373534386433613161633937336338383830303563336236646232333436636263386631 \
    --code 228d8f76c811276e991012cf5f46090377fc72c95a6ef9e1ccd4eebec8997be5b57f0fb2c7f4804af212711e7b49533f8bc00ddee9480f76155b3da1101604b9 \
    --conf-desc 45787472616f7264696e617279206e6f726d616c20636f6e66696775726174696f6e \
    --conf 671e957aff5565a55961dcaef7634f1a665d8f286e7bd99593532741417f22981b57bdc39241c9685f7377e3622067c261c3ce974e6db5f18d121adad2d76185 \
    --auth-desc 41206365727469666963617465 \
    --auth 50808e4ab921ecf31ca5f662b6d8b85b98ec4d3f64175c8b5d70c1f0e2fef048f87b3178907e1f2d652bd8588fa84f4c374347cc34b97dae13a5b981790b38cb \
    --mode normal \
    --hidden 2f299d2cc916e5219a6bcbc14c7135fa25e9a71018c2bafe8c0658d4041de6c87aa444aedcc68e7d7674b81b5838be1b74bf19d4d6fb05fb0db9ee7e297afc09
nat20cli cdi-cert \
    --key-type p256 \
    --parent-key-type p256 \
    --output cdi_0.cose \
    --certificate-format cose \
    --code-desc 795375622d322e332e343a33386334353963666164666132623839353333363939353465313266373534386433613161633937336338383830303563336236646232333436636263386631 \
    --code 228d8f76c811276e991012cf5f46090377fc72c95a6ef9e1ccd4eebec8997be5b57f0fb2c7f4804af212711e7b49533f8bc00ddee9480f76155b3da1101604b9 \
    --conf-desc 45787472616f7264696e617279206e6f726d616c20636f6e66696775726174696f6e \
    --conf 671e957aff5565a55961dcaef7634f1a665d8f286e7bd99593532741417f22981b57bdc39241c9685f7377e3622067c261c3ce974e6db5f18d121adad2d76185 \
    --auth-desc 41206365727469666963617465 \
    --auth 50808e4ab921ecf31ca5f662b6d8b85b98ec4d3f64175c8b5d70c1f0e2fef048f87b3178907e1f2d652bd8588fa84f4c374347cc34b97dae13a5b981790b38cb \
    --mode normal \
    --hidden 2f299d2cc916e5219a6bcbc14c7135fa25e9a71018c2bafe8c0658d4041de6c87aa444aedcc68e7d7674b81b5838be1b74bf19d4d6fb05fb0db9ee7e297afc09
nat20cli promote -i 790fd72ee1352017d822773bc8f5c1ac6e4bf310dfac72fbff622368c01372bc78324f0c06cbc37964e32b18588560a386357e4517ffe93052c67fe6213c38bc
nat20cli cdi-cert \
    --key-type p256 \
    --parent-key-type p256 \
    --output cdi_1.der \
    --certificate-format x509 \
    --code-desc 795375622d322e332e343a33386334353963666164666132623839353333363939353465313266373534386433613161633937336338383830303563336236646232333436636263386631 \
    --code 228d8f76c811276e991012cf5f46090377fc72c95a6ef9e1ccd4eebec8997be5b57f0fb2c7f4804af212711e7b49533f8bc00ddee9480f76155b3da1101604b9 \
    --conf-desc 45787472616f7264696e617279206e6f726d616c20636f6e66696775726174696f6e \
    --conf 671e957aff5565a55961dcaef7634f1a665d8f286e7bd99593532741417f22981b57bdc39241c9685f7377e3622067c261c3ce974e6db5f18d121adad2d76185 \
    --auth-desc 41206365727469666963617465 \
    --auth 50808e4ab921ecf31ca5f662b6d8b85b98ec4d3f64175c8b5d70c1f0e2fef048f87b3178907e1f2d652bd8588fa84f4c374347cc34b97dae13a5b981790b38cb \
    --mode normal \
    --hidden 2f299d2cc916e5219a6bcbc14c7135fa25e9a71018c2bafe8c0658d4041de6c87aa444aedcc68e7d7674b81b5838be1b74bf19d4d6fb05fb0db9ee7e297afc09
nat20cli cdi-cert \
    --key-type p256 \
    --parent-key-type p256 \
    --output cdi_1.cose \
    --certificate-format cose \
    --code-desc 795375622d322e332e343a33386334353963666164666132623839353333363939353465313266373534386433613161633937336338383830303563336236646232333436636263386631 \
    --code 228d8f76c811276e991012cf5f46090377fc72c95a6ef9e1ccd4eebec8997be5b57f0fb2c7f4804af212711e7b49533f8bc00ddee9480f76155b3da1101604b9 \
    --conf-desc 45787472616f7264696e617279206e6f726d616c20636f6e66696775726174696f6e \
    --conf 671e957aff5565a55961dcaef7634f1a665d8f286e7bd99593532741417f22981b57bdc39241c9685f7377e3622067c261c3ce974e6db5f18d121adad2d76185 \
    --auth-desc 41206365727469666963617465 \
    --auth 50808e4ab921ecf31ca5f662b6d8b85b98ec4d3f64175c8b5d70c1f0e2fef048f87b3178907e1f2d652bd8588fa84f4c374347cc34b97dae13a5b981790b38cb \
    --mode normal \
    --hidden 2f299d2cc916e5219a6bcbc14c7135fa25e9a71018c2bafe8c0658d4041de6c87aa444aedcc68e7d7674b81b5838be1b74bf19d4d6fb05fb0db9ee7e297afc09
nat20cli promote -i 790fd72ee1352017d822773bc8f5c1ac6e4bf310dfac72fbff622368c01372bc78324f0c06cbc37964e32b18588560a386357e4517ffe93052c67fe6213c38bc
nat20cli eca-cert \
    --key-type p256 \
    --parent-key-type p256 \
    --output eca.der \
    --certificate-format x509 \
    --challenge aabbcc
nat20cli eca-ee-cert \
    --key-type p256 \
    --parent-key-type p256 \
    --output eca_ee.der \
    --certificate-format x509 \
    --challenge aabbcc \
    --name "Test ECA EE Cert" \
    --key-usage sign
nat20cli eca-ee-sign \
    --key-type p256 \
    --parent-key-type p256 \
    --challenge aabbcc \
    --name "Test ECA EE Cert" \
    --key-usage sign \
    --message "$(xxd -p message.txt)" \
    --output eca_ee.sig

openssl x509 -inform der -outform pem -in cdi_0.der -out cdi_0.pem
openssl x509 -inform der -outform pem -in cdi_1.der -out cdi_1.pem
openssl x509 -inform der -outform pem -in eca.der -out eca.pem
openssl x509 -inform der -outform pem -in eca_ee.der -out eca_ee.pem

# The dice chain is formatted as variable length CBOR array
# with each element being a tagged certificate.
# Here, it is assumed the the chain contains only the semi hardcoded UDS certificate
# from the nat20sw example, which is the only certificate in the chain.
# arr (#6.80150 (bytes(DER encoded cert)))
# tail -c+10 strips off the first 9 bytes:
# The variable lenght array header (1 byte 0x9f)
# The certificate tag (5 bytes)
# The bytes header (3 bytes)
# The head -c-1 strips off the last byte, which is the CBOR "break" byte (0xff) for the variable length array.
# The resulting uds_cert.der file is the DER encoded UDS certificate, which can be parsed with standard tools.
tail -c+10 /sys/kernel/security/nat200/dice_chain | head -c-1 > uds_cert.der

openssl x509 -inform der -in uds_cert.der -outform pem -out uds_cert_p256.pem

cat uds_cert_p256.pem cdi_0.pem cdi_1.pem eca.pem > chain.pem

openssl x509 -inform pem -in uds_cert_p256.pem -noout -text
openssl x509 -inform pem -in cdi_0.pem -noout -text
openssl x509 -inform pem -in cdi_1.pem -noout -text
openssl x509 -inform pem -in eca.pem -noout -text
openssl x509 -inform pem -in eca_ee.pem -noout -text


# Make an asn1 spec for generaring a signature that can be verified with OpenSSL.
# The signature is generated by the nat20cli eca-ee-sign command, which produces
# a raw signature (R||S). The ASN.1 spec wraps the raw signature in a structure
# that OpenSSL can parse and verify.
cat << EOF > sig.asn1
asn1 = SEQUENCE:sig_seq

[sig_seq]
r = INTEGER:0x$(head -c 32 eca_ee.sig | xxd -p | tr -d '\n')
s = INTEGER:0x$(tail -c 32 eca_ee.sig | xxd -p | tr -d '\n')
EOF

openssl asn1parse -genconf sig.asn1 -out sig.der

# Verify the certificate chain. The UDS certificate is self-signed, so it is the trust anchor for the chain.
# The -ignore_critical flag is needed to ignore the critical extension in the UDS certificate,
# which is not understood by OpenSSL but is required by the DICE specification. This check
# only verifies the signatures and the certificate format, not the critical extension semantics.
openssl verify -ignore_critical -CAfile chain.pem eca_ee.pem

echo "OpenSSL chain verification passed."

# Extract public key from the ECA EE cert and verify the signature on the message.
openssl x509 -inform pem -in eca_ee.pem -pubkey -noout > eca_ee_pubkey.pem
openssl dgst -sha256 -verify eca_ee_pubkey.pem -signature sig.der message.txt

echo "OpenSSL signature verification passed."