/*
 * pcie-cryptostore crypto constructions (datasheet 10.4), built on QEMU's
 * qcrypto layer. Thread-safe: used from the KDF worker as well as the main
 * loop, and none of it touches device state.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef CRYPTOSTORE_CRYPTO_H
#define CRYPTOSTORE_CRYPTO_H

#include "crypto/cipher.h"
#include "cryptostore_format.h"

#define CS_HASH_LEN     32
#define CS_KEY_LEN      32

/* Wipe @len bytes that must not survive, then verify they read back zero. */
bool cs_wipe(void *p, size_t len);

/* Constant-time compares and the F9 tag verdict live in cryptostore_fi.h. */
#include "cryptostore_fi.h"

int cs_hmac_sha256(const uint8_t *key, size_t nkey,
                   const struct iovec *iov, size_t niov,
                   uint8_t out[CS_HASH_LEN], Error **errp);
int cs_hkdf_extract(const uint8_t *salt, size_t nsalt,
                    const uint8_t *ikm, size_t nikm,
                    uint8_t prk[CS_HASH_LEN], Error **errp);
int cs_hkdf_expand(const uint8_t prk[CS_HASH_LEN],
                   const uint8_t *info, size_t ninfo,
                   uint8_t *okm, size_t nokm, Error **errp);
int cs_pbkdf2(const uint8_t *pw, size_t npw, const uint8_t salt[CSF_SALT_LEN],
              uint32_t iters, uint8_t kek[CS_KEY_LEN], Error **errp);

/* Iterations giving about @ms of PBKDF2 work, clamped to the format limits. */
uint32_t cs_pbkdf2_calibrate(unsigned ms, Error **errp);

/* KEK for a slot: PBKDF2 of the password, or HKDF-Extract of the recovery key. */
int cs_slot_kek(const CsfSlot *slot, const uint8_t *secret, size_t nsecret,
                uint8_t kek[CS_KEY_LEN], Error **errp);

/*
 * Fill slot->wrapped and slot->tag for @dek. The caller has set state, type,
 * kdf, iters and a fresh salt and IV.
 */
int cs_slot_wrap(CsfSlot *slot, const uint8_t kek[CS_KEY_LEN],
                 const uint8_t uuid[CSF_UUID_LEN], unsigned index,
                 const uint8_t dek[CSF_DEK_LEN], Error **errp);

/*
 * Verify the tag (constant time), then unwrap into @dek. Returns 0 with
 * *match set; the tag is checked twice by different code paths (F9) and
 * *fault is set when the two disagree. @force_first_match is a test hook.
 */
int cs_slot_unwrap(const CsfSlot *slot, const uint8_t kek[CS_KEY_LEN],
                   const uint8_t uuid[CSF_UUID_LEN], unsigned index,
                   uint8_t dek[CSF_DEK_LEN], bool *match, bool *fault,
                   bool force_first_match, Error **errp);

/* Header MAC over the fixed fields (0x000-0x0ff, R1). */
int cs_header_mac(const uint8_t dek[CSF_DEK_LEN], const uint8_t uuid[CSF_UUID_LEN],
                  const uint8_t fixed[CSF_MAC_COVER_LEN],
                  uint8_t mac[CSF_MAC_LEN], Error **errp);

/* Data path: AES-256-XTS with plain64 tweak, one 512-byte sector per call. */
QCryptoCipher *cs_xts_new(const uint8_t dek[CSF_DEK_LEN], Error **errp);
int cs_xts_sector(QCryptoCipher *xts, uint64_t sector, bool encrypt,
                  const uint8_t *in, uint8_t *out, Error **errp);

/* Known-answer tests (SR-34). @fail_on_purpose is a test hook. */
int cs_selftest(bool fail_on_purpose, Error **errp);

#endif /* CRYPTOSTORE_CRYPTO_H */
