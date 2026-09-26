/* SPDX-License-Identifier: GPL-2.0-or-later OR MIT */
/*
 * pcie-cryptostore backing-file format v1 (datasheet section 10).
 *
 * Pure C99 with no QEMU or kernel dependencies, so the same parser runs in
 * the device model, the fuzz harness and host tools (D3, SR-16).
 * All on-disk integers are little-endian.
 */
#ifndef CRYPTOSTORE_FORMAT_H
#define CRYPTOSTORE_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CSF_HDR_SIZE            0x1000u     /* header region */
#define CSF_DATA_OFFSET         0x1000u
#define CSF_SECTOR              512u

#define CSF_MAGIC               "CRYPTOST"
#define CSF_MAGIC_LEN           8
#define CSF_VERSION             1u
#define CSF_CIPHER_XTS_PLAIN64  1u          /* AES-256-XTS, plain64 tweak */

#define CSF_OFF_MAGIC           0x0000u
#define CSF_OFF_VERSION         0x0008u
#define CSF_OFF_UUID            0x000cu
#define CSF_OFF_CAPACITY        0x001cu
#define CSF_OFF_CIPHER          0x0024u
#define CSF_MAC_COVER_LEN       0x0100u     /* header MAC covers 0x000-0x0ff (R1) */
#define CSF_OFF_SLOTS           0x0100u
#define CSF_NUM_SLOTS           8
#define CSF_SLOT_SIZE           256u
#define CSF_OFF_HDR_MAC         0x0900u
#define CSF_OFF_FAIL            0x0f00u
#define CSF_FAIL_SIZE           16u

/* Keyslot field offsets */
#define CSF_SLOT_OFF_STATE      0x00u
#define CSF_SLOT_OFF_TYPE       0x04u
#define CSF_SLOT_OFF_KDF        0x06u
#define CSF_SLOT_OFF_ITERS      0x08u
#define CSF_SLOT_OFF_SALT       0x10u
#define CSF_SLOT_OFF_IV         0x30u
#define CSF_SLOT_OFF_WRAPPED    0x40u
#define CSF_SLOT_OFF_TAG        0x80u
#define CSF_SLOT_TAG_COVER      0x80u       /* tag covers slot bytes 0x00-0x7f */

#define CSF_SLOT_INACTIVE       0x00000000u
#define CSF_SLOT_ACTIVE         0x5a3ca5c3u /* fail-secure constant (SR-21) */
#define CSF_TYPE_PASSWORD       1u
#define CSF_TYPE_RECOVERY       2u
#define CSF_KDF_PBKDF2_SHA256   1u
#define CSF_KDF_HKDF_SHA256     2u

#define CSF_UUID_LEN            16
#define CSF_SALT_LEN            32
#define CSF_IV_LEN              16
#define CSF_DEK_LEN             64
#define CSF_TAG_LEN             32
#define CSF_MAC_LEN             32
#define CSF_RECOVERY_KEY_LEN    32

#define CSF_PBKDF2_MIN_ITERS    600000u     /* OWASP figure for PBKDF2-HMAC-SHA256 (R11) */
#define CSF_PBKDF2_MAX_ITERS    400000000u  /* ~36 s at the dev host's 11M/s (R11, V25) */
#define CSF_MIN_CAPACITY        2048ull     /* 1 MiB */
#define CSF_MAX_CAPACITY        (1ull << 32)

typedef struct CsfSlot {
    uint32_t state;
    uint16_t type;
    uint16_t kdf;
    uint32_t iters;
    uint8_t salt[CSF_SALT_LEN];
    uint8_t iv[CSF_IV_LEN];
    uint8_t wrapped[CSF_DEK_LEN];
    uint8_t tag[CSF_TAG_LEN];
} CsfSlot;

typedef struct CsfHeader {
    uint8_t uuid[CSF_UUID_LEN];
    uint64_t capacity;
    uint16_t cipher;
    CsfSlot slot[CSF_NUM_SLOTS];
    uint8_t hdr_mac[CSF_MAC_LEN];
    uint32_t fail_count;
    bool fail_record_ok;        /* count matched its complement (R7) */
    uint64_t last_attempt_ms;
} CsfHeader;

typedef enum CsfParseResult {
    CSF_UNFORMATTED = 1,        /* header region all zero */
    CSF_VALID = 2,
    CSF_MALFORMED = 3,
} CsfParseResult;

/*
 * Validate a header region in the order of datasheet 10.5 (steps 2-10).
 * @hdr must point at CSF_HDR_SIZE bytes (the caller pads short files with
 * zero, and passes the real size in @file_size). On CSF_MALFORMED, *why
 * names the first failing check; @out is only filled for CSF_VALID.
 */
CsfParseResult csf_parse(const uint8_t *hdr, uint64_t file_size,
                         CsfHeader *out, const char **why);

/* Serialize the MAC-covered fixed fields (0x000-0x0ff) into @out[256]. */
void csf_encode_fixed(const uint8_t uuid[CSF_UUID_LEN], uint64_t capacity,
                      uint8_t out[CSF_MAC_COVER_LEN]);
/* Serialize one keyslot into @out[256]; INACTIVE encodes as all zero. */
void csf_encode_slot(const CsfSlot *slot, uint8_t out[CSF_SLOT_SIZE]);
/* Serialize the failure record into @out[16]. */
void csf_encode_fail(uint32_t count, uint64_t last_ms, uint8_t out[CSF_FAIL_SIZE]);

/* Capacity that FORMAT would give a file of @file_size bytes (0 if too small). */
uint64_t csf_capacity_for_size(uint64_t file_size);

uint16_t csf_le16(const uint8_t *p);
uint32_t csf_le32(const uint8_t *p);
uint64_t csf_le64(const uint8_t *p);
void csf_put_le16(uint8_t *p, uint16_t v);
void csf_put_le32(uint8_t *p, uint32_t v);
void csf_put_le64(uint8_t *p, uint64_t v);

#endif /* CRYPTOSTORE_FORMAT_H */
