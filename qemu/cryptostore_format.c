/*
 * pcie-cryptostore backing-file format v1: parser and encoders.
 *
 * Deliberately free of QEMU dependencies (see cryptostore_format.h) so the
 * exact same code is fuzzed in isolation (SR-16). Every check follows the
 * validation order of datasheet section 10.5.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include <string.h>
#include "cryptostore_format.h"

uint16_t csf_le16(const uint8_t *p)
{
    return (uint16_t)(p[0] | (p[1] << 8));
}

uint32_t csf_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint64_t csf_le64(const uint8_t *p)
{
    return (uint64_t)csf_le32(p) | ((uint64_t)csf_le32(p + 4) << 32);
}

void csf_put_le16(uint8_t *p, uint16_t v)
{
    p[0] = v;
    p[1] = v >> 8;
}

void csf_put_le32(uint8_t *p, uint32_t v)
{
    p[0] = v;
    p[1] = v >> 8;
    p[2] = v >> 16;
    p[3] = v >> 24;
}

void csf_put_le64(uint8_t *p, uint64_t v)
{
    csf_put_le32(p, (uint32_t)v);
    csf_put_le32(p + 4, (uint32_t)(v >> 32));
}

static bool all_zero(const uint8_t *p, size_t len)
{
    uint8_t acc = 0;

    for (size_t i = 0; i < len; i++) {
        acc |= p[i];
    }
    return acc == 0;
}

uint64_t csf_capacity_for_size(uint64_t file_size)
{
    uint64_t cap;

    if (file_size < CSF_DATA_OFFSET) {
        return 0;
    }
    cap = (file_size - CSF_DATA_OFFSET) / CSF_SECTOR;
    if (cap < CSF_MIN_CAPACITY) {
        return 0;
    }
    return cap > CSF_MAX_CAPACITY ? CSF_MAX_CAPACITY : cap;
}

static bool parse_slot(const uint8_t *p, CsfSlot *s, const char **why)
{
    memset(s, 0, sizeof(*s));
    s->state = csf_le32(p + CSF_SLOT_OFF_STATE);

    if (s->state == CSF_SLOT_INACTIVE) {
        if (!all_zero(p, CSF_SLOT_SIZE)) {
            *why = "inactive keyslot is not all zero";
            return false;
        }
        return true;
    }
    if (s->state != CSF_SLOT_ACTIVE) {
        *why = "keyslot state is neither INACTIVE nor ACTIVE";
        return false;
    }

    s->type = csf_le16(p + CSF_SLOT_OFF_TYPE);
    s->kdf = csf_le16(p + CSF_SLOT_OFF_KDF);
    s->iters = csf_le32(p + CSF_SLOT_OFF_ITERS);

    if (s->type == CSF_TYPE_PASSWORD) {
        if (s->kdf != CSF_KDF_PBKDF2_SHA256) {
            *why = "password slot does not use PBKDF2-HMAC-SHA256";
            return false;
        }
        if (s->iters < CSF_PBKDF2_MIN_ITERS || s->iters > CSF_PBKDF2_MAX_ITERS) {
            *why = "PBKDF2 iteration count outside the allowed range";
            return false;
        }
    } else if (s->type == CSF_TYPE_RECOVERY) {
        if (s->kdf != CSF_KDF_HKDF_SHA256 || s->iters != 0) {
            *why = "recovery slot does not use HKDF-SHA256 with 0 iterations";
            return false;
        }
    } else {
        *why = "unknown keyslot type";
        return false;
    }
    if (!all_zero(p + 0x0c, 4) ||
        !all_zero(p + CSF_SLOT_OFF_TAG + CSF_TAG_LEN,
                  CSF_SLOT_SIZE - (CSF_SLOT_OFF_TAG + CSF_TAG_LEN))) {
        *why = "keyslot reserved bytes are not zero";
        return false;
    }

    memcpy(s->salt, p + CSF_SLOT_OFF_SALT, CSF_SALT_LEN);
    memcpy(s->iv, p + CSF_SLOT_OFF_IV, CSF_IV_LEN);
    memcpy(s->wrapped, p + CSF_SLOT_OFF_WRAPPED, CSF_DEK_LEN);
    memcpy(s->tag, p + CSF_SLOT_OFF_TAG, CSF_TAG_LEN);
    return true;
}

CsfParseResult csf_parse(const uint8_t *hdr, uint64_t file_size,
                         CsfHeader *out, const char **why)
{
    const char *dummy;
    CsfHeader h;
    uint64_t max_cap;
    int passwords = 0, recoveries = 0;
    uint32_t count, inv;

    if (!why) {
        why = &dummy;
    }
    *why = NULL;

    /* 2. The header region must exist. */
    if (file_size < CSF_HDR_SIZE) {
        *why = "file smaller than the 4 KiB header region";
        return CSF_MALFORMED;
    }
    /* 3. Entirely zero: blank image. */
    if (all_zero(hdr, CSF_HDR_SIZE)) {
        return CSF_UNFORMATTED;
    }
    /* 4. Magic. A non-zero header is never treated as blank (C5). */
    if (memcmp(hdr + CSF_OFF_MAGIC, CSF_MAGIC, CSF_MAGIC_LEN) != 0) {
        *why = "bad magic";
        return CSF_MALFORMED;
    }
    /* 5. Version. */
    if (csf_le32(hdr + CSF_OFF_VERSION) != CSF_VERSION) {
        *why = "unsupported format version";
        return CSF_MALFORMED;
    }
    /* 6. Reserved regions. */
    if (!all_zero(hdr + 0x0026, CSF_OFF_SLOTS - 0x0026) ||
        !all_zero(hdr + CSF_OFF_HDR_MAC + CSF_MAC_LEN,
                  CSF_OFF_FAIL - (CSF_OFF_HDR_MAC + CSF_MAC_LEN)) ||
        !all_zero(hdr + CSF_OFF_FAIL + CSF_FAIL_SIZE,
                  CSF_HDR_SIZE - (CSF_OFF_FAIL + CSF_FAIL_SIZE))) {
        *why = "reserved header bytes are not zero";
        return CSF_MALFORMED;
    }
    /* 7. Cipher. */
    memset(&h, 0, sizeof(h));
    h.cipher = csf_le16(hdr + CSF_OFF_CIPHER);
    if (h.cipher != CSF_CIPHER_XTS_PLAIN64) {
        *why = "unknown cipher ID";
        return CSF_MALFORMED;
    }
    /* 8. Capacity against bounds and the file size, overflow-free. */
    h.capacity = csf_le64(hdr + CSF_OFF_CAPACITY);
    max_cap = (file_size - CSF_DATA_OFFSET) / CSF_SECTOR;
    if (h.capacity < CSF_MIN_CAPACITY || h.capacity > CSF_MAX_CAPACITY ||
        h.capacity > max_cap) {
        *why = "capacity out of range or larger than the file";
        return CSF_MALFORMED;
    }
    /* 9. Keyslots. */
    for (int i = 0; i < CSF_NUM_SLOTS; i++) {
        if (!parse_slot(hdr + CSF_OFF_SLOTS + i * CSF_SLOT_SIZE, &h.slot[i], why)) {
            return CSF_MALFORMED;
        }
        if (h.slot[i].state == CSF_SLOT_ACTIVE) {
            passwords += h.slot[i].type == CSF_TYPE_PASSWORD;
            recoveries += h.slot[i].type == CSF_TYPE_RECOVERY;
        }
    }
    if (passwords < 1) {
        *why = "no active password keyslot";
        return CSF_MALFORMED;
    }
    if (recoveries > 1) {
        *why = "more than one recovery keyslot";
        return CSF_MALFORMED;
    }
    /* 10. Failure record: a mismatch is reported, not rejected (R7). */
    count = csf_le32(hdr + CSF_OFF_FAIL);
    inv = csf_le32(hdr + CSF_OFF_FAIL + 4);
    h.fail_count = count;
    h.fail_record_ok = (count == (uint32_t)~inv);
    h.last_attempt_ms = csf_le64(hdr + CSF_OFF_FAIL + 8);

    memcpy(h.uuid, hdr + CSF_OFF_UUID, CSF_UUID_LEN);
    memcpy(h.hdr_mac, hdr + CSF_OFF_HDR_MAC, CSF_MAC_LEN);
    if (out) {
        *out = h;
    }
    return CSF_VALID;
}

void csf_encode_fixed(const uint8_t uuid[CSF_UUID_LEN], uint64_t capacity,
                      uint8_t out[CSF_MAC_COVER_LEN])
{
    memset(out, 0, CSF_MAC_COVER_LEN);
    memcpy(out + CSF_OFF_MAGIC, CSF_MAGIC, CSF_MAGIC_LEN);
    csf_put_le32(out + CSF_OFF_VERSION, CSF_VERSION);
    memcpy(out + CSF_OFF_UUID, uuid, CSF_UUID_LEN);
    csf_put_le64(out + CSF_OFF_CAPACITY, capacity);
    csf_put_le16(out + CSF_OFF_CIPHER, CSF_CIPHER_XTS_PLAIN64);
}

void csf_encode_slot(const CsfSlot *s, uint8_t out[CSF_SLOT_SIZE])
{
    memset(out, 0, CSF_SLOT_SIZE);
    if (s->state != CSF_SLOT_ACTIVE) {
        return;
    }
    csf_put_le32(out + CSF_SLOT_OFF_STATE, s->state);
    csf_put_le16(out + CSF_SLOT_OFF_TYPE, s->type);
    csf_put_le16(out + CSF_SLOT_OFF_KDF, s->kdf);
    csf_put_le32(out + CSF_SLOT_OFF_ITERS, s->iters);
    memcpy(out + CSF_SLOT_OFF_SALT, s->salt, CSF_SALT_LEN);
    memcpy(out + CSF_SLOT_OFF_IV, s->iv, CSF_IV_LEN);
    memcpy(out + CSF_SLOT_OFF_WRAPPED, s->wrapped, CSF_DEK_LEN);
    memcpy(out + CSF_SLOT_OFF_TAG, s->tag, CSF_TAG_LEN);
}

void csf_encode_fail(uint32_t count, uint64_t last_ms, uint8_t out[CSF_FAIL_SIZE])
{
    csf_put_le32(out, count);
    csf_put_le32(out + 4, ~count);
    csf_put_le64(out + 8, last_ms);
}
