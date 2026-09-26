/*
 * pcie-cryptostore crypto constructions (datasheet 10.4).
 *
 * Primitives come from QEMU's qcrypto layer (nettle backend): AES-256 in XTS
 * and CTR mode, HMAC-SHA256 and PBKDF2-HMAC-SHA256. HKDF (RFC 5869) is built
 * here on top of HMAC, because QEMU does not provide it. Every construction
 * is covered by a known-answer test in cs_selftest() (SR-34).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "crypto/hmac.h"
#include "crypto/pbkdf.h"
#include "crypto/cipher.h"
#include "crypto/random.h"
#include "cryptostore_crypto.h"
#include "cryptostore_fi.h"
#include "cryptostore_kat.h"

#define LABEL_PREFIX "cryptostore v1 "

bool cs_wipe(void *p, size_t len)
{
    volatile const uint8_t *v = p;
    uint8_t acc = 0;

    explicit_bzero(p, len);
    cs_compiler_barrier();
    for (size_t i = 0; i < len; i++) {
        acc |= v[i];
    }
    return acc == 0;
}

int cs_hmac_sha256(const uint8_t *key, size_t nkey,
                   const struct iovec *iov, size_t niov,
                   uint8_t out[CS_HASH_LEN], Error **errp)
{
    g_autoptr(QCryptoHmac) hmac = NULL;
    uint8_t *res = out;
    size_t reslen = CS_HASH_LEN;

    hmac = qcrypto_hmac_new(QCRYPTO_HASH_ALGO_SHA256, key, nkey, errp);
    if (!hmac) {
        return -1;
    }
    return qcrypto_hmac_bytesv(hmac, iov, niov, &res, &reslen, errp);
}

int cs_hkdf_extract(const uint8_t *salt, size_t nsalt,
                    const uint8_t *ikm, size_t nikm,
                    uint8_t prk[CS_HASH_LEN], Error **errp)
{
    static const uint8_t zeros[CS_HASH_LEN];
    struct iovec iov = { .iov_base = (void *)ikm, .iov_len = nikm };

    /* RFC 5869 2.2: an absent salt is HashLen zero bytes. */
    if (nsalt == 0) {
        salt = zeros;
        nsalt = sizeof(zeros);
    }
    return cs_hmac_sha256(salt, nsalt, &iov, 1, prk, errp);
}

int cs_hkdf_expand(const uint8_t prk[CS_HASH_LEN],
                   const uint8_t *info, size_t ninfo,
                   uint8_t *okm, size_t nokm, Error **errp)
{
    uint8_t t[CS_HASH_LEN];
    size_t tlen = 0, done = 0;
    uint8_t counter = 1;
    int ret = 0;

    if (nokm > 255 * CS_HASH_LEN) {
        error_setg(errp, "HKDF output too long");
        return -1;
    }
    while (done < nokm) {
        struct iovec iov[3] = {
            { .iov_base = t, .iov_len = tlen },
            { .iov_base = (void *)info, .iov_len = ninfo },
            { .iov_base = &counter, .iov_len = 1 },
        };
        size_t n = MIN(nokm - done, (size_t)CS_HASH_LEN);

        ret = cs_hmac_sha256(prk, CS_HASH_LEN, iov, 3, t, errp);
        if (ret < 0) {
            break;
        }
        memcpy(okm + done, t, n);
        done += n;
        tlen = CS_HASH_LEN;
        counter++;
    }
    cs_wipe(t, sizeof(t));
    return ret;
}

/* HKDF-Expand with the domain-separated label "cryptostore v1 <name>". */
static int cs_expand_label(const uint8_t prk[CS_HASH_LEN], const char *name,
                           uint8_t *out, size_t nout, Error **errp)
{
    g_autofree char *label = g_strconcat(LABEL_PREFIX, name, NULL);

    return cs_hkdf_expand(prk, (const uint8_t *)label, strlen(label), out, nout, errp);
}

int cs_pbkdf2(const uint8_t *pw, size_t npw, const uint8_t salt[CSF_SALT_LEN],
              uint32_t iters, uint8_t kek[CS_KEY_LEN], Error **errp)
{
    /* 32 bytes only: asking PBKDF2 for more would halve an attacker's cost (11.4). */
    return qcrypto_pbkdf2(QCRYPTO_HASH_ALGO_SHA256, pw, npw, salt, CSF_SALT_LEN,
                          iters, kek, CS_KEY_LEN, errp);
}

uint32_t cs_pbkdf2_calibrate(unsigned ms, Error **errp)
{
    uint8_t salt[CSF_SALT_LEN] = { 0 };
    static const uint8_t pw[] = "calibration";
    uint64_t per_sec = 0, iters;

    /*
     * Hybrid CPUs (the dev host mixes Zen 5 and Zen 5c cores) calibrate
     * about 2x apart depending on where the thread lands. SR-03 is about an
     * attacker's cost, so calibrate against the fastest core seen: take the
     * best of three runs.
     */
    for (int run = 0; run < 3; run++) {
        uint64_t r = qcrypto_pbkdf2_count_iters(QCRYPTO_HASH_ALGO_SHA256, pw, sizeof(pw),
                                                salt, sizeof(salt), CS_KEY_LEN, errp);
        if (r == (uint64_t)-1) {
            return 0;
        }
        per_sec = MAX(per_sec, r);
    }
    iters = per_sec * ms / 1000;
    iters = MAX(iters, (uint64_t)CSF_PBKDF2_MIN_ITERS);
    iters = MIN(iters, (uint64_t)CSF_PBKDF2_MAX_ITERS);
    return iters;
}

int cs_slot_kek(const CsfSlot *slot, const uint8_t *secret, size_t nsecret,
                uint8_t kek[CS_KEY_LEN], Error **errp)
{
    if (slot->kdf == CSF_KDF_PBKDF2_SHA256) {
        return cs_pbkdf2(secret, nsecret, slot->salt, slot->iters, kek, errp);
    }
    if (slot->kdf == CSF_KDF_HKDF_SHA256) {
        return cs_hkdf_extract(slot->salt, CSF_SALT_LEN, secret, nsecret, kek, errp);
    }
    error_setg(errp, "unknown KDF");
    return -1;
}

/* Keys and keystream shared by wrap and unwrap. */
static int cs_slot_keys(const uint8_t kek[CS_KEY_LEN], uint8_t wrap_key[CS_KEY_LEN],
                        uint8_t tag_key[CS_KEY_LEN], Error **errp)
{
    if (cs_expand_label(kek, "wrap-key", wrap_key, CS_KEY_LEN, errp) < 0 ||
        cs_expand_label(kek, "tag-key", tag_key, CS_KEY_LEN, errp) < 0) {
        return -1;
    }
    return 0;
}

static int cs_ctr_xor(const uint8_t key[CS_KEY_LEN], const uint8_t iv[CSF_IV_LEN],
                      const uint8_t *in, uint8_t *out, size_t len, Error **errp)
{
    g_autoptr(QCryptoCipher) ctr = NULL;

    ctr = qcrypto_cipher_new(QCRYPTO_CIPHER_ALGO_AES_256, QCRYPTO_CIPHER_MODE_CTR,
                             key, CS_KEY_LEN, errp);
    if (!ctr || qcrypto_cipher_setiv(ctr, iv, CSF_IV_LEN, errp) < 0) {
        return -1;
    }
    return qcrypto_cipher_encrypt(ctr, in, out, len, errp);
}

static int cs_slot_tag(const CsfSlot *slot, const uint8_t tag_key[CS_KEY_LEN],
                       const uint8_t uuid[CSF_UUID_LEN], unsigned index,
                       uint8_t tag[CSF_TAG_LEN], Error **errp)
{
    uint8_t enc[CSF_SLOT_SIZE];
    uint8_t idx[4];
    struct iovec iov[3] = {
        { .iov_base = (void *)uuid, .iov_len = CSF_UUID_LEN },
        { .iov_base = idx, .iov_len = sizeof(idx) },
        { .iov_base = enc, .iov_len = CSF_SLOT_TAG_COVER },
    };

    csf_put_le32(idx, index);
    csf_encode_slot(slot, enc);
    return cs_hmac_sha256(tag_key, CS_KEY_LEN, iov, 3, tag, errp);
}

int cs_slot_wrap(CsfSlot *slot, const uint8_t kek[CS_KEY_LEN],
                 const uint8_t uuid[CSF_UUID_LEN], unsigned index,
                 const uint8_t dek[CSF_DEK_LEN], Error **errp)
{
    uint8_t wrap_key[CS_KEY_LEN], tag_key[CS_KEY_LEN];
    int ret = -1;

    if (cs_slot_keys(kek, wrap_key, tag_key, errp) == 0 &&
        cs_ctr_xor(wrap_key, slot->iv, dek, slot->wrapped, CSF_DEK_LEN, errp) == 0 &&
        cs_slot_tag(slot, tag_key, uuid, index, slot->tag, errp) == 0) {
        ret = 0;
    }
    cs_wipe(wrap_key, sizeof(wrap_key));
    cs_wipe(tag_key, sizeof(tag_key));
    return ret;
}

int cs_slot_unwrap(const CsfSlot *slot, const uint8_t kek[CS_KEY_LEN],
                   const uint8_t uuid[CSF_UUID_LEN], unsigned index,
                   uint8_t dek[CSF_DEK_LEN], bool *match, bool *fault,
                   bool force_first_match, Error **errp)
{
    uint8_t wrap_key[CS_KEY_LEN], tag_key[CS_KEY_LEN], tag[CSF_TAG_LEN];
    uint32_t verdict;
    int ret = -1;

    *match = false;
    *fault = false;
    if (cs_slot_keys(kek, wrap_key, tag_key, errp) < 0 ||
        cs_slot_tag(slot, tag_key, uuid, index, tag, errp) < 0) {
        goto out;
    }
    /* Tag first, decrypt only after it verifies (11.4); compared twice (F9). */
    verdict = cs_tag_verdict(tag, slot->tag, CSF_TAG_LEN, force_first_match);
    if (verdict != CS_FS_TRUE && verdict != CS_FS_FALSE) {
        *fault = true;
        ret = 0;
        goto out;
    }
    if (verdict == CS_FS_TRUE) {
        if (cs_ctr_xor(wrap_key, slot->iv, slot->wrapped, dek, CSF_DEK_LEN, errp) < 0) {
            goto out;
        }
        *match = true;
    }
    ret = 0;
out:
    cs_wipe(wrap_key, sizeof(wrap_key));
    cs_wipe(tag_key, sizeof(tag_key));
    cs_wipe(tag, sizeof(tag));
    return ret;
}

int cs_header_mac(const uint8_t dek[CSF_DEK_LEN], const uint8_t uuid[CSF_UUID_LEN],
                  const uint8_t fixed[CSF_MAC_COVER_LEN],
                  uint8_t mac[CSF_MAC_LEN], Error **errp)
{
    uint8_t prk[CS_HASH_LEN], hmk[CS_KEY_LEN];
    struct iovec iov = { .iov_base = (void *)fixed, .iov_len = CSF_MAC_COVER_LEN };
    int ret = -1;

    if (cs_hkdf_extract(uuid, CSF_UUID_LEN, dek, CSF_DEK_LEN, prk, errp) == 0 &&
        cs_expand_label(prk, "header-mac", hmk, sizeof(hmk), errp) == 0 &&
        cs_hmac_sha256(hmk, sizeof(hmk), &iov, 1, mac, errp) == 0) {
        ret = 0;
    }
    cs_wipe(prk, sizeof(prk));
    cs_wipe(hmk, sizeof(hmk));
    return ret;
}

QCryptoCipher *cs_xts_new(const uint8_t dek[CSF_DEK_LEN], Error **errp)
{
    return qcrypto_cipher_new(QCRYPTO_CIPHER_ALGO_AES_256, QCRYPTO_CIPHER_MODE_XTS,
                              dek, CSF_DEK_LEN, errp);
}

int cs_xts_sector(QCryptoCipher *xts, uint64_t sector, bool encrypt,
                  const uint8_t *in, uint8_t *out, Error **errp)
{
    uint8_t iv[16] = { 0 };

    csf_put_le64(iv, sector);   /* plain64 tweak: LE64(sector) || 0^8 */
    if (qcrypto_cipher_setiv(xts, iv, sizeof(iv), errp) < 0) {
        return -1;
    }
    return encrypt ? qcrypto_cipher_encrypt(xts, in, out, CSF_SECTOR, errp)
                   : qcrypto_cipher_decrypt(xts, in, out, CSF_SECTOR, errp);
}

/* ---- known-answer tests (SR-34) ---- */

static bool kat_hmac(const uint8_t *key, size_t nkey, const uint8_t *data,
                     size_t ndata, const uint8_t *want, Error **errp)
{
    uint8_t out[CS_HASH_LEN];
    struct iovec iov = { .iov_base = (void *)data, .iov_len = ndata };

    return cs_hmac_sha256(key, nkey, &iov, 1, out, errp) == 0 &&
           memcmp(out, want, CS_HASH_LEN) == 0;
}

static bool kat_hkdf(const uint8_t *ikm, size_t nikm, const uint8_t *salt, size_t nsalt,
                     const uint8_t *info, size_t ninfo, const uint8_t *prk_want,
                     const uint8_t *okm_want, size_t nokm, Error **errp)
{
    uint8_t prk[CS_HASH_LEN], okm[255];

    return cs_hkdf_extract(salt, nsalt, ikm, nikm, prk, errp) == 0 &&
           memcmp(prk, prk_want, CS_HASH_LEN) == 0 &&
           cs_hkdf_expand(prk, info, ninfo, okm, nokm, errp) == 0 &&
           memcmp(okm, okm_want, nokm) == 0;
}

int cs_selftest(bool fail_on_purpose, Error **errp)
{
    uint8_t buf[KAT_XTS10_PTEXT_LEN];
    uint8_t dk[KAT_PBKDF2_1_DK_LEN];
    g_autoptr(QCryptoCipher) xts = NULL;
    const char *failed = NULL;

#define KAT(name, expr) do { if (!failed && !(expr)) { failed = name; } } while (0)
    KAT("HMAC-SHA256 RFC 4231 case 1",
        kat_hmac(kat_hmac1_key, KAT_HMAC1_KEY_LEN, kat_hmac1_data, KAT_HMAC1_DATA_LEN,
                 kat_hmac1_mac, errp));
    KAT("HMAC-SHA256 RFC 4231 case 2",
        kat_hmac(kat_hmac2_key, KAT_HMAC2_KEY_LEN, kat_hmac2_data, KAT_HMAC2_DATA_LEN,
                 kat_hmac2_mac, errp));
    KAT("HMAC-SHA256 RFC 4231 case 6",
        kat_hmac(kat_hmac6_key, KAT_HMAC6_KEY_LEN, kat_hmac6_data, KAT_HMAC6_DATA_LEN,
                 kat_hmac6_mac, errp));
    KAT("HKDF-SHA256 RFC 5869 case 1",
        kat_hkdf(kat_hkdf1_ikm, KAT_HKDF1_IKM_LEN, kat_hkdf1_salt, KAT_HKDF1_SALT_LEN,
                 kat_hkdf1_info, KAT_HKDF1_INFO_LEN, kat_hkdf1_prk, kat_hkdf1_okm,
                 KAT_HKDF1_OKM_LEN, errp));
    KAT("HKDF-SHA256 RFC 5869 case 2",
        kat_hkdf(kat_hkdf2_ikm, KAT_HKDF2_IKM_LEN, kat_hkdf2_salt, KAT_HKDF2_SALT_LEN,
                 kat_hkdf2_info, KAT_HKDF2_INFO_LEN, kat_hkdf2_prk, kat_hkdf2_okm,
                 KAT_HKDF2_OKM_LEN, errp));
    KAT("HKDF-SHA256 RFC 5869 case 3",
        kat_hkdf(kat_hkdf3_ikm, KAT_HKDF3_IKM_LEN, kat_hkdf3_salt, KAT_HKDF3_SALT_LEN,
                 kat_hkdf3_info, KAT_HKDF3_INFO_LEN, kat_hkdf3_prk, kat_hkdf3_okm,
                 KAT_HKDF3_OKM_LEN, errp));
    KAT("PBKDF2-HMAC-SHA256 RFC 7914 vector 1",
        qcrypto_pbkdf2(QCRYPTO_HASH_ALGO_SHA256, (const uint8_t *)KAT_PBKDF2_1_P,
                       strlen(KAT_PBKDF2_1_P), (const uint8_t *)KAT_PBKDF2_1_S,
                       strlen(KAT_PBKDF2_1_S), KAT_PBKDF2_1_C, dk, sizeof(dk), errp) == 0 &&
        memcmp(dk, kat_pbkdf2_1_dk, sizeof(dk)) == 0);
    if (!failed) {
        xts = cs_xts_new(kat_xts10_key, errp);
        KAT("AES-256-XTS setup", xts != NULL);
    }
    if (!failed) {
        uint8_t iv[16];
        memcpy(iv, kat_xts10_iv, sizeof(iv));
        KAT("AES-256-XTS IEEE 1619 vector 10 encrypt",
            qcrypto_cipher_setiv(xts, iv, sizeof(iv), errp) == 0 &&
            qcrypto_cipher_encrypt(xts, kat_xts10_ptext, buf, sizeof(buf), errp) == 0 &&
            memcmp(buf, kat_xts10_ctext, sizeof(buf)) == 0);
        KAT("AES-256-XTS IEEE 1619 vector 10 decrypt",
            qcrypto_cipher_setiv(xts, iv, sizeof(iv), errp) == 0 &&
            qcrypto_cipher_decrypt(xts, kat_xts10_ctext, buf, sizeof(buf), errp) == 0 &&
            memcmp(buf, kat_xts10_ptext, sizeof(buf)) == 0);
        /* The plain64 path of the device must agree with the vector's tweak (sector 0xff). */
        KAT("AES-256-XTS plain64 sector tweak",
            cs_xts_sector(xts, 0xff, true, kat_xts10_ptext, buf, errp) == 0 &&
            memcmp(buf, kat_xts10_ctext, CSF_SECTOR) == 0);
    }
    KAT("forced failure (test hook)", !fail_on_purpose);
#undef KAT

    if (failed) {
        if (errp && !*errp) {
            error_setg(errp, "crypto self-test failed: %s", failed);
        } else if (errp) {
            error_prepend(errp, "crypto self-test failed: %s: ", failed);
        }
        return -1;
    }
    return 0;
}
