/*
 * pcie-cryptorecovery: interface used by pcie-cryptostore over the QOM link
 * (recovery Option B, threat model Section 9). The recovery key never
 * crosses into the guest.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef CRYPTORECOVERY_H
#define CRYPTORECOVERY_H

#include "qom/object.h"
#include "cryptostore_format.h"

#define TYPE_PCIE_CRYPTORECOVERY "pcie-cryptorecovery"
OBJECT_DECLARE_SIMPLE_TYPE(CryptoRecoveryState, PCIE_CRYPTORECOVERY)

typedef enum CrRelease {
    CR_RELEASED = 0,
    CR_NO_KEY,          /* nothing stored, or bound to another image */
    CR_NOT_ARMED,       /* not armed by guest and host, or already released */
    CR_FAULT,           /* redundant release-once check disagreed (F8) */
} CrRelease;

/* Present, realized and backed by storage. */
bool cryptorecovery_available(CryptoRecoveryState *r);

/* Could a key for @uuid be released right now? Does not consume anything. */
CrRelease cryptorecovery_can_release(CryptoRecoveryState *r,
                                     const uint8_t uuid[CSF_UUID_LEN]);

/* Release the key for @uuid into @key (at most once per machine boot). */
CrRelease cryptorecovery_release(CryptoRecoveryState *r,
                                 const uint8_t uuid[CSF_UUID_LEN],
                                 uint8_t key[CSF_RECOVERY_KEY_LEN]);

/* Persist @key bound to @uuid (FORMAT, ENROLL_RECOVERY). Flushed and verified. */
bool cryptorecovery_store(CryptoRecoveryState *r, const uint8_t uuid[CSF_UUID_LEN],
                          const uint8_t key[CSF_RECOVERY_KEY_LEN], Error **errp);

#endif /* CRYPTORECOVERY_H */
