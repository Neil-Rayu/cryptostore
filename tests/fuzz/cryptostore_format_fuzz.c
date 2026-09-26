/*
 * libFuzzer harness for the cryptostore header parser (SR-16).
 *
 * Input: 8 bytes of file size (LE) followed by up to 4 KiB of header.
 * Properties checked on every input:
 *   - csf_parse() never crashes (ASan/UBSan catch memory errors)
 *   - it returns one of UNFORMATTED / VALID / MALFORMED, with a reason for
 *     MALFORMED
 *   - a VALID header re-encodes to exactly the input bytes (round trip)
 *
 * Build and run: tools/fuzz-cryptostore-format.sh [seconds]
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cryptostore_format.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    uint8_t hdr[CSF_HDR_SIZE] = {0};
    uint8_t buf[CSF_SLOT_SIZE];
    uint64_t file_size = 0;
    const char *why = NULL;
    CsfHeader h;
    CsfParseResult r;

    if (size >= 8) {
        file_size = csf_le64(data);
        data += 8;
        size -= 8;
    }
    memcpy(hdr, data, size < sizeof(hdr) ? size : sizeof(hdr));

    r = csf_parse(hdr, file_size, &h, &why);
    switch (r) {
    case CSF_UNFORMATTED:
        break;
    case CSF_MALFORMED:
        if (!why) {
            abort();
        }
        break;
    case CSF_VALID:
        csf_encode_fixed(h.uuid, h.capacity, buf);
        if (memcmp(buf, hdr, CSF_MAC_COVER_LEN) != 0) {
            abort();
        }
        for (int i = 0; i < CSF_NUM_SLOTS; i++) {
            csf_encode_slot(&h.slot[i], buf);
            if (memcmp(buf, hdr + CSF_OFF_SLOTS + i * CSF_SLOT_SIZE, CSF_SLOT_SIZE)) {
                abort();
            }
        }
        if (h.fail_record_ok) {
            csf_encode_fail(h.fail_count, h.last_attempt_ms, buf);
            if (memcmp(buf, hdr + CSF_OFF_FAIL, CSF_FAIL_SIZE)) {
                abort();
            }
        }
        if (memcmp(h.hdr_mac, hdr + CSF_OFF_HDR_MAC, CSF_MAC_LEN)) {
            abort();
        }
        break;
    default:
        abort();
    }
    return 0;
}
