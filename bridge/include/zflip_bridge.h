// ZFlip bridge: PCZT <-> Flipper sign request (see bridge/src/ffi.rs).
// Every call returns 0 on success; otherwise a negative code and `out` holds a
// UTF-8 error message. Release every returned buffer with zflip_free.
#pragma once
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *ptr;
    size_t len;
} ZflipBuffer;

int32_t zflip_sign_request(const uint8_t *pczt, size_t pczt_len, const char *ufvk, ZflipBuffer *out);
int32_t zflip_apply_signatures(const uint8_t *pczt, size_t pczt_len, const uint8_t *sigs, size_t sigs_len,
                               ZflipBuffer *out);
int32_t zflip_address(const char *ufvk, uint32_t index, ZflipBuffer *out);
void zflip_free(ZflipBuffer buf);
