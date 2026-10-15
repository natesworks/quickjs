/*
 * Luna custom bytecode container format.
 *
 * This module owns the on-disk/on-wire representation of compiled mods.
 * It is deliberately self contained: no dependency on quickjs internals,
 * glib or any crypto library, so the same code can be compiled into the
 * engine, into offline tools and into host side test harnesses.
 *
 * Container layout (all multi byte integers little endian):
 *
 *   offset size field
 *   ------ ---- -----
 *        0    4 magic "LUNA"
 *        4    1 format version (LUNA_BC_VERSION)
 *        5    1 flags (LUNA_BC_FLAG_*)
 *        6    1 kdf shift: PBKDF2 rounds = 1u << shift
 *        7    1 reserved, must be zero
 *        8    8 payload length in bytes
 *       16   16 salt
 *       32   12 chacha20 nonce
 *       44    8 key check (HMAC based, no keystream is revealed)
 *       52   16 truncated HMAC-SHA256 tag
 *       68   .. ciphertext, exactly payload_len bytes
 *
 * The plaintext payload is a quickjs serialized object graph whose per
 * function opcode streams have been run through a key derived, size and
 * format preserving opcode permutation. Everything is then encrypted with
 * ChaCha20 using keys derived by PBKDF2-HMAC-SHA256 from the anti-mod blob,
 * so a container extracted from one build/device/app cannot be decrypted on
 * another one.
 *
 * Key schedule (every subkey is domain separated, and all of them are wiped
 * as soon as the container has been sealed or opened):
 *
 *   dk       = PBKDF2-HMAC-SHA256(blob, salt, 1 << shift), 64 bytes
 *   stream   = dk[ 0..32)                     ChaCha20 key
 *   mac      = H("luna-mac-v1"   || dk)       container tag
 *   check    = H("luna-check-v1" || dk)       key confirmation
 *   perm     = H("luna-perm-v1"  || dk)       opcode permutation master
 *
 * The permutation is then re-keyed per function with the function ordinal,
 * so two functions of the same mod never share an instruction encoding.
 */
#ifndef LUNA_BC_H
#define LUNA_BC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LUNA_BC_MAGIC       "LUNA"
#define LUNA_BC_MAGIC_LEN   4
#define LUNA_BC_VERSION     2
#define LUNA_BC_HEADER_SIZE 68

/* flags */
#define LUNA_BC_FLAG_PERMUTED     (1u << 0) /* payload opcodes are permuted */
#define LUNA_BC_FLAG_STRIPPED     (1u << 1) /* debug info was stripped */
#define LUNA_BC_FLAG_DEVICE_BOUND (1u << 2) /* anti-mod blob carries a device id */

/* key material sizes */
#define LUNA_BC_KEY_LEN       32
#define LUNA_BC_HMAC_KEY_LEN  32
#define LUNA_BC_DK_LEN        (LUNA_BC_KEY_LEN + LUNA_BC_HMAC_KEY_LEN)
#define LUNA_BC_SALT_LEN      16
#define LUNA_BC_NONCE_LEN     12
#define LUNA_BC_KEYCHECK_LEN  8
#define LUNA_BC_TAG_LEN       16

/* default and bounds for the PBKDF2 iteration count */
#define LUNA_BC_KDF_SHIFT_MIN 12
#define LUNA_BC_KDF_SHIFT_MAX 24
#define LUNA_BC_KDF_SHIFT_DEFAULT 18

#define LUNA_BC_ERROR_MAX 256

/* Return codes. Everything negative is a failure; the message buffer (when
 * provided) always receives a NUL terminated human readable reason. */
enum {
    LUNA_BC_OK = 0,
    LUNA_BC_ERR_ARGUMENT = -1,
    LUNA_BC_ERR_MEMORY = -2,
    LUNA_BC_ERR_BUFFER = -3,
    LUNA_BC_ERR_MAGIC = -4,
    LUNA_BC_ERR_VERSION = -5,
    LUNA_BC_ERR_LENGTH = -6,
    LUNA_BC_ERR_KEY = -7,
    LUNA_BC_ERR_TAMPERED = -8,
    LUNA_BC_ERR_OVERFLOW = -9,
};

/*
 * Anti-mod binding data. Both the offline compiler and the runtime fill the
 * very same structure; luna_bc_antimod_blob() canonicalizes it into the
 * PBKDF2 password. Any field left NULL is serialized as the empty string.
 *
 *  apk_sig_sha256 : lowercase hex digest of the app signing certificate,
 *                   as taken from the APK Signature Scheme v2/v3 block
 *                   (or the META-INF certificate of v1 only APKs).
 *  sig_scheme     : "v1", "v2", "v3" or "v3.1"; informational.
 *  device_id      : optional stable per device identifier; when set the
 *                   container only ever decrypts on that device.
 *  label          : domain separation label, normally the mod package name,
 *                   so each mod gets its own key.
 */
typedef struct LunaAntiModData {
    const char *package;
    const char *apk_sig_sha256;
    const char *sig_scheme;
    const char *version_name;
    const char *version_code;
    const char *device_id;
    const char *label;
} LunaAntiModData;

/* Parsed container header. */
typedef struct LunaBCHeader {
    uint8_t version;
    uint8_t flags;
    uint8_t kdf_shift;
    uint8_t reserved;
    uint64_t payload_len;
    uint8_t salt[LUNA_BC_SALT_LEN];
    uint8_t nonce[LUNA_BC_NONCE_LEN];
    uint8_t key_check[LUNA_BC_KEYCHECK_LEN];
    uint8_t tag[LUNA_BC_TAG_LEN];
} LunaBCHeader;

/*
 * Opcode permutation context: the caller supplies size/fmt tables straight
 * from the engine so this file stays engine independent. Values with size 0
 * are treated as "not a usable opcode" and are left untouched.
 */
typedef struct LunaBCPerm {
    uint8_t perm[256];   /* canonical opcode -> stored opcode */
    uint8_t unperm[256]; /* stored opcode -> canonical opcode */
} LunaBCPerm;

/* Canonical anti-mod blob ("password") serialization. */
size_t luna_bc_antimod_blob(const LunaAntiModData *am, uint8_t *out, size_t out_cap);

/* Key derivation: PBKDF2-HMAC-SHA256(blob, salt, 1 << kdf_shift).
 * On success writes LUNA_BC_DK_LEN bytes into dk and returns LUNA_BC_OK. */
int luna_bc_derive_key(const LunaAntiModData *am, const uint8_t *salt,
                       uint32_t kdf_shift, uint8_t *dk, char *err, size_t err_cap);

/* Pack a plaintext quickjs serialization into a Luna container.
 * Returns LUNA_BC_OK and a malloc()ed buffer via out and out_len. */
int luna_bc_pack(const LunaAntiModData *am, const uint8_t *payload, size_t payload_len,
                 uint32_t kdf_shift, int flags, uint8_t **out, size_t *out_len,
                 char *err, size_t err_cap);

/*
 * Two step packing, used when the caller needs the derived key before the
 * payload exists (the engine permutes opcodes with a subkey derived from it).
 * luna_bc_pack_begin() fills hdr (salt/nonce/version) and dk; the payload is
 * then produced with the permutation key from luna_bc_perm_key(), and
 * luna_bc_pack_finish() encrypts and seals it. Set hdr->flags before finish.
 */
int luna_bc_pack_begin(const LunaAntiModData *am, uint32_t kdf_shift,
                       LunaBCHeader *hdr, uint8_t *dk, char *err, size_t err_cap);
int luna_bc_pack_finish(const LunaAntiModData *am, const LunaBCHeader *hdr, const uint8_t *dk,
                        const uint8_t *payload, size_t payload_len, uint8_t **out, size_t *out_len,
                        char *err, size_t err_cap);

/* Two step unpacking: verify the key first, then decrypt and verify the MAC.
 * The dk output lets the caller rebuild the same opcode permutation. */
int luna_bc_unpack_begin(const uint8_t *buf, size_t len, const LunaAntiModData *am,
                         LunaBCHeader *hdr, uint8_t *dk, char *err, size_t err_cap);
int luna_bc_unpack_finish(const uint8_t *buf, size_t len, const LunaBCHeader *hdr,
                          const uint8_t *dk, uint8_t **payload, size_t *payload_len,
                          char *err, size_t err_cap);

/* Unpack and verify a container in one call. */
int luna_bc_unpack(const uint8_t *buf, size_t len, const LunaAntiModData *am,
                   uint8_t **payload, size_t *payload_len, LunaBCHeader *hdr,
                   char *err, size_t err_cap);

/* Header only inspection, no key needed. */
int luna_bc_parse_header(const uint8_t *buf, size_t len, LunaBCHeader *hdr,
                         char *err, size_t err_cap);

/*
 * Opcode permutation. `key` is a subkey (or subkey plus function ordinal):
 * derive one per function with luna_bc_perm_function_key() so that no two
 * functions share an instruction encoding. op_size/op_fmt are 256 entry
 * tables; op_size[v] == 0 marks unused slots.
 */
void luna_bc_build_permutation(LunaBCPerm *p, const uint8_t *key, size_t key_len,
                               const uint8_t *op_size, const uint8_t *op_fmt);

/* Re-key the permutation master for one function ordinal. */
void luna_bc_perm_function_key(uint8_t *out, const uint8_t *perm_master,
                               uint32_t func_index);

/* Apply the permutation (or its inverse) over a serialized opcode stream.
 * Returns the number of bytes walked, or -1 if the stream is malformed. */
long luna_bc_permute_stream(uint8_t *buf, size_t len, const LunaBCPerm *p,
                            int inverse, const uint8_t *op_size);

/* Zero a permutation table so key derived material does not linger. */
void luna_bc_perm_wipe(LunaBCPerm *p);

/* The ChaCha20 permutation master key derived from dk. */
void luna_bc_perm_key(const uint8_t *dk, uint8_t *out);

/* Primitives, exposed for the self test and for reuse by tooling. */
typedef struct { uint32_t state[8]; uint64_t bitlen; uint8_t buf[64]; size_t buflen; } LunaBCSha256;
void luna_bc_sha256_init(LunaBCSha256 *c);
void luna_bc_sha256_update(LunaBCSha256 *c, const void *data, size_t len);
void luna_bc_sha256_final(LunaBCSha256 *c, uint8_t out[32]);
void luna_bc_sha256(const void *data, size_t len, uint8_t out[32]);
typedef struct LunaBCHmac {
    LunaBCSha256 inner;
    uint8_t opad[64];
} LunaBCHmac;
void luna_bc_hmac_init(LunaBCHmac *h, const uint8_t *key, size_t key_len);
void luna_bc_hmac_update(LunaBCHmac *h, const uint8_t *data, size_t len);
void luna_bc_hmac_final(LunaBCHmac *h, uint8_t out[32]);
void luna_bc_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t len, uint8_t out[32]);
void luna_bc_pbkdf2_sha256(const uint8_t *pass, size_t pass_len,
                           const uint8_t *salt, size_t salt_len,
                           uint32_t iters, uint8_t *out, size_t out_len);
void luna_bc_chacha20_xor(const uint8_t key[32], const uint8_t nonce[12],
                          uint32_t counter, uint8_t *data, size_t len);

/* Constant time buffers compare, returns 1 when equal. */
int luna_bc_equal(const void *a, const void *b, size_t len);

/* Erase sensitive memory: volatile multi pass, so hooking memset() or an
 * optimizing compiler cannot skip it. */
void luna_bc_wipe(void *p, size_t n);

void luna_bc_hex(const uint8_t *in, size_t len, char *out);
int luna_bc_unhex(const char *in, uint8_t *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif /* LUNA_BC_H */
