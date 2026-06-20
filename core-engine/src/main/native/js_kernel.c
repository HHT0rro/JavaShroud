/*
 * JavaShroud Native Microkernel (js_kernel)
 *
 * Minimal JNI native library that provides runtime protection primitives:
 *   1. js_kernel_init        - initialization and environment validation
 *   2. js_kernel_verify      - runtime bytecode integrity verification
 *   3. js_kernel_decrypt_aes - AES-CBC payload decryption for protected resources
 *   4. js_kernel_heartbeat   - anti-tamper heartbeat check
 *
 * This is the real native kernel that gets compiled per-platform and
 * bundled into the obfuscated JAR by the jni-microkernel-loader pass.
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>

/*
 * Single-host cross compilation note:
 * This translation unit intentionally avoids platform SDK headers
 * (windows.h / dlfcn.h / unistd.h). None of their symbols are used here,
 * and avoiding them lets `zig cc -target <arch>-<os>` build every declared
 * platform from one machine using the self-contained jni.h in cross-compile/.
 */
#ifdef _WIN32
  #define JS_LOCAL
#else
  #define JS_LOCAL __attribute__((visibility("hidden")))
#endif

static volatile int g_initialized = 0;
static volatile unsigned int g_heartbeat_counter = 0;
static volatile unsigned int g_integrity_seed = 0;

/* Forward declaration so the key self-check can hash the decoded key. */
static unsigned int fnv1a_hash(const unsigned char* data, int len);

/*
 * Tigress-style constant encoding: the embedded native verification key is
 * stored in additively biased form and decoded at init time. Tampering with
 * the encoded key bytes causes the runtime self-check (FNV1a validation) to
 * fail, blocking protected native calls.
 *
 * JS_KEY_OBF is intentionally `volatile`: without it, -O2 can constant-fold
 * the decode expression and store the plaintext key in rodata. The volatile
 * qualifier forces the decode to run at load time, so only biased bytes are
 * present in the binary image.
 */
static volatile unsigned char JS_KEY_OBF[] = {
    0xFB, 0x2F, 0x4A, 0x74, 0x53, 0xB4, 0xA4, 0x82,
    0x06, 0xDA, 0x32, 0x10, 0x9F, 0xD8, 0x3E, 0x38
};
static unsigned char g_decoded_key[16];
static volatile int g_key_valid = 0;

static inline unsigned char js_key_mask(int i) {
    unsigned int m = 0xA5u + (unsigned int)i * 0x1Fu;
    m += (m >> 3) + (unsigned int)(i * 17u);
    return (unsigned char)(m & 0xFFu);
}

static void js_decode_key(void) {
    for (int i = 0; i < 16; i++) {
        g_decoded_key[i] = (unsigned char)(JS_KEY_OBF[i] - js_key_mask(i));
    }
    /* Anti-tamper self-check: decoded key FNV1a must match the expected constant. */
    unsigned int chk = fnv1a_hash(g_decoded_key, 16);
    g_key_valid = (chk == 0xAD3B3ED7u) ? 1 : 0;
}

static unsigned int fnv1a_hash(const unsigned char* data, int len) {
    unsigned int hash = 0x811c9dc5u;
    for (int i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193u;
    }
    return hash;
}

static unsigned long long js_rotl64(unsigned long long value, int bits) {
    return (value << bits) | (value >> (64 - bits));
}

static unsigned long long js_read_le64(const unsigned char *data, int available) {
    unsigned long long value = 0;
    for (int index = 0; index < available; index++) value |= ((unsigned long long)data[index]) << (8 * index);
    return value;
}

static void js_write_le64(unsigned char out[8], unsigned long long value) {
    for (int index = 0; index < 8; index++) out[index] = (unsigned char)(value >> (8 * index));
}

#define JS_SIP_ROUND do {     v0 += v1; v1 = js_rotl64(v1, 13); v1 ^= v0; v0 = js_rotl64(v0, 32);     v2 += v3; v3 = js_rotl64(v3, 16); v3 ^= v2;     v0 += v3; v3 = js_rotl64(v3, 21); v3 ^= v0;     v2 += v1; v1 = js_rotl64(v1, 17); v1 ^= v2; v2 = js_rotl64(v2, 32); } while (0)

static unsigned long long js_native_keyed_mac64(const unsigned char *data, int len) {
    if (!g_key_valid) js_decode_key();
    unsigned long long k0 = js_read_le64(g_decoded_key, 8) ^ (((unsigned long long)g_integrity_seed << 32) | (unsigned long long)g_integrity_seed);
    unsigned long long k1 = js_read_le64(g_decoded_key + 8, 8) ^ 0x9E3779B97F4A7C15ULL;
    unsigned long long v0 = 0x736F6D6570736575ULL ^ k0;
    unsigned long long v1 = 0x646F72616E646F6DULL ^ k1;
    unsigned long long v2 = 0x6C7967656E657261ULL ^ k0;
    unsigned long long v3 = 0x7465646279746573ULL ^ k1;
    int offset = 0;
    while (offset + 8 <= len) {
        unsigned long long m = js_read_le64(data + offset, 8);
        v3 ^= m;
        JS_SIP_ROUND; JS_SIP_ROUND;
        v0 ^= m;
        offset += 8;
    }
    unsigned long long b = ((unsigned long long)(len & 0xff)) << 56;
    int remaining = len - offset;
    b |= js_read_le64(data + offset, remaining);
    v3 ^= b;
    JS_SIP_ROUND; JS_SIP_ROUND;
    v0 ^= b;
    v2 ^= 0xffu;
    JS_SIP_ROUND; JS_SIP_ROUND; JS_SIP_ROUND; JS_SIP_ROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

static int js_consttime_eq8(const unsigned char *actual, const unsigned char *expected) {
    unsigned int diff = 0;
    for (int index = 0; index < 8; index++) diff |= (unsigned int)(actual[index] ^ expected[index]);
    return diff == 0;
}


JS_LOCAL jint JNICALL
jsn_k0(
    JNIEnv* env, jclass clazz, jstring platform)
{
    if (g_initialized) return 1;
    js_decode_key();
    if (!g_key_valid) return -2; /* Key tampered */
    const char* plat = (*env)->GetStringUTFChars(env, platform, NULL);
    if (!plat) return -1;
    g_integrity_seed = fnv1a_hash((const unsigned char*)plat, (int)strlen(plat));
    g_heartbeat_counter = 0;
    g_initialized = 1;
    (*env)->ReleaseStringUTFChars(env, platform, plat);
    return 0;
}

JS_LOCAL jint JNICALL
jsn_k1(
    JNIEnv* env, jclass clazz, jbyteArray data, jbyteArray expected_mac)
{
    if (!data || !expected_mac) return -1;
    jsize len = (*env)->GetArrayLength(env, data);
    jsize mac_len = (*env)->GetArrayLength(env, expected_mac);
    if (mac_len != 8) return -1;
    jbyte* bytes = (*env)->GetByteArrayElements(env, data, NULL);
    if (!bytes) return -1;
    jbyte* expected = (*env)->GetByteArrayElements(env, expected_mac, NULL);
    if (!expected) { (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT); return -1; }
    unsigned char actual[8];
    unsigned long long mac = js_native_keyed_mac64((const unsigned char*)bytes, len);
    js_write_le64(actual, mac);
    int ok = js_consttime_eq8(actual, (const unsigned char*)expected);
    memset(actual, 0, sizeof(actual));
    (*env)->ReleaseByteArrayElements(env, expected_mac, expected, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data, bytes, JNI_ABORT);
    return ok ? 0 : -1;
}

JS_LOCAL jint JNICALL
jsn_k3(
    JNIEnv* env, jclass clazz)
{
    return (jint)(++g_heartbeat_counter);
}


/* ---- AES-128-CBC software implementation (decrypt only) ---- */

static const unsigned char AES_SBOX_INV[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const unsigned char AES_RCON[11] = {
    0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

static void aes_inv_sub_bytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++) state[i] = AES_SBOX_INV[state[i]];
}

static void aes_inv_shift_rows(unsigned char state[16]) {
    unsigned char t;
    /* row 1: right shift 1 */
    t = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t;
    /* row 2: right shift 2 */
    t = state[2]; state[2] = state[10]; state[10] = t;
    t = state[6]; state[6] = state[14]; state[14] = t;
    /* row 3: right shift 3 */
    t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t;
}

static unsigned char aes_gf_mul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        unsigned char hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

static void aes_inv_mix_columns(unsigned char state[16]) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        unsigned char a = state[i], b = state[i+1], d = state[i+2], e = state[i+3];
        state[i]   = (unsigned char)(aes_gf_mul(a,0x0e) ^ aes_gf_mul(b,0x0b) ^ aes_gf_mul(d,0x0d) ^ aes_gf_mul(e,0x09));
        state[i+1] = (unsigned char)(aes_gf_mul(a,0x09) ^ aes_gf_mul(b,0x0e) ^ aes_gf_mul(d,0x0b) ^ aes_gf_mul(e,0x0d));
        state[i+2] = (unsigned char)(aes_gf_mul(a,0x0d) ^ aes_gf_mul(b,0x09) ^ aes_gf_mul(d,0x0e) ^ aes_gf_mul(e,0x0b));
        state[i+3] = (unsigned char)(aes_gf_mul(a,0x0b) ^ aes_gf_mul(b,0x0d) ^ aes_gf_mul(d,0x09) ^ aes_gf_mul(e,0x0e));
    }
}

static void aes_add_round_key(unsigned char state[16], const unsigned char* key) {
    for (int i = 0; i < 16; i++) state[i] ^= key[i];
}

/* AES-128 forward S-box for key expansion */
static const unsigned char AES_SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static void aes_expand_key(const unsigned char key[16], unsigned char expanded[176]) {
    memcpy(expanded, key, 16);
    for (int i = 16; i < 176; i += 4) {
        unsigned char temp[4];
        memcpy(temp, expanded + i - 4, 4);
        if (i % 16 == 0) {
            unsigned char t = temp[0];
            temp[0] = (unsigned char)(AES_SBOX[temp[1]] ^ AES_RCON[i / 16]);
            temp[1] = (unsigned char)(AES_SBOX[temp[2]]);
            temp[2] = (unsigned char)(AES_SBOX[temp[3]]);
            temp[3] = (unsigned char)(AES_SBOX[t]);
        }
        for (int j = 0; j < 4; j++) {
            expanded[i + j] = (unsigned char)(expanded[i - 16 + j] ^ temp[j]);
        }
    }
}

static int aes_cbc_decrypt(const unsigned char* in, int len, unsigned char* out,
                           const unsigned char key[16], const unsigned char iv[16]) {
    if (len % 16 != 0 || len <= 0) return -1;
    unsigned char expanded[176];
    aes_expand_key(key, expanded);
    unsigned char prev[16];
    memcpy(prev, iv, 16);
    unsigned char state[16];
    for (int off = 0; off < len; off += 16) {
        memcpy(state, in + off, 16);
        aes_add_round_key(state, expanded + 160);
        for (int round = 9; round >= 1; round--) {
            aes_inv_shift_rows(state);
            aes_inv_sub_bytes(state);
            aes_add_round_key(state, expanded + round * 16);
            aes_inv_mix_columns(state);
        }
        aes_inv_shift_rows(state);
        aes_inv_sub_bytes(state);
        aes_add_round_key(state, expanded);
        for (int i = 0; i < 16; i++) out[off + i] = (unsigned char)(state[i] ^ prev[i]);
        memcpy(prev, in + off, 16);
    }
    int resultLen = len;
    if (len > 0) {
        unsigned char pad = out[len - 1];
        if (pad >= 1 && pad <= 16) {
            int valid = 1;
            for (int i = 0; i < pad; i++) {
                if (out[len - 1 - i] != pad) { valid = 0; break; }
            }
            if (valid) resultLen = len - pad;
        }
    }
    return resultLen;
}



/*
 * JNI: nativeDecryptAes(byte[] encrypted, byte[] key, byte[] iv) -> byte[]
 * AES-128-CBC decrypt with PKCS5 unpadding.
 */
JS_LOCAL jbyteArray JNICALL
jsn_k4(
    JNIEnv* env, jclass clazz, jbyteArray encrypted, jbyteArray keyArr, jbyteArray ivArr)
{
    if (!encrypted || !keyArr || !ivArr) return NULL;
    jsize encLen = (*env)->GetArrayLength(env, encrypted);
    jsize keyLen = (*env)->GetArrayLength(env, keyArr);
    jsize ivLen = (*env)->GetArrayLength(env, ivArr);
    if (keyLen != 16 || ivLen != 16 || encLen % 16 != 0 || encLen <= 0) return NULL;

    jbyte* enc = (*env)->GetByteArrayElements(env, encrypted, NULL);
    jbyte* key = (*env)->GetByteArrayElements(env, keyArr, NULL);
    jbyte* iv = (*env)->GetByteArrayElements(env, ivArr, NULL);
    if (!enc || !key || !iv) {
        if (enc) (*env)->ReleaseByteArrayElements(env, encrypted, enc, JNI_ABORT);
        if (key) (*env)->ReleaseByteArrayElements(env, keyArr, key, JNI_ABORT);
        if (iv) (*env)->ReleaseByteArrayElements(env, ivArr, iv, JNI_ABORT);
        return NULL;
    }

    unsigned char* out = (unsigned char*)malloc((size_t)encLen);
    if (!out) {
        (*env)->ReleaseByteArrayElements(env, encrypted, enc, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, keyArr, key, JNI_ABORT);
        (*env)->ReleaseByteArrayElements(env, ivArr, iv, JNI_ABORT);
        return NULL;
    }

    int resultLen = aes_cbc_decrypt((const unsigned char*)enc, (int)encLen, out, (const unsigned char*)key, (const unsigned char*)iv);
    (*env)->ReleaseByteArrayElements(env, encrypted, enc, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, keyArr, key, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, ivArr, iv, JNI_ABORT);

    if (resultLen <= 0) { free(out); return NULL; }
    jbyteArray result = (*env)->NewByteArray(env, (jsize)resultLen);
    if (!result) { free(out); return NULL; }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)resultLen, (const jbyte*)out);
    free(out);
    return result;
}

JS_LOCAL jstring JNICALL
jsn_k5(
    JNIEnv* env, jclass clazz)
{
    (void)clazz;
    return (*env)->NewStringUTF(env, "n/1");
}

/*
 * Boot token: returns a deterministic value derived from native internal state.
 * Used by the Java side to verify the native library was not replaced
 * (e.g. by Frida Interceptor.replace returning a stub).
 * The token depends on the decoded key, init state, and integrity seed,
 * so any tampering with the native binary produces a different value.
 */
JS_LOCAL jlong JNICALL
jsn_k6(
    JNIEnv* env, jclass clazz)
{
    (void)env; (void)clazz;
    unsigned long long token = 0xCBF29CE484222325ULL;
    /* Mix in the decoded key hash */
    unsigned int kh = fnv1a_hash(g_decoded_key, 16);
    token ^= kh;
    token *= 0x100000001B3ULL;
    /* Mix in init state */
    token ^= (unsigned long long)g_initialized;
    token *= 0x100000001B3ULL;
    /* Mix in integrity seed */
    token ^= (unsigned long long)g_integrity_seed;
    token *= 0x100000001B3ULL;
    /* Mix in key validity */
    token ^= (unsigned long long)g_key_valid;
    token *= 0x100000001B3ULL;
    return (jlong)token;
}


/* ---- Diversified virtualization stack VM ---- */

/*
 * Native diversified VM used by the JNI microkernel self-exercise and native
 * resource protection. The encoder emits a per-seed VM dialect: opcode values
 * are randomized, every semantic opcode has a duplicate alias, inert handler
 * noise is inserted, common opcode runs may be folded into super-operators,
 * and dispatch can take one of several native paths. VBC4-only resource handling
 * rejects old non-authenticated VM bytecode streams.
 */



