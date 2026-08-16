package io.github.hht0rro.javashroud.transforms.protection;

import java.lang.ref.SoftReference;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

public final class StringEncryptionHelper {
    private static final String STRING_CACHE_PROPERTY = "javashroud.stringCache";
    private static final ConcurrentMap<String, String> STRONG_CACHE = new ConcurrentHashMap<>();
    private static final ConcurrentMap<String, SoftReference<String>> SOFT_CACHE = new ConcurrentHashMap<>();
    private static volatile CachePolicy activeCachePolicy;

    private StringEncryptionHelper() { }

    /**
     * Opens one AKEN v4 StringPage through its typed native route and applies
     * the existing cache policy only to the resulting JVM String.  The
     * page-local plaintext buffer never becomes a Java cache value and is
     * wiped immediately after UTF-8 decoding.
     */
    public static String cachedDecodeAkenStringPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        CachePolicy cachePolicy = configuredCachePolicy();
        activateCachePolicy(cachePolicy);
        requireAkenStringPageRequest(encodedHandle, pageIndex, callSiteProof);
        try {
            Supplier<String> decoder = () -> decodedAkenStringPage(encodedHandle, pageIndex, callSiteProof);
            if (cachePolicy == CachePolicy.OFF) return decodedValue(decoder);
            return cachedValue(cachePolicy, akenStringPageCacheKey(encodedHandle, pageIndex, callSiteProof), decoder);
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("AKEN string page native decoder is not registered for the sealed helper", error);
        }
    }

    private static String decodedAkenStringPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        byte[] opened = null;
        try {
            opened = JniMicrokernelHelper.decodeAkenStringPage(encodedHandle, pageIndex, callSiteProof);
            return new String(opened, StandardCharsets.UTF_8);
        } finally {
            if (opened != null) Arrays.fill(opened, (byte) 0);
        }
    }

    private static void requireAkenStringPageRequest(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        if (encodedHandle == null || encodedHandle.length != 24 || pageIndex < 0 ||
            callSiteProof == null || callSiteProof.length == 0 || callSiteProof.length > 4096) {
            throw new SecurityException("AKEN string page request is invalid");
        }
    }

    private static String akenStringPageCacheKey(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        /*
         * ISO-8859-1 is a one-byte-to-one-char mapping.  The handle has a
         * fixed width, while page index and proof length are encoded as UTF-16
         * code units before their raw byte bindings.  That makes the cache key
         * unambiguous even when proof bytes contain delimiters or NUL values.
         */
        return new StringBuilder(12 + encodedHandle.length + callSiteProof.length)
            .append("AKEN4")
            .append((char) encodedHandle.length)
            .append(new String(encodedHandle, StandardCharsets.ISO_8859_1))
            .append((char) (pageIndex >>> 16))
            .append((char) pageIndex)
            .append((char) (callSiteProof.length >>> 16))
            .append((char) callSiteProof.length)
            .append(new String(callSiteProof, StandardCharsets.ISO_8859_1))
            .toString();
    }

    private static String cachedValue(CachePolicy cachePolicy, String key, Supplier<String> decoder) {
        switch (cachePolicy) {
            case OFF:
                return decodedValue(decoder);
            case SOFT:
                return softCachedValue(key, decoder);
            case STRONG:
                return STRONG_CACHE.computeIfAbsent(key, ignored -> decodedValue(decoder));
            default:
                throw new SecurityException("unsupported string cache policy");
        }
    }

    private static String softCachedValue(String key, Supplier<String> decoder) {
        for (;;) {
            SoftReference<String> reference = SOFT_CACHE.get(key);
            if (reference != null) {
                String cached = reference.get();
                if (cached != null) return cached;
                SOFT_CACHE.remove(key, reference);
            }

            String decoded = decodedValue(decoder);
            SoftReference<String> replacement = new SoftReference<>(decoded);
            SoftReference<String> existing = SOFT_CACHE.putIfAbsent(key, replacement);
            if (existing == null) return decoded;

            String cached = existing.get();
            if (cached != null) return cached;
            if (SOFT_CACHE.replace(key, existing, replacement)) return decoded;
        }
    }

    private static String decodedValue(Supplier<String> decoder) {
        String decoded = decoder.get();
        if (decoded == null) throw new SecurityException("string-encryption native decoder returned no value");
        return decoded;
    }

    private static CachePolicy configuredCachePolicy() {
        String configured = System.getProperty(STRING_CACHE_PROPERTY);
        if (configured == null || configured.trim().isEmpty()) return CachePolicy.SOFT;
        switch (configured.trim().toLowerCase(Locale.ROOT)) {
            case "off":
                return CachePolicy.OFF;
            case "soft":
                return CachePolicy.SOFT;
            case "strong":
                return CachePolicy.STRONG;
            default:
                throw new SecurityException("unsupported javashroud.stringCache policy: " + configured);
        }
    }

    private static void activateCachePolicy(CachePolicy cachePolicy) {
        if (activeCachePolicy == cachePolicy) return;
        synchronized (StringEncryptionHelper.class) {
            if (activeCachePolicy != cachePolicy) {
                STRONG_CACHE.clear();
                SOFT_CACHE.clear();
                activeCachePolicy = cachePolicy;
            }
        }
    }

    /* Package-private test hooks: cache state is observable, decrypted values are not. */
    static void cacheForTesting(String key, Supplier<String> decoder) {
        CachePolicy cachePolicy = configuredCachePolicy();
        activateCachePolicy(cachePolicy);
        cachedValue(cachePolicy, key, decoder);
    }

    static String cachePolicyForTesting() {
        return configuredCachePolicy().propertyValue;
    }

    static void resetCacheForTesting() {
        synchronized (StringEncryptionHelper.class) {
            STRONG_CACHE.clear();
            SOFT_CACHE.clear();
            activeCachePolicy = null;
        }
    }

    static int softCacheEntryCountForTesting() {
        return SOFT_CACHE.size();
    }

    static int strongCacheEntryCountForTesting() {
        return STRONG_CACHE.size();
    }

    private enum CachePolicy {
        OFF("off"),
        SOFT("soft"),
        STRONG("strong");

        private final String propertyValue;

        CachePolicy(String propertyValue) {
            this.propertyValue = propertyValue;
        }
    }
}
