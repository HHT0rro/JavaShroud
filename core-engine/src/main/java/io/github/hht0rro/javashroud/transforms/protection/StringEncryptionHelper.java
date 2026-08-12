package io.github.hht0rro.javashroud.transforms.protection;

import java.lang.ref.SoftReference;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;

public final class StringEncryptionHelper {
    static { JniMicrokernelHelper.loadKernel("decrypt", "auto", "vm-diverse"); }

    private static final String STRING_CACHE_PROPERTY = "javashroud.stringCache";
    private static final ConcurrentMap<String, String> STRONG_CACHE = new ConcurrentHashMap<>();
    private static final ConcurrentMap<String, SoftReference<String>> SOFT_CACHE = new ConcurrentHashMap<>();
    private static volatile CachePolicy activeCachePolicy;

    private StringEncryptionHelper() { }

    public static native byte[] nativeDecodeString(byte[] payload, int seed, int flags, long classIdentityHigh, long classIdentityLow);

    public static String cachedDecodeString(byte[] payload, int seed, int flags, long classIdentityHigh, long classIdentityLow) {
        CachePolicy cachePolicy = configuredCachePolicy();
        activateCachePolicy(cachePolicy);
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            throw new SecurityException("string-encryption requires the sealed native kernel (" +
                JniMicrokernelHelper.getLoadStatus() + ")");
        }
        try {
            Supplier<String> decoder = () -> decodedNativeString(
                payload,
                seed,
                flags,
                classIdentityHigh,
                classIdentityLow
            );
            if (cachePolicy == CachePolicy.OFF) return decodedValue(decoder);

            String key = seed + ":" + flags + ":" + Long.toHexString(classIdentityHigh) + ":" +
                Long.toHexString(classIdentityLow) + ":" + new String(payload, StandardCharsets.ISO_8859_1);
            return cachedValue(cachePolicy, key, decoder);
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("string-encryption native decoder is not registered for the sealed helper", error);
        }
    }

    private static String decodedNativeString(byte[] payload, int seed, int flags, long classIdentityHigh, long classIdentityLow) {
        return new String(
            nativeDecodeString(payload, seed, flags, classIdentityHigh, classIdentityLow),
            StandardCharsets.UTF_8
        );
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
