package io.github.hht0rro.javashroud.transforms.protection;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

public final class StringEncryptionHelper {
    static { JniMicrokernelHelper.loadKernel("decrypt", "auto", "vm-diverse"); }

    private static final ConcurrentMap<String, String> CACHE = new ConcurrentHashMap<>();

    private StringEncryptionHelper() { }

    public static native byte[] nativeDecodeString(byte[] payload, int seed, int flags);

    public static String cachedDecodeString(byte[] payload, int seed, int flags) {
        String key = seed + ":" + flags + ":" + new String(payload, StandardCharsets.ISO_8859_1);
        return CACHE.computeIfAbsent(key, ignored -> new String(nativeDecodeString(payload, seed, flags), StandardCharsets.UTF_8));
    }
}
