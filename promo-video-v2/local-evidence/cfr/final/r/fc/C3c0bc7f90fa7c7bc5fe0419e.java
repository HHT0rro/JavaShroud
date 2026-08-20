/*
 * Decompiled with CFR 0.152.
 */
package r.fc;

import java.lang.ref.SoftReference;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;
import r.2e.C02f581bd2c02dabf8066a201;

public final class C3c0bc7f90fa7c7bc5fe0419e {
    private static final /* synthetic */ String STRING_CACHE_PROPERTY = "javashroud.stringCache";
    private static final /* synthetic */ ConcurrentMap<String, String> STRONG_CACHE;
    private static final /* synthetic */ ConcurrentMap<String, SoftReference<String>> SOFT_CACHE;
    private static volatile /* synthetic */ Ib4cf4fd4070f451d activeCachePolicy;

    private C3c0bc7f90fa7c7bc5fe0419e() {
    }

    public static native /* synthetic */ byte[] m_88372f05c76a0d2a(byte[] var0, int var1, int var2, long var3, long var5);

    public static /* synthetic */ String cachedDecodeString(byte[] byArray, int n, int n2, long l, long l2) {
        Ib4cf4fd4070f451d ib4cf4fd4070f451d = C3c0bc7f90fa7c7bc5fe0419e.configuredCachePolicy();
        C3c0bc7f90fa7c7bc5fe0419e.activateCachePolicy(ib4cf4fd4070f451d);
        if (!C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            throw new SecurityException("string-encryption requires the sealed native kernel (" + C02f581bd2c02dabf8066a201.getLoadStatus() + ")");
        }
        try {
            Supplier<String> supplier = () -> C3c0bc7f90fa7c7bc5fe0419e.decodedNativeString(byArray, n, n2, l, l2);
            if (ib4cf4fd4070f451d == Ib4cf4fd4070f451d.OFF) {
                return C3c0bc7f90fa7c7bc5fe0419e.decodedValue(supplier);
            }
            String string = n + ":" + n2 + ":" + Long.toHexString(l) + ":" + Long.toHexString(l2) + ":" + new String(byArray, StandardCharsets.ISO_8859_1);
            return C3c0bc7f90fa7c7bc5fe0419e.cachedValue(ib4cf4fd4070f451d, string, supplier);
        }
        catch (UnsatisfiedLinkError unsatisfiedLinkError) {
            throw new SecurityException("string-encryption native decoder is not registered for the sealed helper", unsatisfiedLinkError);
        }
    }

    private static /* synthetic */ String decodedNativeString(byte[] byArray, int n, int n2, long l, long l2) {
        return new String(C3c0bc7f90fa7c7bc5fe0419e.m_88372f05c76a0d2a(byArray, n, n2, l, l2), StandardCharsets.UTF_8);
    }

    private static /* synthetic */ String cachedValue(Ib4cf4fd4070f451d ib4cf4fd4070f451d, String string2, Supplier<String> supplier) {
        switch (ib4cf4fd4070f451d.ordinal()) {
            case 0: {
                return C3c0bc7f90fa7c7bc5fe0419e.decodedValue(supplier);
            }
            case 1: {
                return C3c0bc7f90fa7c7bc5fe0419e.softCachedValue(string2, supplier);
            }
            case 2: {
                return STRONG_CACHE.computeIfAbsent(string2, string -> C3c0bc7f90fa7c7bc5fe0419e.decodedValue(supplier));
            }
        }
        throw new SecurityException("unsupported string cache policy");
    }

    private static /* synthetic */ String softCachedValue(String string, Supplier<String> supplier) {
        String string2;
        SoftReference<String> softReference;
        SoftReference<String> softReference2;
        do {
            SoftReference softReference3;
            if ((softReference3 = (SoftReference)SOFT_CACHE.get(string)) != null) {
                string2 = (String)softReference3.get();
                if (string2 != null) {
                    return string2;
                }
                SOFT_CACHE.remove(string, softReference3);
            }
            if ((softReference2 = SOFT_CACHE.putIfAbsent(string, softReference = new SoftReference<String>(string2 = C3c0bc7f90fa7c7bc5fe0419e.decodedValue(supplier)))) == null) {
                return string2;
            }
            String string3 = softReference2.get();
            if (string3 == null) continue;
            return string3;
        } while (!SOFT_CACHE.replace(string, softReference2, softReference));
        return string2;
    }

    private static /* synthetic */ String decodedValue(Supplier<String> supplier) {
        String string = supplier.get();
        if (string == null) {
            throw new SecurityException("string-encryption native decoder returned no value");
        }
        return string;
    }

    private static /* synthetic */ Ib4cf4fd4070f451d configuredCachePolicy() {
        String string = System.getProperty(STRING_CACHE_PROPERTY);
        if (string == null || string.trim().isEmpty()) {
            return Ib4cf4fd4070f451d.SOFT;
        }
        switch (string.trim().toLowerCase(Locale.ROOT)) {
            case "off": {
                return Ib4cf4fd4070f451d.OFF;
            }
            case "soft": {
                return Ib4cf4fd4070f451d.SOFT;
            }
            case "strong": {
                return Ib4cf4fd4070f451d.STRONG;
            }
        }
        throw new SecurityException("unsupported javashroud.stringCache policy: " + string);
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ void activateCachePolicy(Ib4cf4fd4070f451d ib4cf4fd4070f451d) {
        if (activeCachePolicy == ib4cf4fd4070f451d) {
            return;
        }
        Class<C3c0bc7f90fa7c7bc5fe0419e> clazz = C3c0bc7f90fa7c7bc5fe0419e.class;
        synchronized (C3c0bc7f90fa7c7bc5fe0419e.class) {
            if (activeCachePolicy != ib4cf4fd4070f451d) {
                STRONG_CACHE.clear();
                SOFT_CACHE.clear();
                activeCachePolicy = ib4cf4fd4070f451d;
            }
            // ** MonitorExit[var1_1] (shouldn't be in output)
            return;
        }
    }

    static /* synthetic */ void cacheForTesting(String string, Supplier<String> supplier) {
        Ib4cf4fd4070f451d ib4cf4fd4070f451d = C3c0bc7f90fa7c7bc5fe0419e.configuredCachePolicy();
        C3c0bc7f90fa7c7bc5fe0419e.activateCachePolicy(ib4cf4fd4070f451d);
        C3c0bc7f90fa7c7bc5fe0419e.cachedValue(ib4cf4fd4070f451d, string, supplier);
    }

    static /* synthetic */ String cachePolicyForTesting() {
        return C3c0bc7f90fa7c7bc5fe0419e.configuredCachePolicy().propertyValue;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    static /* synthetic */ void resetCacheForTesting() {
        Class<C3c0bc7f90fa7c7bc5fe0419e> clazz = C3c0bc7f90fa7c7bc5fe0419e.class;
        synchronized (C3c0bc7f90fa7c7bc5fe0419e.class) {
            STRONG_CACHE.clear();
            SOFT_CACHE.clear();
            activeCachePolicy = null;
            // ** MonitorExit[var0] (shouldn't be in output)
            return;
        }
    }

    static /* synthetic */ int softCacheEntryCountForTesting() {
        return SOFT_CACHE.size();
    }

    static /* synthetic */ int strongCacheEntryCountForTesting() {
        return STRONG_CACHE.size();
    }

    static {
        C02f581bd2c02dabf8066a201.m_d7c5053f05b22be5("decrypt", "auto", "vm-diverse");
        STRONG_CACHE = new ConcurrentHashMap<String, String>();
        SOFT_CACHE = new ConcurrentHashMap<String, SoftReference<String>>();
    }

    private static enum Ib4cf4fd4070f451d {
        OFF("off"),
        SOFT("soft"),
        STRONG("strong");

        private final /* synthetic */ String propertyValue;

        private Ib4cf4fd4070f451d(String string2) {
            this.propertyValue = string2;
        }
    }
}

