package io.github.hht0rro.javashroud.transforms.protection;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.Method;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.lang.invoke.CallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.LambdaMetafactory;
import java.util.LinkedHashSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Runtime helper for JNI microkernel loader.
 * Pure Java - no Kotlin runtime dependency.
 *
 * Attempts to load a bundled native kernel from the JAR resources.
 * In pure VBC4-only mode this helper is strictly fail-closed:
 * native bootstrap and load logic remain, and native ABI failures reject execution.
 */
public final class JniMicrokernelHelper {

    private static final int LOAD_FAILED = -1;
    private static final int LOAD_UNTRIED = 0;
    private static final int LOAD_LOADING = 1;
    private static final int LOAD_READY = 2;
    private static volatile int loadState = LOAD_UNTRIED;
    private static volatile String loadMessage = "";
    private static volatile int akenLoadState = LOAD_UNTRIED;
    private static volatile String akenLoadMessage = "";
    private static volatile boolean diversifiedVmEnabled;
    private static volatile String vmSelfCheck = "";
    private static volatile boolean nativeSelfCheckFailed;
    private static volatile boolean sealedNativeBindingsPublished;
    private static final String AKEN_NATIVE_LOCATOR_RESOURCE = "META-INF/jsrt/native.locator";
    private static final String AKEN_NATIVE_BINDINGS_LOCATOR_RESOURCE = "META-INF/jsrt/native.bindings.locator";
    private static final String AKEN_NATIVE_RESOURCE_ROOT = "META-INF/";
    private static final int AKEN_NATIVE_LOCATOR_MAGIC_0 = 0xD7;
    private static final int AKEN_NATIVE_LOCATOR_MAGIC_1 = 0xA4;
    private static final int AKEN_NATIVE_LOCATOR_MAGIC_2 = 0x91;
    private static final int AKEN_NATIVE_LOCATOR_MAGIC_3 = 0xE3;
    private static final String AKEN_NATIVE_LOCATOR_COMMITMENT_DOMAIN =
        "javashroud-aken-native-locator-commitment-v2";
    private static final String AKEN_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN =
        "javashroud-aken-native-locator-route-mask-v2";
    private static final int AKEN_NATIVE_LOCATOR_VERSION = 2;
    private static final int AKEN_NATIVE_LOCATOR_HEADER_BYTES = 8;
    private static final int AKEN_NATIVE_LOCATOR_COMMITMENT_BYTES = 32;
    private static final int AKEN_NATIVE_LOCATOR_RECORD_FIXED_BYTES = 40;
    private static final int AKEN_NATIVE_LOCATOR_MAX_RECORDS = 3;
    private static final int AKEN_NATIVE_LOCATOR_MAX_ROUTE_BYTES = 2048;
    private static final int AKEN_NATIVE_LOCATOR_KIND_LIBRARY = 1;
    private static final int AKEN_NATIVE_LOCATOR_KIND_BINDINGS = 2;
    private static final int AKEN_NATIVE_LOCATOR_MAX_BYTES = 16 * 1024;
    private static final int AKEN_NATIVE_MAX_LIBRARY_BYTES = 256 * 1024 * 1024;
    private static final int AKEN_NATIVE_SHA256_LENGTH = 32;
    private static final int AKEN_NATIVE_BINDINGS_MAX_BYTES = 4 * 1024 * 1024;
    private static final int LAMBDA_FLAG_SERIALIZABLE = 1;
    private static final int LAMBDA_FLAG_MARKERS = 2;
    private static final int LAMBDA_FLAG_BRIDGES = 4;
    private static final int LAMBDA_SUPPORTED_FLAGS = LAMBDA_FLAG_SERIALIZABLE | LAMBDA_FLAG_MARKERS | LAMBDA_FLAG_BRIDGES;
    private static final ConcurrentMap<String, MethodHandle> SAM_LAMBDA_CACHE = new ConcurrentHashMap<>();
    private static final ConcurrentMap<String, Class<?>> SAM_BRIDGE_INTERFACE_CACHE = new ConcurrentHashMap<>();

    private JniMicrokernelHelper() { }

    /* ---- JNI R1 methods (implemented by the bundled Rust runtime) ---- */

    static native int nativeInit(String platform);
    static native int nativeHeartbeat();
    static native boolean nativeInstallAkenSessionNonce(byte[] startupNonce);
    static native Object nativeExecuteAkenVmPage(long entryToken, byte[] encodedHandle, int pageIndex, byte[] callSiteProof, Object[] args);
    static native String nativeOpenAkenString(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);
    static native byte[] nativeReadAkenClassPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);
    static native void nativeConsumeAkenNativeChunk(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    /* ---- AKEN R1 typed page bridge ---- */

    public static Object executeAkenVmPage(long entryToken, byte[] encodedHandle, int pageIndex, byte[] callSiteProof, Object[] args) {
        requireAkenPageRequest(encodedHandle, pageIndex, callSiteProof, "VM");
        ensureAkenNativeKernel();
        try {
            /* A null result is valid for a virtualized void method and for a
             * reference-returning method whose value is null. The native bridge
             * reports every unsuccessful execution by throwing SecurityException
             * before returning to this call site. */
            return nativeExecuteAkenVmPage(entryToken, encodedHandle, pageIndex, callSiteProof, args);
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("AKEN VM page bridge is not registered for the sealed helper", error);
        }
    }

    static String openAkenString(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        requireAkenPageRequest(encodedHandle, pageIndex, callSiteProof, "string");
        ensureAkenNativeKernel();
        String result = nativeOpenAkenString(encodedHandle, pageIndex, callSiteProof);
        if (result == null) throw new SecurityException("AKEN string page access failed closed");
        return result;
    }

    public static byte[] readAkenClassPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        requireAkenPageRequest(encodedHandle, pageIndex, callSiteProof, "class");
        ensureAkenNativeKernel();
        return requireAkenPageResult(nativeReadAkenClassPage(encodedHandle, pageIndex, callSiteProof), "class");
    }

    /**
     * Opens and consumes exactly one authenticated native-private chunk inside
     * the JNI kernel.  The decrypted chunk never crosses the JNI boundary.
     */
    public static void consumeAkenNativeChunk(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        requireAkenPageRequest(encodedHandle, pageIndex, callSiteProof, "native");
        ensureAkenNativeKernel();
        nativeConsumeAkenNativeChunk(encodedHandle, pageIndex, callSiteProof);
    }

    private static void requireAkenPageRequest(byte[] encodedHandle, int pageIndex, byte[] callSiteProof, String purpose) {
        if (encodedHandle == null || encodedHandle.length != 24 || pageIndex < 0 || callSiteProof == null || callSiteProof.length == 0 || callSiteProof.length > 4096) {
            throw new SecurityException("AKEN " + purpose + " page request is invalid");
        }
    }

    private static void ensureAkenNativeKernel() {
        if (akenLoadState == LOAD_UNTRIED) loadAkenNativeKernel();
        if (akenLoadState != LOAD_READY) {
            throw new SecurityException("AKEN page access requires the sealed native kernel (" + akenLoadMessage + ")");
        }
    }

    /** Load only the authenticated AKEN-R1 Rust JNI artifact. */
    private static synchronized void loadAkenNativeKernel() {
        if (akenLoadState != LOAD_UNTRIED) return;
        akenLoadState = LOAD_LOADING;
        try {
            String platformTarget = detectPlatform();
            if (platformTarget == null) {
                akenLoadMessage = "aken:native-unavailable";
                akenLoadState = LOAD_FAILED;
                return;
            }
            if (!tryLoadAkenBundledNative(platformTarget)) {
                if (akenLoadMessage == null || akenLoadMessage.length() == 0) {
                    akenLoadMessage = "aken:bundled-native-unavailable";
                }
                akenLoadState = LOAD_FAILED;
                return;
            }
            akenLoadState = LOAD_READY;
            nativeSelfCheckFailed = false;
            runDiversifiedVmSelfExercise();
        } catch (Throwable error) {
            akenLoadMessage = debugNativeLoadMessage("aken:native-exception", error);
            akenLoadState = LOAD_FAILED;
        }
    }

    private static boolean tryLoadAkenBundledNative(String platformTarget) {
        AkenNativeLibrary locator;
        try {
            locator = readAkenNativeLocator(platformTarget);
        } catch (SecurityException error) {
            akenLoadMessage = "aken:native-locator-invalid:" + platformTarget;
            return false;
        }
        return tryLoadAkenBundledNativeResource(platformTarget, locator);
    }

    private static boolean tryLoadAkenBundledNativeResource(String platformTarget, AkenNativeLibrary locator) {
        byte[] nativeBytes = null;
        byte[] actualDigest = null;
        File tempLib = null;
        String previousLoaderOwner = System.getProperty(sealedLoaderPropertyName());
        String previousClassBindings = System.getProperty(sealedBindingPropertyName());
        String previousMethodBindings = System.getProperty(sealedMethodBindingPropertyName());
        String previousFieldBindings = System.getProperty(sealedFieldBindingPropertyName());
        boolean previousBindingsPublished = sealedNativeBindingsPublished;
        boolean loaded = false;
        try (InputStream in = resourceStream(locator.resourcePath)) {
            if (in == null) {
                akenLoadMessage = "aken:native-resource-missing:" + platformTarget;
                return false;
            }
            nativeBytes = readAllBounded(in, locator.storedLength);
            if (nativeBytes.length != locator.storedLength || hasAkenRejectedLegacyHeader(nativeBytes)) {
                akenLoadMessage = "aken:native-resource-invalid:" + platformTarget;
                return false;
            }
            validateR1NativeImage(platformTarget, nativeBytes);
            actualDigest = sha256(nativeBytes);
            if (!MessageDigest.isEqual(locator.sha256, actualDigest)) {
                akenLoadMessage = "aken:native-resource-digest-mismatch:" + platformTarget;
                return false;
            }
            String bindingText = sealedNativeBindingText(locator);
            if (bindingText == null || bindingText.length() == 0) {
                akenLoadMessage = "aken:native-bindings-invalid:" + platformTarget;
                return false;
            }
            for (File extractDirectory : nativeExtractDirectories()) {
                if (!ensureNativeExtractDirectory(extractDirectory)) continue;
                tempLib = createUniqueTempFile(nativeTempPrefix(locator.resourcePath), locator.fileSuffix, extractDirectory);
                tempLib.deleteOnExit();
                try (FileOutputStream out = new FileOutputStream(tempLib)) {
                    out.write(nativeBytes);
                }
                tempLib.setReadable(true, true);
                tempLib.setWritable(true, true);
                tempLib.setExecutable(true, true);
                publishSealedNativeBindings(bindingText);
                sealedNativeBindingsPublished = true;
                System.load(tempLib.getAbsolutePath());
                int initResult = initializeNativeKernel(platformTarget);
                if (initResult < 0) {
                    akenLoadMessage = "aken:native-init-failed:" + initResult;
                    return false;
                }
                installAkenSessionNonce();
                if (!verifyAkenNativeAbiAfterLoad()) return false;
                akenLoadMessage = "aken:native:bundled:" + platformTarget + ":" + initResult;
                loaded = true;
                return true;
            }
            akenLoadMessage = "aken:native-extract-unavailable:" + platformTarget;
            return false;
        } catch (UnsatisfiedLinkError error) {
            akenLoadMessage = debugNativeLoadMessage("aken:native-load-error", error);
            return false;
        } catch (Throwable error) {
            akenLoadMessage = debugNativeLoadMessage("aken:native-init-error", error);
            return false;
        } finally {
            if (nativeBytes != null) Arrays.fill(nativeBytes, (byte) 0);
            if (actualDigest != null) Arrays.fill(actualDigest, (byte) 0);
            locator.clear();
            if (!loaded && tempLib != null) tempLib.delete();
            if (!loaded) {
                sealedNativeBindingsPublished = previousBindingsPublished;
                restoreLoaderProperty(previousLoaderOwner);
                restoreProperty(sealedBindingPropertyName(), previousClassBindings);
                restoreProperty(sealedMethodBindingPropertyName(), previousMethodBindings);
                restoreProperty(sealedFieldBindingPropertyName(), previousFieldBindings);
            }
        }
    }

    private static boolean verifyAkenNativeAbiAfterLoad() {
        byte[] handle = new byte[24];
        byte[] proof = new byte[] { 1 };
        try {
            if (nativeHeartbeat() < 0) {
                akenLoadMessage = "aken:abi-failed:nativeHeartbeat";
                return false;
            }
            try {
                nativeExecuteAkenVmPage(0L, handle, 0, proof, null);
            } catch (SecurityException expectedRouteFailure) {
                // The current native bridge is intentionally fail-closed until page routing lands.
            }
            try {
                nativeOpenAkenString(handle, 0, proof);
            } catch (SecurityException expectedRouteFailure) {
                // Registered typed route reached native code.
            }
            try {
                nativeReadAkenClassPage(handle, 0, proof);
            } catch (SecurityException expectedRouteFailure) {
                // Registered typed route reached native code.
            }
            try {
                nativeConsumeAkenNativeChunk(handle, 0, proof);
            } catch (SecurityException expectedRouteFailure) {
                // Registered typed route reached native code.
            }
            return true;
        } catch (UnsatisfiedLinkError error) {
            akenLoadMessage = "aken:abi-missing:typed-page-bridge";
            return false;
        } catch (Throwable error) {
            akenLoadMessage = "aken:abi-probe-failed:" + error.getClass().getName();
            return false;
        } finally {
            Arrays.fill(handle, (byte) 0);
            Arrays.fill(proof, (byte) 0);
        }
    }

    private static void validateR1NativeImage(String platformTarget, byte[] bytes) {
        if (bytes == null || bytes.length < 64 || hasAkenRejectedLegacyHeader(bytes)) {
            throw new SecurityException("AKEN-R1 native image is invalid");
        }
        if ("x86_64-pc-windows-gnu".equals(platformTarget)) {
            if (bytes[0] != 'M' || bytes[1] != 'Z') {
                throw new SecurityException("AKEN-R1 Windows image is not PE");
            }
            int peOffset = readLittleEndianInt(bytes, 0x3C);
            if (peOffset < 0 || peOffset > bytes.length - 24 || bytes[peOffset] != 'P' ||
                bytes[peOffset + 1] != 'E' || bytes[peOffset + 2] != 0 || bytes[peOffset + 3] != 0 ||
                readLittleEndianShort(bytes, peOffset + 4) != 0x8664) {
                throw new SecurityException("AKEN-R1 Windows image architecture is invalid");
            }
            int sectionCount = readLittleEndianShort(bytes, peOffset + 6);
            int optionalHeaderSize = readLittleEndianShort(bytes, peOffset + 20);
            int characteristics = readLittleEndianShort(bytes, peOffset + 22);
            int optionalHeaderOffset = peOffset + 24;
            if (sectionCount < 1 || sectionCount > 96 || optionalHeaderSize < 112 ||
                optionalHeaderOffset > bytes.length - optionalHeaderSize ||
                readLittleEndianShort(bytes, optionalHeaderOffset) != 0x20B ||
                (characteristics & 0x2000) == 0) {
                throw new SecurityException("AKEN-R1 Windows image is not an AMD64 DLL");
            }
            long sectionTableEnd = (long) optionalHeaderOffset + optionalHeaderSize + (long) sectionCount * 40L;
            if (sectionTableEnd > bytes.length) {
                throw new SecurityException("AKEN-R1 Windows image section table is invalid");
            }
        } else if ("x86_64-unknown-linux-gnu.2.17".equals(platformTarget)) {
            if (bytes[0] != 0x7F || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F' ||
                bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 ||
                readLittleEndianShort(bytes, 16) != 3 || readLittleEndianShort(bytes, 18) != 62 ||
                readLittleEndianInt(bytes, 20) != 1) {
                throw new SecurityException("AKEN-R1 Linux image is not an AMD64 ELF shared object");
            }
            long programHeaderOffset = readLittleEndianLong(bytes, 32);
            int elfHeaderSize = readLittleEndianShort(bytes, 52);
            int programHeaderEntrySize = readLittleEndianShort(bytes, 54);
            int programHeaderCount = readLittleEndianShort(bytes, 56);
            long programHeaderBytes = (long) programHeaderEntrySize * programHeaderCount;
            if (programHeaderOffset < 0L || elfHeaderSize < 64 || programHeaderEntrySize < 56 ||
                programHeaderCount < 1 || programHeaderCount > 1024 ||
                programHeaderOffset > bytes.length || programHeaderBytes > bytes.length - programHeaderOffset) {
                throw new SecurityException("AKEN-R1 Linux image program headers are invalid");
            }
        } else {
            throw new SecurityException("AKEN-R1 target is unsupported");
        }
        String[] requiredMarkers = new String[] {
            "JNI_OnLoad",
            "JNI_OnUnload",
            "jsrt_r1_runtime_binding_digest",
            "jsrt_r1_open_frame",
            "nativeInit",
            "nativeHeartbeat",
            "nativeInstallAkenSessionNonce",
            "nativeExecuteAkenVmPage",
            "nativeOpenAkenString",
            "nativeReadAkenClassPage",
            "nativeConsumeAkenNativeChunk",
        };
        for (String marker : requiredMarkers) {
            if (!containsAscii(bytes, marker)) {
                throw new SecurityException("AKEN-R1 native image is missing binding " + marker);
            }
        }
    }

    private static boolean containsAscii(byte[] bytes, String value) {
        byte[] needle = value.getBytes(StandardCharsets.US_ASCII);
        if (needle.length == 0 || bytes.length < needle.length) return false;
        for (int start = 0; start <= bytes.length - needle.length; start++) {
            boolean match = true;
            for (int index = 0; index < needle.length; index++) {
                if (bytes[start + index] != needle[index]) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        return false;
    }

    private static int readLittleEndianShort(byte[] bytes, int offset) {
        if (offset < 0 || offset > bytes.length - 2) return -1;
        return (bytes[offset] & 0xFF) | ((bytes[offset + 1] & 0xFF) << 8);
    }

    private static int readLittleEndianInt(byte[] bytes, int offset) {
        if (offset < 0 || offset > bytes.length - 4) return -1;
        return (bytes[offset] & 0xFF) |
            ((bytes[offset + 1] & 0xFF) << 8) |
            ((bytes[offset + 2] & 0xFF) << 16) |
            ((bytes[offset + 3] & 0xFF) << 24);
    }

    private static long readLittleEndianLong(byte[] bytes, int offset) {
        if (offset < 0 || offset > bytes.length - 8) return -1L;
        long value = 0L;
        for (int index = 0; index < 8; index++) {
            value |= (long) (bytes[offset + index] & 0xFF) << (index * 8);
        }
        return value;
    }

    private static byte[] requireAkenPageResult(byte[] result, String purpose) {
        if (result == null) throw new SecurityException("AKEN " + purpose + " page access failed closed");
        return result;
    }

    private static byte[] readAkenNativeLocatorBytes() throws Exception {
        try (InputStream in = resourceStream(AKEN_NATIVE_LOCATOR_RESOURCE)) {
            return in == null ? null : readAllBounded(in, AKEN_NATIVE_LOCATOR_MAX_BYTES);
        }
    }

    /** Resolve and authenticate one binary AKEN-R1 locator for the active target. */
    private static AkenNativeLibrary readAkenNativeLocator(String expectedPlatform) {
        byte[] raw = null;
        byte[] expectedCommitment = null;
        byte[] storedCommitment = null;
        byte[] bindingSha256 = null;
        AkenNativeLibrary selected = null;
        boolean completed = false;
        try {
            raw = readAkenNativeLocatorBytes();
            if (raw == null) throw new SecurityException("AKEN native locator is missing");
            if (raw.length < AKEN_NATIVE_LOCATOR_HEADER_BYTES + AKEN_NATIVE_LOCATOR_COMMITMENT_BYTES ||
                hasAkenRejectedLegacyHeader(raw) || !hasAkenLocatorMagic(raw) ||
                (raw[4] & 0xFF) != AKEN_NATIVE_LOCATOR_VERSION || (raw[5] & 0xFF) != 0) {
                throw new SecurityException("AKEN native locator binary header is invalid");
            }
            int payloadLength = raw.length - AKEN_NATIVE_LOCATOR_COMMITMENT_BYTES;
            expectedCommitment = akenNativeLocatorCommitment(raw, payloadLength);
            storedCommitment = Arrays.copyOfRange(raw, payloadLength, raw.length);
            if (!MessageDigest.isEqual(expectedCommitment, storedCommitment)) {
                throw new SecurityException("AKEN native locator commitment is invalid");
            }
            int recordCount = readAkenLocatorU16(raw, 6, payloadLength);
            if (recordCount < 1 || recordCount > AKEN_NATIVE_LOCATOR_MAX_RECORDS) {
                throw new SecurityException("AKEN native locator record count is invalid");
            }

            int expectedPlatformId = akenNativePlatformId(expectedPlatform);
            if (expectedPlatformId == 0) {
                throw new SecurityException("AKEN native locator requested platform is invalid");
            }
            int offset = AKEN_NATIVE_LOCATOR_HEADER_BYTES;
            int lastPlatformId = 0;
            boolean bindingSeen = false;
            String bindingResourcePath = null;
            int bindingStoredLength = 0;
            LinkedHashSet<String> seenRoutes = new LinkedHashSet<>();
            for (int recordIndex = 0; recordIndex < recordCount; recordIndex++) {
                if (offset < 0 || offset > payloadLength - AKEN_NATIVE_LOCATOR_RECORD_FIXED_BYTES) {
                    throw new SecurityException("AKEN native locator record is truncated");
                }
                int kind = raw[offset++] & 0xFF;
                int platformId = raw[offset++] & 0xFF;
                int routeLength = readAkenLocatorU16(raw, offset, payloadLength);
                offset += 2;
                int storedLength = readAkenLocatorPositiveU32(raw, offset, payloadLength);
                offset += 4;
                if (routeLength < 1 || routeLength > AKEN_NATIVE_LOCATOR_MAX_ROUTE_BYTES ||
                    offset > payloadLength - AKEN_NATIVE_SHA256_LENGTH ||
                    routeLength > payloadLength - offset - AKEN_NATIVE_SHA256_LENGTH) {
                    throw new SecurityException("AKEN native locator route length is invalid");
                }
                byte[] digest = Arrays.copyOfRange(raw, offset, offset + AKEN_NATIVE_SHA256_LENGTH);
                offset += AKEN_NATIVE_SHA256_LENGTH;
                byte[] maskedRoute = Arrays.copyOfRange(raw, offset, offset + routeLength);
                offset += routeLength;
                byte[] routeBytes = null;
                boolean digestTransferred = false;
                try {
                    routeBytes = unmaskAkenNativeLocatorRoute(
                        maskedRoute,
                        kind,
                        platformId,
                        storedLength,
                        digest
                    );
                    if (!isAkenNativeRouteBytes(routeBytes)) {
                        throw new SecurityException("AKEN native locator route encoding is invalid");
                    }
                    String resourcePath = new String(routeBytes, StandardCharsets.US_ASCII);
                    if (!isAkenNativeResourcePath(resourcePath) || !seenRoutes.add(resourcePath)) {
                        throw new SecurityException("AKEN native locator route is invalid or duplicated");
                    }

                    if (kind == AKEN_NATIVE_LOCATOR_KIND_LIBRARY) {
                        if (bindingSeen || platformId <= lastPlatformId || platformId > 2 ||
                            storedLength > AKEN_NATIVE_MAX_LIBRARY_BYTES) {
                            throw new SecurityException("AKEN native locator platform record is invalid");
                        }
                        lastPlatformId = platformId;
                        String fileSuffix = akenNativeSuffix(platformId);
                        if (fileSuffix == null || !resourcePath.endsWith(fileSuffix)) {
                            throw new SecurityException("AKEN native locator suffix binding is invalid");
                        }
                        if (platformId == expectedPlatformId) {
                            if (selected != null) {
                                throw new SecurityException("AKEN native locator has duplicate active platform");
                            }
                            selected = new AkenNativeLibrary(resourcePath, fileSuffix, storedLength, digest);
                            digestTransferred = true;
                        }
                    } else if (kind == AKEN_NATIVE_LOCATOR_KIND_BINDINGS) {
                        if (platformId != 0 || bindingSeen || recordIndex != recordCount - 1 ||
                            storedLength > AKEN_NATIVE_BINDINGS_MAX_BYTES) {
                            throw new SecurityException("AKEN native bindings locator record is invalid");
                        }
                        bindingSeen = true;
                        bindingResourcePath = resourcePath;
                        bindingStoredLength = storedLength;
                        bindingSha256 = digest;
                        digestTransferred = true;
                    } else {
                        throw new SecurityException("AKEN native locator record kind is invalid");
                    }
                } finally {
                    Arrays.fill(maskedRoute, (byte) 0);
                    if (routeBytes != null) Arrays.fill(routeBytes, (byte) 0);
                    if (!digestTransferred) Arrays.fill(digest, (byte) 0);
                }
            }
            if (offset != payloadLength) throw new SecurityException("AKEN native locator has trailing bytes");
            if (selected == null) throw new SecurityException("AKEN native locator has no active platform route");
            if (!bindingSeen || bindingResourcePath == null || bindingSha256 == null) {
                throw new SecurityException("AKEN native locator has no final binding route");
            }
            selected.bindingResourcePath = bindingResourcePath;
            selected.bindingStoredLength = bindingStoredLength;
            selected.bindingSha256 = bindingSha256;
            bindingSha256 = null;
            completed = true;
            return selected;
        } catch (SecurityException error) {
            throw error;
        } catch (Exception error) {
            throw new SecurityException("AKEN native locator is unreadable", error);
        } finally {
            if (raw != null) Arrays.fill(raw, (byte) 0);
            if (expectedCommitment != null) Arrays.fill(expectedCommitment, (byte) 0);
            if (storedCommitment != null) Arrays.fill(storedCommitment, (byte) 0);
            if (bindingSha256 != null) Arrays.fill(bindingSha256, (byte) 0);
            if (!completed && selected != null) selected.clear();
        }
    }

    private static boolean hasAkenLocatorMagic(byte[] bytes) {
        return bytes != null && bytes.length >= 4 &&
            (bytes[0] & 0xFF) == AKEN_NATIVE_LOCATOR_MAGIC_0 &&
            (bytes[1] & 0xFF) == AKEN_NATIVE_LOCATOR_MAGIC_1 &&
            (bytes[2] & 0xFF) == AKEN_NATIVE_LOCATOR_MAGIC_2 &&
            (bytes[3] & 0xFF) == AKEN_NATIVE_LOCATOR_MAGIC_3;
    }

    private static int akenNativePlatformId(String platform) {
        if ("x86_64-pc-windows-gnu".equals(platform)) return 1;
        if ("x86_64-unknown-linux-gnu.2.17".equals(platform)) return 2;
        return 0;
    }

    private static String akenNativeSuffix(int platformId) {
        if (platformId == 1) return ".dll";
        if (platformId == 2) return ".so";
        return null;
    }

    private static boolean isAkenNativeResourcePath(String resourcePath) {
        if (resourcePath == null || !resourcePath.startsWith(AKEN_NATIVE_RESOURCE_ROOT) ||
            resourcePath.length() == AKEN_NATIVE_RESOURCE_ROOT.length() || resourcePath.indexOf('\\') >= 0 ||
            resourcePath.indexOf('\u0000') >= 0 || resourcePath.indexOf('|') >= 0 ||
            resourcePath.indexOf('\r') >= 0 || resourcePath.indexOf('\n') >= 0) {
            return false;
        }
        String normalizedPath = resourcePath.toLowerCase(Locale.ROOT);
        if (normalizedPath.startsWith("meta-inf/.r/") ||
            normalizedPath.startsWith("meta-inf/js-native/") || normalizedPath.startsWith("meta-inf/native-src/") ||
            (normalizedPath.startsWith("meta-inf/jsrt/") &&
                !normalizedPath.startsWith("meta-inf/jsrt/windows-x64/") &&
                !normalizedPath.startsWith("meta-inf/jsrt/linux-x64/")) ||
            !hasCurrentR1ResourceSuffix(normalizedPath)) {
            return false;
        }
        String tail = resourcePath.substring(AKEN_NATIVE_RESOURCE_ROOT.length());
        String[] segments = tail.split("/", -1);
        if (segments.length == 0 || isRetiredR1PathSegment(segments[0])) return false;
        for (String segment : segments) {
            if (segment.length() == 0 || ".".equals(segment) || "..".equals(segment) ||
                isRetiredR1PathSegment(segment)) return false;
            for (int index = 0; index < segment.length(); index++) {
                char character = segment.charAt(index);
                if (!((character >= 'a' && character <= 'z') ||
                    (character >= 'A' && character <= 'Z') ||
                    (character >= '0' && character <= '9') ||
                    character == '.' || character == '_' || character == '-')) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean isRetiredR1PathSegment(String segment) {
        String lower = segment.toLowerCase(Locale.ROOT);
        return lower.equals("aken") || lower.equals(".aken") || lower.equals(".r") ||
            lower.equals("js-native") || lower.equals("native-src") ||
            lower.contains(new String(new char[] {'m', 'a', 'c', 'o', 's'})) ||
            lower.contains(new String(new char[] {'d', 'a', 'r', 'w', 'i', 'n'})) ||
            lower.contains(new String(new char[] {'m', 'a', 'c', 'h', 'o'})) ||
            lower.contains(new String(new char[] {'m', 'a', 'c', 'h', '-', 'o'})) ||
            lower.startsWith(new String(new char[] {'j', 's', '_', 'k', 'e', 'r', 'n', 'e', 'l', '_'})) ||
            lower.startsWith(new String(new char[] {'z', 'i', 'g'}));
    }

    private static boolean hasCurrentR1ResourceSuffix(String normalizedPath) {
        return normalizedPath.endsWith(".dll") || normalizedPath.endsWith(".so") ||
            normalizedPath.endsWith(".properties") || normalizedPath.endsWith(".xml") ||
            normalizedPath.endsWith(".json") || normalizedPath.endsWith(".yml") ||
            normalizedPath.endsWith(".cfg") || normalizedPath.endsWith(".conf") ||
            normalizedPath.endsWith(".ini") || normalizedPath.endsWith(".txt");
    }

    private static int readAkenLocatorU16(byte[] bytes, int offset, int limit) {
        if (bytes == null || offset < 0 || limit < 0 || offset > limit - 2 || limit > bytes.length) {
            throw new SecurityException("AKEN native locator u16 is truncated");
        }
        return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
    }

    private static int readAkenLocatorPositiveU32(byte[] bytes, int offset, int limit) {
        if (bytes == null || offset < 0 || limit < 0 || offset > limit - 4 || limit > bytes.length) {
            throw new SecurityException("AKEN native locator u32 is truncated");
        }
        long value = ((long) (bytes[offset] & 0xFF) << 24) |
            ((long) (bytes[offset + 1] & 0xFF) << 16) |
            ((long) (bytes[offset + 2] & 0xFF) << 8) |
            (long) (bytes[offset + 3] & 0xFF);
        if (value <= 0L || value > Integer.MAX_VALUE) {
            throw new SecurityException("AKEN native locator length is invalid");
        }
        return (int) value;
    }

    private static byte[] akenNativeLocatorCommitment(byte[] payload, int payloadLength) {
        byte[] domain = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            domain = AKEN_NATIVE_LOCATOR_COMMITMENT_DOMAIN.getBytes(StandardCharsets.US_ASCII);
            digest.update(domain);
            digest.update(payload, 0, payloadLength);
            return digest.digest();
        } catch (Exception error) {
            throw new SecurityException("AKEN native locator commitment is unavailable", error);
        } finally {
            if (domain != null) Arrays.fill(domain, (byte) 0);
        }
    }

    private static byte[] unmaskAkenNativeLocatorRoute(
        byte[] masked,
        int kind,
        int platformId,
        int storedLength,
        byte[] digestBytes
    ) {
        byte[] route = masked.clone();
        int offset = 0;
        int blockIndex = 0;
        byte[] domain = null;
        try {
            domain = AKEN_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN.getBytes(StandardCharsets.US_ASCII);
            while (offset < route.length) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(domain);
                digest.update((byte) kind);
                digest.update((byte) platformId);
                updateAkenLocatorInt(digest, storedLength);
                digest.update(digestBytes);
                updateAkenLocatorInt(digest, blockIndex++);
                byte[] block = digest.digest();
                try {
                    int count = Math.min(block.length, route.length - offset);
                    for (int index = 0; index < count; index++) {
                        route[offset + index] = (byte) (route[offset + index] ^ block[index]);
                    }
                    offset += count;
                } finally {
                    Arrays.fill(block, (byte) 0);
                }
            }
            return route;
        } catch (Exception error) {
            Arrays.fill(route, (byte) 0);
            throw new SecurityException("AKEN native locator route mask is unavailable", error);
        } finally {
            if (domain != null) Arrays.fill(domain, (byte) 0);
        }
    }

    private static void updateAkenLocatorInt(MessageDigest digest, int value) {
        digest.update((byte) (value >>> 24));
        digest.update((byte) (value >>> 16));
        digest.update((byte) (value >>> 8));
        digest.update((byte) value);
    }

    private static boolean isAkenNativeRouteBytes(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return false;
        for (byte value : bytes) {
            int unsigned = value & 0xFF;
            if (unsigned == 0 || unsigned > 0x7F) return false;
        }
        return true;
    }

    private static boolean isAscii(byte[] bytes) {
        for (byte value : bytes) if ((value & 0x80) != 0) return false;
        return true;
    }

    private static boolean hasAkenRejectedLegacyHeader(byte[] bytes) {
        return hasAkenHeader(bytes, 'J', 'S', 'R', 'P') ||
            hasAkenHeader(bytes, 'J', 'S', 'B', 'I') ||
            hasAkenHeader(bytes, 'J', 'S', 'B', 'M') ||
            hasAkenHeader(bytes, 'J', 'S', 'B', 'K');
    }

    private static boolean hasAkenHeader(byte[] bytes, char first, char second, char third, char fourth) {
        return bytes != null && bytes.length >= 4 &&
            (bytes[0] & 0xFF) == first &&
            (bytes[1] & 0xFF) == second &&
            (bytes[2] & 0xFF) == third &&
            (bytes[3] & 0xFF) == fourth;
    }

    /* Retained Java entrypoints fail closed; R1 exposes no generic resource ABI. */
    public static Object executeVmResource(long entryToken, String resourcePath, Object[] args) {
        throw new SecurityException("generic VM resource execution is not part of the R1 runtime");
    }

    public static Object executeVmResource(long entryToken, Object[] args) {
        throw new SecurityException("generic VM resource execution is not part of the R1 runtime");
    }

    public static void executeVmResourceVoid(long entryToken) {
        throw new SecurityException("generic VM resource execution is not part of the R1 runtime");
    }

    public static int executeVmResourceInt(long entryToken) {
        throw new SecurityException("generic VM resource execution is not part of the R1 runtime");
    }

    public static int executeVmResourceIntInt(long entryToken, int arg0) {
        throw new SecurityException("generic VM resource execution is not part of the R1 runtime");
    }

    public static void executeVmResourceIntVoid(long entryToken, int arg0) {
        throw new SecurityException("generic VM resource execution is not part of the R1 runtime");
    }

    public static Runnable createRunnableLambda(String owner, String name, String descriptor, int implTag, Object[] captured) {
        return (Runnable) createSamLambda("run", "()Ljava/lang/Runnable;", owner, name, descriptor, implTag, "()V", "()V", "0;;", captured);
    }

    public static Object createSamLambda(
        String samName,
        String factoryDescriptor,
        String owner,
        String name,
        String descriptor,
        int implTag,
        String samDescriptor,
        String instantiatedDescriptor,
        String encodedOptions,
        Object[] captured
    ) {
        final Object[] capturedArgs = captured == null ? new Object[0] : Arrays.copyOf(captured, captured.length);
        final MethodHandle linkedTarget = resolveSamLambdaTarget(owner, name, descriptor, implTag);
        String samOwner = descriptorReturnInternalName(factoryDescriptor);
        try {
            ClassLoader loader = JniMicrokernelHelper.class.getClassLoader();
            Class<?> samInterface = Class.forName(samOwner.replace('/', '.'), false, loader);
            MethodType samType = MethodType.fromMethodDescriptorString(samDescriptor, loader);
            MethodType instantiatedType = MethodType.fromMethodDescriptorString(instantiatedDescriptor, loader);
            SamLambdaOptions options = parseSamLambdaOptions(encodedOptions, loader, samType);
            if (!samInterface.isInterface() || samName.length() == 0 || samType.parameterCount() != instantiatedType.parameterCount()) {
                throw new IllegalArgumentException("invalid virtualized SAM recipe");
            }
            if ((options.flags & LAMBDA_FLAG_SERIALIZABLE) == 0) {
                return createNonSerializableSamLambda(
                    samName,
                    factoryDescriptor,
                    owner,
                    linkedTarget,
                    samType,
                    instantiatedType,
                    options,
                    capturedArgs
                );
            }
            MethodHandle handle = adaptSamLambdaTarget(linkedTarget, capturedArgs, instantiatedType);
            return createSamProxy(
                samInterface,
                samName,
                handle,
                options,
                owner,
                name,
                descriptor,
                implTag,
                instantiatedDescriptor,
                capturedArgs
            );
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot create virtualized SAM lambda", e);
        }
    }

    private static Object createNonSerializableSamLambda(
        String samName,
        String factoryDescriptor,
        String owner,
        MethodHandle linkedTarget,
        MethodType samType,
        MethodType instantiatedType,
        SamLambdaOptions options,
        Object[] captured
    ) throws ReflectiveOperationException {
        ClassLoader loader = JniMicrokernelHelper.class.getClassLoader();
        Class<?> ownerClass = Class.forName(owner.replace('/', '.'), false, loader);
        MethodHandles.Lookup caller;
        try {
            caller = privateLookup(ownerClass);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            caller = MethodHandles.lookup();
        }
        MethodType factoryType = MethodType.fromMethodDescriptorString(factoryDescriptor, loader);
        CallSite site;
        try {
            if (options.flags == 0) {
                site = LambdaMetafactory.metafactory(
                    caller,
                    samName,
                    factoryType,
                    samType,
                    linkedTarget,
                    instantiatedType
                );
            } else {
                List<Object> arguments = new ArrayList<>();
                arguments.add(samType);
                arguments.add(linkedTarget);
                arguments.add(instantiatedType);
                arguments.add(Integer.valueOf(options.flags));
                if ((options.flags & LAMBDA_FLAG_MARKERS) != 0) {
                    arguments.add(Integer.valueOf(options.markerInterfaces.length));
                    arguments.addAll(Arrays.asList(options.markerInterfaces));
                }
                if ((options.flags & LAMBDA_FLAG_BRIDGES) != 0) {
                    arguments.add(Integer.valueOf(options.bridgeDescriptors.length));
                    for (String bridgeDescriptor : options.bridgeDescriptors) {
                        arguments.add(MethodType.fromMethodDescriptorString(bridgeDescriptor, loader));
                    }
                }
                site = LambdaMetafactory.altMetafactory(caller, samName, factoryType, arguments.toArray());
            }
        } catch (java.lang.invoke.LambdaConversionException error) {
            throw new ReflectiveOperationException("cannot link virtualized SAM lambda", error);
        }
        try {
            return site.getTarget().invokeWithArguments(captured);
        } catch (RuntimeException | Error error) {
            throw error;
        } catch (Throwable error) {
            throw new ReflectiveOperationException("cannot instantiate virtualized SAM lambda", error);
        }
    }

    private static MethodHandle resolveSamLambdaTarget(String owner, String name, String descriptor, int implTag) {
        String key = owner + '\u0000' + name + '\u0000' + descriptor + '\u0000' + implTag;
        MethodHandle cached = SAM_LAMBDA_CACHE.get(key);
        if (cached != null) return cached;
        try {
            ClassLoader loader = JniMicrokernelHelper.class.getClassLoader();
            Class<?> ownerClass = Class.forName(owner.replace('/', '.'), false, loader);
            String resolvedName = resolveBoundMethodName(owner, name, descriptor);
            MethodType methodType = descriptorMethodType(descriptor, ownerClass.getClassLoader());
            MethodHandle linked = resolveMethodHandle(ownerClass, resolvedName, methodType, implTag);
            if (linked == null) throw new IllegalArgumentException("unsupported lambda implementation handle tag: " + implTag);
            MethodHandle existing = SAM_LAMBDA_CACHE.putIfAbsent(key, linked);
            return existing == null ? linked : existing;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot link virtualized SAM lambda", e);
        }
    }

    private static Object invokeSamLambdaTarget(MethodHandle linkedTarget, Object[] captured, Object[] callArgs) throws Throwable {
        int available = captured.length + callArgs.length;
        if (available != linkedTarget.type().parameterCount()) {
            throw new IllegalStateException("lambda argument count mismatch");
        }
        Object[] args = new Object[available];
        System.arraycopy(captured, 0, args, 0, captured.length);
        System.arraycopy(callArgs, 0, args, captured.length, callArgs.length);
        return linkedTarget.invokeWithArguments(args);
    }

    private static MethodHandle adaptSamLambdaTarget(MethodHandle linkedTarget, Object[] captured, MethodType instantiatedType)
        throws ReflectiveOperationException {
        MethodHandle handle = MethodHandles.lookup().findStatic(
            JniMicrokernelHelper.class,
            "invokeSamLambdaTarget",
            MethodType.methodType(Object.class, MethodHandle.class, Object[].class, Object[].class)
        );
        handle = MethodHandles.insertArguments(handle, 0, linkedTarget, captured);
        return handle.asCollector(Object[].class, instantiatedType.parameterCount()).asType(instantiatedType);
    }

    private static Object createSamProxy(
        final Class<?> samInterface,
        final String samName,
        final MethodHandle target,
        final SamLambdaOptions options,
        final String owner,
        final String name,
        final String descriptor,
        final int implTag,
        final String instantiatedDescriptor,
        final Object[] captured
    ) throws ReflectiveOperationException {
        LinkedHashSet<Class<?>> interfaces = new LinkedHashSet<>();
        interfaces.add(samInterface);
        interfaces.addAll(Arrays.asList(options.markerInterfaces));
        if ((options.flags & LAMBDA_FLAG_SERIALIZABLE) != 0) interfaces.add(Serializable.class);
        if (options.bridgeDescriptors.length != 0) {
            interfaces.add(samBridgeInterface(samName, options.bridgeDescriptors));
        }
        return Proxy.newProxyInstance(
            JniMicrokernelHelper.class.getClassLoader(),
            interfaces.toArray(new Class<?>[0]),
            new SamInvocationHandler(
                samInterface.getName(), samName, owner, name, descriptor, implTag,
                instantiatedDescriptor, captured, target
            )
        );
    }

    private static SamLambdaOptions parseSamLambdaOptions(String encoded, ClassLoader loader, MethodType samType)
        throws ClassNotFoundException {
        String[] sections = encoded == null ? new String[0] : encoded.split(";", -1);
        if (sections.length != 3) throw new IllegalArgumentException("invalid virtualized SAM options");
        int flags;
        try {
            flags = Integer.parseInt(sections[0], 16);
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException("invalid virtualized SAM flags", error);
        }
        if (flags < 0 || (flags & ~LAMBDA_SUPPORTED_FLAGS) != 0) {
            throw new IllegalArgumentException("unsupported virtualized SAM flags");
        }
        String[] markerDescriptors = splitSamOptionList(sections[1]);
        String[] bridgeDescriptors = splitSamOptionList(sections[2]);
        if ((flags & LAMBDA_FLAG_MARKERS) == 0 && markerDescriptors.length != 0) {
            throw new IllegalArgumentException("unexpected virtualized SAM markers");
        }
        if ((flags & LAMBDA_FLAG_BRIDGES) == 0 && bridgeDescriptors.length != 0) {
            throw new IllegalArgumentException("unexpected virtualized SAM bridges");
        }
        Class<?>[] markerInterfaces = new Class<?>[markerDescriptors.length];
        for (int index = 0; index < markerDescriptors.length; index++) {
            String descriptor = decodeSamOptionDescriptor(markerDescriptors[index]);
            TypeParseResult parsed = parseDescriptorType(descriptor, 0, loader);
            if (parsed.nextIndex != descriptor.length() || !parsed.type.isInterface()) {
                throw new IllegalArgumentException("invalid virtualized SAM marker interface");
            }
            markerInterfaces[index] = parsed.type;
        }
        String[] decodedBridgeDescriptors = new String[bridgeDescriptors.length];
        for (int index = 0; index < bridgeDescriptors.length; index++) {
            String descriptor = decodeSamOptionDescriptor(bridgeDescriptors[index]);
            MethodType bridgeType = MethodType.fromMethodDescriptorString(descriptor, loader);
            if (bridgeType.parameterCount() != samType.parameterCount()) {
                throw new IllegalArgumentException("invalid virtualized SAM bridge descriptor");
            }
            decodedBridgeDescriptors[index] = descriptor;
        }
        return new SamLambdaOptions(flags, markerInterfaces, decodedBridgeDescriptors);
    }

    private static String[] splitSamOptionList(String encoded) {
        return encoded == null || encoded.length() == 0 ? new String[0] : encoded.split(",", -1);
    }

    private static String decodeSamOptionDescriptor(String encoded) {
        byte[] bytes = Base64.getUrlDecoder().decode(encoded);
        try {
            return new String(bytes, StandardCharsets.US_ASCII);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }

    private static Class<?> samBridgeInterface(String samName, String[] bridgeDescriptors)
        throws ReflectiveOperationException {
        LinkedHashSet<String> uniqueDescriptors = new LinkedHashSet<>(Arrays.asList(bridgeDescriptors));
        StringBuilder cacheKeyBuilder = new StringBuilder(samName.length() + uniqueDescriptors.size() * 24);
        cacheKeyBuilder.append(samName.length()).append(':').append(samName);
        for (String bridgeDescriptor : uniqueDescriptors) {
            cacheKeyBuilder.append('|').append(bridgeDescriptor.length()).append(':').append(bridgeDescriptor);
        }
        String cacheKey = cacheKeyBuilder.toString();
        Class<?> cached = SAM_BRIDGE_INTERFACE_CACHE.get(cacheKey);
        if (cached != null) return cached;
        synchronized (SAM_BRIDGE_INTERFACE_CACHE) {
            cached = SAM_BRIDGE_INTERFACE_CACHE.get(cacheKey);
            if (cached != null) return cached;
            byte[] nameDigest = sha256(cacheKey.getBytes(StandardCharsets.UTF_8));
            StringBuilder simpleName = new StringBuilder("$B$");
            try {
                for (int index = 0; index < 12; index++) {
                    int value = nameDigest[index] & 0xFF;
                    simpleName.append(Character.forDigit(value >>> 4, 16));
                    simpleName.append(Character.forDigit(value & 0x0F, 16));
                }
            } finally {
                Arrays.fill(nameDigest, (byte) 0);
            }
            String helperName = JniMicrokernelHelper.class.getName();
            int packageEnd = helperName.lastIndexOf('.');
            String binaryName = packageEnd < 0
                ? simpleName.toString()
                : helperName.substring(0, packageEnd + 1) + simpleName;
            byte[] classBytes = buildSamBridgeInterfaceBytes(
                binaryName.replace('.', '/'),
                samName,
                uniqueDescriptors.toArray(new String[0])
            );
            Class<?> generated = defineSamBridgeInterface(binaryName, classBytes);
            SAM_BRIDGE_INTERFACE_CACHE.put(cacheKey, generated);
            return generated;
        }
    }

    private static byte[] buildSamBridgeInterfaceBytes(
        String internalName,
        String samName,
        String[] bridgeDescriptors
    ) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            DataOutputStream output = new DataOutputStream(bytes);
            output.writeInt(0xCAFEBABE);
            output.writeShort(0);
            output.writeShort(52);
            output.writeShort(bridgeDescriptors.length + 9);
            writeSamBridgeUtf8(output, internalName);       // #1
            output.writeByte(7); output.writeShort(1);     // #2 this class
            writeSamBridgeUtf8(output, "java/lang/Object"); // #3
            output.writeByte(7); output.writeShort(3);     // #4 Object
            writeSamBridgeUtf8(output, samName);            // #5 method name
            writeSamBridgeUtf8(output, "Exceptions");      // #6
            writeSamBridgeUtf8(output, "java/lang/Throwable"); // #7
            output.writeByte(7); output.writeShort(7);     // #8 Throwable
            for (String bridgeDescriptor : bridgeDescriptors) {
                writeSamBridgeUtf8(output, bridgeDescriptor);
            }

            output.writeShort(0x1601); // public abstract synthetic interface
            output.writeShort(2);
            output.writeShort(4);
            output.writeShort(0);
            output.writeShort(0);
            output.writeShort(bridgeDescriptors.length);
            for (int index = 0; index < bridgeDescriptors.length; index++) {
                output.writeShort(0x1441); // public abstract bridge synthetic
                output.writeShort(5);
                output.writeShort(9 + index);
                output.writeShort(1);
                output.writeShort(6);
                output.writeInt(4);
                output.writeShort(1);
                output.writeShort(8);
            }
            output.writeShort(0);
            output.flush();
            return bytes.toByteArray();
        } catch (IOException error) {
            throw new IllegalStateException("cannot encode virtualized SAM bridge interface", error);
        }
    }

    private static void writeSamBridgeUtf8(DataOutputStream output, String value) throws IOException {
        output.writeByte(1);
        output.writeUTF(value);
    }

    private static Class<?> defineSamBridgeInterface(String binaryName, byte[] classBytes)
        throws ReflectiveOperationException {
        try {
            Method defineClass = MethodHandles.Lookup.class.getMethod("defineClass", byte[].class);
            return (Class<?>) defineClass.invoke(MethodHandles.lookup(), new Object[] { classBytes });
        } catch (NoSuchMethodException ignored) {
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            java.lang.reflect.Field unsafeField = unsafeClass.getDeclaredField("theUnsafe");
            unsafeField.setAccessible(true);
            Object unsafe = unsafeField.get(null);
            Method defineClass = unsafeClass.getDeclaredMethod(
                "defineClass",
                String.class,
                byte[].class,
                int.class,
                int.class,
                ClassLoader.class,
                java.security.ProtectionDomain.class
            );
            return (Class<?>) defineClass.invoke(
                unsafe,
                binaryName,
                classBytes,
                Integer.valueOf(0),
                Integer.valueOf(classBytes.length),
                JniMicrokernelHelper.class.getClassLoader(),
                JniMicrokernelHelper.class.getProtectionDomain()
            );
        }
    }

    private static final class SamLambdaOptions {
        final int flags;
        final Class<?>[] markerInterfaces;
        final String[] bridgeDescriptors;

        SamLambdaOptions(int flags, Class<?>[] markerInterfaces, String[] bridgeDescriptors) {
            this.flags = flags;
            this.markerInterfaces = Arrays.copyOf(markerInterfaces, markerInterfaces.length);
            this.bridgeDescriptors = Arrays.copyOf(bridgeDescriptors, bridgeDescriptors.length);
        }
    }

    private static final class SamInvocationHandler implements InvocationHandler, Serializable {
        private static final long serialVersionUID = 1L;

        private final String samInterfaceName;
        private final String samName;
        private final String owner;
        private final String name;
        private final String descriptor;
        private final int implTag;
        private final String instantiatedDescriptor;
        private final Object[] captured;
        private transient MethodHandle target;

        SamInvocationHandler(
            String samInterfaceName,
            String samName,
            String owner,
            String name,
            String descriptor,
            int implTag,
            String instantiatedDescriptor,
            Object[] captured,
            MethodHandle target
        ) {
            this.samInterfaceName = samInterfaceName;
            this.samName = samName;
            this.owner = owner;
            this.name = name;
            this.descriptor = descriptor;
            this.implTag = implTag;
            this.instantiatedDescriptor = instantiatedDescriptor;
            this.captured = Arrays.copyOf(captured, captured.length);
            this.target = target;
        }

        @Override
        public Object invoke(Object proxy, java.lang.reflect.Method method, Object[] arguments) throws Throwable {
            Object[] args = arguments == null ? new Object[0] : arguments;
            if (method.getDeclaringClass() == Object.class) {
                if ("equals".equals(method.getName())) return Boolean.valueOf(args.length == 1 && proxy == args[0]);
                if ("hashCode".equals(method.getName())) return Integer.valueOf(System.identityHashCode(proxy));
                if ("toString".equals(method.getName())) return samInterfaceName + "@" + Integer.toHexString(System.identityHashCode(proxy));
            }
            if (method.isDefault()) {
                MethodHandle defaultHandle = privateLookup(method.getDeclaringClass())
                    .unreflectSpecial(method, method.getDeclaringClass())
                    .bindTo(proxy);
                return defaultHandle.invokeWithArguments(args);
            }
            if (!samName.equals(method.getName())) throw new AbstractMethodError(method.toString());
            MethodType invocationType = MethodType.methodType(method.getReturnType(), method.getParameterTypes());
            return target().asType(invocationType).invokeWithArguments(args);
        }

        private MethodHandle target() throws ReflectiveOperationException {
            if (target != null) return target;
            ClassLoader loader = JniMicrokernelHelper.class.getClassLoader();
            MethodHandle linked = resolveSamLambdaTarget(owner, name, descriptor, implTag);
            MethodType instantiatedType = MethodType.fromMethodDescriptorString(instantiatedDescriptor, loader);
            target = adaptSamLambdaTarget(linked, captured, instantiatedType);
            return target;
        }

        private void readObject(ObjectInputStream input) throws IOException, ClassNotFoundException {
            input.defaultReadObject();
            try {
                target = target();
            } catch (ReflectiveOperationException | RuntimeException error) {
                InvalidObjectException invalid = new InvalidObjectException("cannot relink virtualized SAM lambda");
                invalid.initCause(error);
                throw invalid;
            }
        }
    }

    public static MethodHandle resolveVmMethodHandle(String encoded) {
        try {
            String[] parts = encoded == null ? null : encoded.split("\\|", -1);
            if (parts == null || parts.length != 5 || !"handle".equals(parts[0])) return null;
            int tag = Integer.parseInt(parts[1]);
            String owner = parts[2];
            String name = resolveBoundMethodName(owner, parts[3], parts[4]);
            String descriptor = parts[4];
            ClassLoader loader = JniMicrokernelHelper.class.getClassLoader();
            Class<?> ownerClass = Class.forName(owner.replace('/', '.'), false, loader);
            MethodType methodType = descriptorMethodType(descriptor, ownerClass.getClassLoader());
            return resolveMethodHandle(ownerClass, name, methodType, tag);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static MethodHandle resolveMethodHandle(
        Class<?> ownerClass,
        String name,
        MethodType methodType,
        int tag
    ) throws ReflectiveOperationException {
        MethodHandles.Lookup lookup;
        try {
            lookup = privateLookup(ownerClass);
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            lookup = MethodHandles.publicLookup();
        }
        switch (tag) {
            case 5: return lookup.findVirtual(ownerClass, name, methodType);
            case 6: return lookup.findStatic(ownerClass, name, methodType);
            case 7: return lookup.findSpecial(ownerClass, name, methodType, ownerClass);
            case 8:
                if (!"<init>".equals(name) || methodType.returnType() != void.class) return null;
                return lookup.findConstructor(ownerClass, methodType);
            case 9: return lookup.findVirtual(ownerClass, name, methodType);
            default: return null;
        }
    }

    private static MethodHandles.Lookup privateLookup(Class<?> ownerClass) throws ReflectiveOperationException {
        try {
            Method privateLookupIn = MethodHandles.class.getMethod(
                "privateLookupIn",
                Class.class,
                MethodHandles.Lookup.class
            );
            return (MethodHandles.Lookup) privateLookupIn.invoke(null, ownerClass, MethodHandles.lookup());
        } catch (NoSuchMethodException ignored) {
            java.lang.reflect.Constructor<MethodHandles.Lookup> constructor =
                MethodHandles.Lookup.class.getDeclaredConstructor(Class.class);
            constructor.setAccessible(true);
            return constructor.newInstance(ownerClass);
        }
    }

    private static String descriptorReturnInternalName(String descriptor) {
        int close = descriptor.indexOf(')');
        if (descriptor.length() <= close + 2 || descriptor.charAt(close + 1) != 'L') {
            throw new IllegalArgumentException("invalid SAM factory descriptor");
        }
        int end = descriptor.indexOf(';', close + 2);
        if (end < 0) throw new IllegalArgumentException("invalid SAM factory descriptor");
        return descriptor.substring(close + 2, end);
    }

    private static MethodType descriptorMethodType(String descriptor, ClassLoader loader) throws ClassNotFoundException {
        int close = descriptor.indexOf(')');
        if (descriptor.length() <= close + 1) throw new IllegalArgumentException("invalid method descriptor");
        Class<?>[] parameterTypes = descriptorParameterTypes(descriptor, loader);
        if (descriptor.charAt(close + 1) == 'V') {
            if (descriptor.length() != close + 2) throw new IllegalArgumentException("invalid method descriptor");
            return MethodType.methodType(void.class, parameterTypes);
        }
        TypeParseResult returnType = parseDescriptorType(descriptor, close + 1, loader);
        return MethodType.methodType(returnType.type, parameterTypes);
    }
    private static String resolveBoundMethodName(String owner, String name, String descriptor) {
        String bindings = System.getProperty(sealedMethodBindingPropertyName());
        if (bindings == null || bindings.length() == 0) return name;
        String key = sealedBindingKey(owner + "#" + name + "#" + descriptor) + "=";
        String[] lines = bindings.split("\\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.startsWith(key)) {
                String mapped = trimmed.substring(key.length());
                if (mapped.length() > 0) return mapped;
            }
        }
        return name;
    }
    private static Class<?>[] descriptorParameterTypes(String descriptor, ClassLoader loader) throws ClassNotFoundException {
        int open = descriptor.indexOf('(');
        int close = descriptor.indexOf(')', open + 1);
        if (open != 0 || close < 0) throw new IllegalArgumentException("invalid method descriptor");
        java.util.ArrayList<Class<?>> types = new java.util.ArrayList<>();
        int index = open + 1;
        while (index < close) {
            TypeParseResult parsed = parseDescriptorType(descriptor, index, loader);
            types.add(parsed.type);
            index = parsed.nextIndex;
        }
        return types.toArray(new Class<?>[0]);
    }

    private static TypeParseResult parseDescriptorType(String descriptor, int index, ClassLoader loader) throws ClassNotFoundException {
        char tag = descriptor.charAt(index);
        switch (tag) {
            case 'Z': return new TypeParseResult(boolean.class, index + 1);
            case 'B': return new TypeParseResult(byte.class, index + 1);
            case 'C': return new TypeParseResult(char.class, index + 1);
            case 'S': return new TypeParseResult(short.class, index + 1);
            case 'I': return new TypeParseResult(int.class, index + 1);
            case 'J': return new TypeParseResult(long.class, index + 1);
            case 'F': return new TypeParseResult(float.class, index + 1);
            case 'D': return new TypeParseResult(double.class, index + 1);
            case 'L': {
                int end = descriptor.indexOf(';', index);
                if (end < 0) throw new IllegalArgumentException("invalid object descriptor");
                String className = descriptor.substring(index + 1, end).replace('/', '.');
                return new TypeParseResult(Class.forName(className, false, loader), end + 1);
            }
            case '[': {
                int end = index;
                while (descriptor.charAt(end) == '[') end++;
                if (descriptor.charAt(end) == 'L') {
                    end = descriptor.indexOf(';', end);
                    if (end < 0) throw new IllegalArgumentException("invalid array descriptor");
                }
                String arrayDescriptor = descriptor.substring(index, end + 1).replace('/', '.');
                return new TypeParseResult(Class.forName(arrayDescriptor, false, loader), end + 1);
            }
            default:
                throw new IllegalArgumentException("unsupported descriptor tag " + tag);
        }
    }

    private static final class TypeParseResult {
        final Class<?> type;
        final int nextIndex;
        TypeParseResult(Class<?> type, int nextIndex) {
            this.type = type;
            this.nextIndex = nextIndex;
        }
    }

    /* ---- Public status API ---- */

    public static String getLoadStatus() {
        return loadState == LOAD_UNTRIED && (loadMessage == null || loadMessage.length() == 0) ? "untried" : loadMessage;
    }

    public static boolean isNativeLoaded() {
        return loadState == LOAD_READY || akenLoadState == LOAD_READY;
    }

    /* ---- Kernel loading ---- */

    public static void loadKernel(String kernelComponents, String targetPlatform) {
        loadKernel(kernelComponents, targetPlatform, "vm-off");
    }

    public static synchronized void loadKernel(String kernelComponents, String targetPlatform, String vmMode) {
        diversifiedVmEnabled = "vm-diverse".equals(vmMode);
        if (isNativeLoaded()) {
            runDiversifiedVmSelfExercise();
            return;
        }
        if (loadState == LOAD_LOADING || akenLoadState == LOAD_LOADING) return;
        loadState = LOAD_LOADING;
        try {
            String platformTarget = detectPlatform();
            if (platformTarget == null) {
                loadMessage = "native-unavailable";
                loadState = LOAD_FAILED;
                runDiversifiedVmSelfExercise();
                return;
            }
            if (!targetPlatformAllowsCurrent(targetPlatform, platformTarget)) {
                loadMessage = "native-platform-not-requested:" + platformTarget;
                loadState = LOAD_FAILED;
                return;
            }
            loadAkenNativeKernel();
            if (akenLoadState == LOAD_READY) {
                loadState = LOAD_UNTRIED;
                loadMessage = "";
                runDiversifiedVmSelfExercise();
                return;
            }
            loadMessage = akenLoadMessage == null || akenLoadMessage.length() == 0
                ? "aken:bundled-native-unavailable"
                : akenLoadMessage;
            loadState = LOAD_FAILED;
            runDiversifiedVmSelfExercise();
        } catch (Throwable e) {
            loadMessage = debugNativeLoadMessage("aken:native-exception", e);
            loadState = LOAD_FAILED;
        }
    }

    private static boolean targetPlatformAllowsCurrent(String targetPlatform, String platformTarget) {
        if (targetPlatform == null || platformTarget == null) return false;
        String requested = targetPlatform.trim();
        if ("auto".equalsIgnoreCase(requested) || "all".equalsIgnoreCase(requested)) return true;
        String[] platforms = requested.split(",", -1);
        for (String platform : platforms) {
            String candidate = platform.trim();
            if (platformTarget.equals(candidate) ||
                ("windows-x64".equalsIgnoreCase(candidate) && "x86_64-pc-windows-gnu".equals(platformTarget)) ||
                ("linux-x64".equalsIgnoreCase(candidate) && "x86_64-unknown-linux-gnu.2.17".equals(platformTarget))) {
                return true;
            }
        }
        return false;
    }

    /** Whether diversified virtualization was requested for this load. */
    public static boolean isDiversifiedVmEnabled() {
        return diversifiedVmEnabled;
    }

    /** True once the authenticated R1 image and all seven JNI entries are ready. */
    public static boolean isKernelIntegrityReady() {
        return akenLoadState == LOAD_READY && !nativeSelfCheckFailed;
    }

    /** Status string for the diversified-VM load-time self-exercise. */
    public static String getVmSelfCheck() {
        return vmSelfCheck;
    }

    /*
     * Diversified virtualization is native-only in VBC4 mode. The Java helper
     * records whether the mode was requested and relies on ABI/boot-token gates
     * after native load instead of running any Java VM fallback path.
     */
    private static void runDiversifiedVmSelfExercise() {
        if (!diversifiedVmEnabled) return;
        vmSelfCheck = isNativeLoaded() ? "native:vm-diverse:ok" : "native:vm-diverse:unavailable";
    }

    /** Require a ready authenticated R1 runtime. */
    public static void requireHealthyKernel() {
        if (!isKernelIntegrityReady() || (vmSelfCheck != null && vmSelfCheck.contains("mismatch"))) {
            throw new SecurityException("Kernel integrity mismatch");
        }
    }

    private static byte[] createVmStartupNonce() {
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static String sealedBindingKey(String value) {
        byte[] encoded = ("AKEN-BINDING-V1|" + value).getBytes(StandardCharsets.UTF_8);
        try {
            byte[] digest;
            try {
                digest = MessageDigest.getInstance("SHA-256").digest(encoded);
            } catch (NoSuchAlgorithmException e) {
                throw new SecurityException("public binding digest unavailable", e);
            }
            try {
                char[] hex = new char[16];
                for (int i = 0; i < 8; i++) {
                    int valueByte = digest[i] & 0xFF;
                    hex[i * 2] = Character.forDigit((valueByte >>> 4) & 0xF, 16);
                    hex[i * 2 + 1] = Character.forDigit(valueByte & 0xF, 16);
                }
                return new String(hex);
            } finally {
                Arrays.fill(digest, (byte) 0);
            }
        } finally {
            Arrays.fill(encoded, (byte) 0);
        }
    }

    /* ---- Locked R1 host targets ---- */
    private static String detectPlatform() {
        return detectPlatform(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
    }

    private static String detectPlatform(String osName, String osArch) {
        String normalizedOs = osName == null ? "" : osName.trim();
        String normalizedArch = osArch == null ? "" : osArch.trim();
        boolean x64 = "amd64".equalsIgnoreCase(normalizedArch) ||
            "x86_64".equalsIgnoreCase(normalizedArch) || "x64".equalsIgnoreCase(normalizedArch);
        if (!x64) return null;
        if (normalizedOs.equalsIgnoreCase("Windows") || normalizedOs.regionMatches(true, 0, "Windows ", 0, 8)) {
            return "x86_64-pc-windows-gnu";
        }
        if (normalizedOs.equalsIgnoreCase("Linux") || normalizedOs.regionMatches(true, 0, "Linux ", 0, 6)) {
            return "x86_64-unknown-linux-gnu.2.17";
        }
        return null;
    }

    private static String debugNativeLoadMessage(String prefix, Throwable e) {
        if (!Boolean.getBoolean("javashroud.debugNativeLoad")) return "native-unavailable";
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) root = root.getCause();
        String detail = prefix + ":" + e.getClass().getName() + ":" + String.valueOf(e.getMessage());
        if (root != e) detail += ":cause=" + root.getClass().getName() + ":" + String.valueOf(root.getMessage());
        return detail;
    }

    private static int initializeNativeKernel(String platformTarget) {
        return nativeInit(platformTarget);
    }

    private static void installAkenSessionNonce() {
        byte[] startupNonce = createVmStartupNonce();
        try {
            if (!nativeInstallAkenSessionNonce(startupNonce)) {
                throw new SecurityException("AKEN runtime session nonce installation failed");
            }
        } finally {
            Arrays.fill(startupNonce, (byte) 0);
        }
    }

    private static File[] nativeExtractDirectories() {
        LinkedHashSet<String> paths = new LinkedHashSet<>();
        addNativeExtractDirectory(paths, System.getProperty("javashroud.native.extract.dir", ""));
        String userHome = System.getProperty("user.home", "");
        if (userHome != null && userHome.length() > 0) {
            addNativeExtractDirectory(paths, new File(new File(userHome, ".javashroud"), "native"));
        }
        String userDir = System.getProperty("user.dir", "");
        if (userDir != null && userDir.length() > 0) {
            addNativeExtractDirectory(paths, new File(new File(userDir, ".javashroud-native"), "native"));
        }
        addNativeExtractDirectory(paths, System.getProperty("java.io.tmpdir", ""));
        File[] directories = new File[paths.size()];
        int index = 0;
        for (String path : paths) directories[index++] = new File(path);
        return directories;
    }

    private static void addNativeExtractDirectory(LinkedHashSet<String> paths, String path) {
        if (path == null) return;
        String trimmedPath = path.trim();
        if (trimmedPath.length() == 0) return;
        addNativeExtractDirectory(paths, new File(trimmedPath));
    }

    private static void addNativeExtractDirectory(LinkedHashSet<String> paths, File directory) {
        if (directory == null) return;
        try {
            paths.add(directory.getAbsoluteFile().getPath());
        } catch (SecurityException ignored) {
        }
    }

    private static boolean ensureNativeExtractDirectory(File directory) {
        try {
            if (directory == null) return false;
            if (directory.exists()) return directory.isDirectory() && directory.canWrite();
            return directory.mkdirs() && directory.isDirectory() && directory.canWrite();
        } catch (SecurityException e) {
            return false;
        }
    }

    private static String nativeTempPrefix(String resourcePath) {
        int hash = 0x811C9DC5;
        for (int i = 0; i < resourcePath.length(); i++) {
            hash ^= resourcePath.charAt(i) & 0xFF;
            hash *= 0x01000193;
        }
        String suffix = Integer.toUnsignedString(hash, 36);
        return ("n" + suffix + "xxxx").substring(0, 8);
    }
    private static InputStream resourceStream(String resourcePath) {
        InputStream in = JniMicrokernelHelper.class.getResourceAsStream("/" + resourcePath);
        if (in != null) return in;
        ClassLoader loader = JniMicrokernelHelper.class.getClassLoader();
        return loader == null ? null : loader.getResourceAsStream(resourcePath);
    }

    private static void publishSealedNativeBindings(String bindingText) {
        if (bindingText == null || bindingText.length() == 0) {
            throw new SecurityException("AKEN native bindings are unavailable");
        }
        try {
            publishSealedNativeLoaderOwner();
            StringBuilder bindings = new StringBuilder();
            StringBuilder methodBindings = new StringBuilder();
            StringBuilder fieldBindings = new StringBuilder();
            String[] lines = bindingText.split("\n");
            for (String line : lines) {
                String[] parts = line.trim().split("\\|", -1);
                if (parts.length != 3) {
                    throw new SecurityException("AKEN native bindings record is malformed");
                }
                if ("B".equals(parts[0])) {
                    if (bindings.length() > 0) bindings.append('\n');
                    bindings.append(parts[1]).append('=').append(parts[2]);
                } else if ("M".equals(parts[0])) {
                    if (methodBindings.length() > 0) methodBindings.append('\n');
                    methodBindings.append(parts[1]).append('=').append(parts[2]);
                } else if ("F".equals(parts[0])) {
                    if (fieldBindings.length() > 0) fieldBindings.append('\n');
                    fieldBindings.append(parts[1]).append('=').append(parts[2]);
                } else {
                    throw new SecurityException("AKEN native bindings record type is invalid");
                }
            }
            if (bindings.length() > 0) {
                System.setProperty(sealedBindingPropertyName(), mergeBindingProperties(System.getProperty(sealedBindingPropertyName()), bindings.toString()));
            }
            if (methodBindings.length() > 0) {
                System.setProperty(sealedMethodBindingPropertyName(), mergeBindingProperties(System.getProperty(sealedMethodBindingPropertyName()), methodBindings.toString()));
            }
            if (fieldBindings.length() > 0) {
                System.setProperty(sealedFieldBindingPropertyName(), mergeBindingProperties(System.getProperty(sealedFieldBindingPropertyName()), fieldBindings.toString()));
            }
        } catch (SecurityException error) {
            throw error;
        } catch (Throwable error) {
            throw new SecurityException("AKEN native bindings are unavailable", error);
        }
    }

    private static void publishSealedNativeLoaderOwner() {
        System.setProperty(sealedLoaderPropertyName(), JniMicrokernelHelper.class.getName().replace('.', '/'));
    }

    private static void restoreLoaderProperty(String previous) {
        restoreProperty(sealedLoaderPropertyName(), previous);
    }

    private static void restoreProperty(String name, String previous) {
        try {
            if (previous == null) {
                System.clearProperty(name);
            } else {
                System.setProperty(name, previous);
            }
        } catch (Throwable ignored) {
        }
    }

    private static String mergeBindingProperties(String existing, String additions) {
        if (existing == null || existing.length() == 0) return additions;
        if (additions == null || additions.length() == 0) return existing;
        java.util.LinkedHashMap<String, String> merged = new java.util.LinkedHashMap<>();
        appendBindingProperties(merged, existing);
        appendBindingProperties(merged, additions);
        StringBuilder out = new StringBuilder();
        for (java.util.Map.Entry<String, String> entry : merged.entrySet()) {
            if (out.length() > 0) out.append('\n');
            out.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return out.toString();
    }

    private static void appendBindingProperties(java.util.LinkedHashMap<String, String> target, String text) {
        String[] lines = text.split("\n");
        for (String line : lines) {
            int separator = line.indexOf('=');
            if (separator <= 0) continue;
            target.put(line.substring(0, separator), line.substring(separator + 1));
        }
    }

    private static String sealedLoaderPropertyName() {
        return new String(new char[]{'j', '.', 'l'});
    }

    private static String sealedBindingPropertyName() {
        return new String(new char[]{'j', '.', 'b'});
    }

    private static String sealedMethodBindingPropertyName() {
        return new String(new char[]{'j', '.', 'm'});
    }

    private static String sealedFieldBindingPropertyName() {
        return new String(new char[]{'j', '.', 'f'});
    }

    private static String sealedNativeBindingText(AkenNativeLibrary locator) {
        String resourcePath = locator == null ? null : locator.bindingResourcePath;
        if (resourcePath == null || !isAkenNativeResourcePath(resourcePath)) {
            throw new SecurityException("AKEN native bindings resource path is unavailable");
        }
        try (InputStream in = resourceStream(resourcePath)) {
            if (in == null) return null;
            byte[] raw = readAllBounded(in, AKEN_NATIVE_BINDINGS_MAX_BYTES);
            try {
                if (locator != null) verifyAkenNativeBinding(locator, raw);
                if (raw.length == 0 || hasAkenRejectedLegacyHeader(raw) || !isAscii(raw)) {
                    throw new SecurityException("AKEN native bindings are not raw relocation metadata");
                }
                return new String(raw, StandardCharsets.UTF_8);
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        } catch (SecurityException error) {
            throw error;
        } catch (Exception error) {
            throw new SecurityException("AKEN native bindings are unavailable", error);
        }
    }

    private static void verifyAkenNativeBinding(AkenNativeLibrary locator, byte[] raw) {
        if (locator.bindingResourcePath == null ||
            !isAkenNativeResourcePath(locator.bindingResourcePath) ||
            locator.bindingSha256 == null || raw.length != locator.bindingStoredLength) {
            throw new SecurityException("AKEN native binding locator does not match the sealed resource");
        }
        byte[] actualDigest = sha256(raw);
        try {
            if (!MessageDigest.isEqual(locator.bindingSha256, actualDigest)) {
                throw new SecurityException("AKEN native binding digest mismatch");
            }
        } finally {
            Arrays.fill(actualDigest, (byte) 0);
        }
    }

    public static byte[] decodeRuntimeResourceForNative(byte[] raw) {
        throw new SecurityException("generic runtime-resource decoding is not part of the R1 runtime");
    }

    public static byte[] decodeRuntimeResourceEnvelope(byte[] raw) {
        throw new SecurityException("generic runtime-resource decoding is not part of the R1 runtime");
    }

    public static byte[] deriveClassEncryptionKey(byte[] keyId, byte[] salt, int length) {
        throw new SecurityException("class-encryption key derivation is not part of the R1 Java helper");
    }

    public static byte[] decryptClassBytes(byte[] keyId, byte[] salt, byte[] nonce, byte[] ciphertext, byte[] aad, int keyLength) {
        throw new SecurityException("class-encryption decryption is not part of the R1 Java helper");
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException error) {
            throw new SecurityException("SHA-256 is unavailable", error);
        }
    }

    private static File createUniqueTempFile(String prefix, String suffix, File dir) throws java.io.IOException {
        long seed = System.nanoTime();
        for (int attempt = 0; attempt < 100; attempt++) {
            File candidate = new File(dir, prefix + (seed + attempt) + suffix);
            if (candidate.createNewFile()) return candidate;
        }
        throw new java.io.IOException("cannot create unique temp file in " + dir);
    }

    private static byte[] readAllBounded(InputStream in, int maxBytes) throws IOException {
        if (in == null || maxBytes <= 0) throw new IOException("invalid bounded stream request");
        ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(maxBytes, 1024));
        byte[] buffer = new byte[1024];
        int total = 0;
        try {
            int read;
            while ((read = in.read(buffer)) >= 0) {
                if (read == 0) continue;
                if (read > maxBytes - total) throw new IOException("stream exceeds configured limit");
                out.write(buffer, 0, read);
                total += read;
            }
            return out.toByteArray();
        } finally {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    private static final class AkenNativeLibrary {
        final String resourcePath;
        final String fileSuffix;
        final int storedLength;
        final byte[] sha256;
        String bindingResourcePath;
        int bindingStoredLength;
        byte[] bindingSha256;

        AkenNativeLibrary(String resourcePath, String fileSuffix, int storedLength, byte[] sha256) {
            this.resourcePath = resourcePath;
            this.fileSuffix = fileSuffix;
            this.storedLength = storedLength;
            this.sha256 = sha256;
        }

        void clear() {
            Arrays.fill(sha256, (byte) 0);
            if (bindingSha256 != null) Arrays.fill(bindingSha256, (byte) 0);
            bindingResourcePath = null;
            bindingStoredLength = 0;
            bindingSha256 = null;
        }
    }

}
