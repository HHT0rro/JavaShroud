package io.github.hht0rro.javashroud.transforms.protection.qp;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.lang.invoke.CallSite;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Arrays;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Runtime helper for JNI microkernel loader.
 * Pure Java - no Kotlin runtime dependency.
 *
 * Attempts to load a bundled native kernel from the JAR resources.
 * In pure native-VM-only mode this helper is strictly fail-closed:
 * native bootstrap and load logic remain, and native ABI failures reject execution.
 */
public final class QpBridge {

    private static final int LOAD_FAILED = -1;
    private static final int LOAD_UNTRIED = 0;
    private static final int LOAD_LOADING = 1;
    private static final int LOAD_READY = 2;
    private static final int KERNEL_UNINITIALIZED = 0;
    private static final int KERNEL_BINDINGS_VERIFIED = 1;
    private static final int KERNEL_NATIVE_READY = 2;
    private static final int KERNEL_DEFENSE_READY = 3;
    private static final int KERNEL_SUSPECT = 4;
    private static final int KERNEL_TAMPERED = 5;
    private static final int KERNEL_FAILED = 6;
    private static volatile int kernelState = KERNEL_UNINITIALIZED;
    private static volatile boolean defenseRequired;
    private static volatile int loadState = LOAD_UNTRIED;
    private static volatile String loadMessage = "";
    private static volatile int nativeLoadState = LOAD_UNTRIED;
    private static volatile String nativeLoadMessage = "";
    private static volatile boolean diversifiedVmEnabled;
    /** Short platform key of the loaded native library; selects the sealed pack resource. */
    private static volatile String loadedNativePlatformKey;

    /** Maps a Rust target triple to the catalog pack platform key. */
    private static String shortPlatformKey(String platformTarget) {
        if (platformTarget == null) return "";
        if ("x86_64-pc-windows-gnu".equals(platformTarget)) return "windows-x64";
        if ("x86_64-unknown-linux-gnu.2.17".equals(platformTarget)) return "linux-x64";
        return platformTarget.trim();
    }
    /* 0 = not requested, 1 = native ready, 2 = native unavailable. */
    private static volatile int vmSelfCheckCode;
    private static volatile boolean nativeSelfCheckFailed;
    private static volatile boolean sealedNativeBindingsPublished;
    private static final String QP_NATIVE_LOCATOR_RESOURCE = "META-INF/jsrt/native.locator";
    private static final String QP_NATIVE_BINDINGS_LOCATOR_RESOURCE = "META-INF/jsrt/native.bindings.locator";
    private static final String QP_CATALOG_INDEX_RESOURCE = "META-INF/jsrt/catalog.index";
    private static final String QP_CATALOG_RESOURCE_ROOT = "META-INF/jsrt/catalog/";
    private static final String QP_NATIVE_RESOURCE_ROOT = "META-INF/";
    private static final int QP_NATIVE_LOCATOR_MAGIC_0 = 0xD7;
    private static final int QP_NATIVE_LOCATOR_MAGIC_1 = 0xA4;
    private static final int QP_NATIVE_LOCATOR_MAGIC_2 = 0x91;
    private static final int QP_NATIVE_LOCATOR_MAGIC_3 = 0xE3;
    private static final String QP_NATIVE_LOCATOR_COMMITMENT_DOMAIN =
        "javashroud-qp-native-locator-commitment-v2";
    private static final String QP_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN =
        "javashroud-qp-native-locator-route-mask-v2";
    private static final int QP_NATIVE_LOCATOR_VERSION = 2;
    private static final int QP_NATIVE_LOCATOR_HEADER_BYTES = 8;
    private static final int QP_NATIVE_LOCATOR_COMMITMENT_BYTES = 32;
    private static final int QP_NATIVE_LOCATOR_RECORD_FIXED_BYTES = 40;
    private static final int QP_NATIVE_LOCATOR_MAX_RECORDS = 3;
    private static final int QP_NATIVE_LOCATOR_MAX_ROUTE_BYTES = 2048;
    private static final int QP_NATIVE_LOCATOR_KIND_LIBRARY = 1;
    private static final int QP_NATIVE_LOCATOR_KIND_BINDINGS = 2;
    private static final int QP_NATIVE_LOCATOR_MAX_BYTES = 16 * 1024;
    private static final int QP_NATIVE_MAX_LIBRARY_BYTES = 256 * 1024 * 1024;
    private static final int QP_NATIVE_SHA256_LENGTH = 32;
    private static final int QP_NATIVE_BINDINGS_MAX_BYTES = 4 * 1024 * 1024;
    private QpBridge() { }

    /* ---- JNI current methods (implemented by the bundled Rust runtime) ---- */

    static native int nativeInit(String platform);
    static native int nativeHeartbeat();
    static native boolean nativeInstallSessionNonce(byte[] startupNonce);
    static native int nativeInstallCatalog(byte[] directory, byte[] bundle, byte[] pack);
    static native Object nativeExecuteVmPage(long entryToken, byte[] packedRequest, Object[] args);
    static native String nativeOpenStringPage(byte[] packedRequest);
    static native byte[] nativeReadClassPage(byte[] packedRequest);
    static native void nativeConsumeNativeSegment(byte[] packedRequest);
    public static native int nativeInitializeDefense(String surface, String profile);
    public static native int nativeProbeDefense(String surface, String point);
    public static native byte[] nativeTransformDefense(byte[] material, String binding);
    public static native int nativeInitializeDefenseCode(int surfaceCode, int profileCode);
    public static native int nativeProbeDefenseCode(int surfaceCode, int pointCode);
    public static native byte[] nativeTransformDefenseCode(byte[] material, int bindingCode);
    static native Object nativeInvokeSite(
        MethodHandles.Lookup lookup,
        String indyName,
        MethodType methodType,
        byte[] token,
        Object[] arguments,
        boolean linkBootstrap
    );

    /**
     * Link an invokedynamic site without returning its bootstrap or business
     * MethodHandles to Java.
     */
    public static CallSite linkTargetSite(
        MethodHandles.Lookup lookup,
        String indyName,
        MethodType methodType,
        byte[] token,
        Object[] arguments
    ) {
        requireTargetSiteRequest(lookup, indyName, methodType, token, arguments);
        ensureQpNativeKernel();
        byte[] copy = Arrays.copyOf(token, token.length);
        Object[] argumentCopy = copyOpaqueArguments(arguments);
        try {
            Object result = nativeInvokeSite(lookup, indyName, methodType, copy, argumentCopy, true);
            if (!(result instanceof CallSite) || !((CallSite) result).type().equals(methodType)) {
                throw new SecurityException("indy target site linking failed closed");
            }
            return (CallSite) result;
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("indy target Native linker is unavailable", error);
        } finally {
            Arrays.fill(copy, (byte) 0);
            clearOpaqueArguments(argumentCopy);
        }
    }

    /** Invoke one opaque business target without materializing its handle in Java. */
    public static Object invokeTargetSite(
        MethodHandles.Lookup lookup,
        String indyName,
        MethodType methodType,
        byte[] token,
        Object[] arguments
    ) throws Throwable {
        requireTargetSiteRequest(lookup, indyName, methodType, token, arguments);
        ensureQpNativeKernel();
        byte[] copy = Arrays.copyOf(token, token.length);
        Object[] argumentCopy = Arrays.copyOf(arguments, arguments.length);
        try {
            return nativeInvokeSite(lookup, indyName, methodType, copy, argumentCopy, false);
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("indy target Native invocation is unavailable", error);
        } finally {
            Arrays.fill(copy, (byte) 0);
            Arrays.fill(argumentCopy, null);
        }
    }

    private static void requireTargetSiteRequest(
        MethodHandles.Lookup lookup,
        String indyName,
        MethodType methodType,
        byte[] token,
        Object[] arguments
    ) {
        if (lookup == null || indyName == null || indyName.length() == 0 || indyName.length() > 512 ||
            methodType == null || token == null || token.length == 0 || token.length > 64 * 1024 ||
            arguments == null || arguments.length > 4096) {
            throw new SecurityException("indy target site request is invalid");
        }
    }

    private static Object[] copyOpaqueArguments(Object[] arguments) {
        Object[] copy = Arrays.copyOf(arguments, arguments.length);
        for (int i = 0; i < copy.length; i++) {
            if (copy[i] instanceof byte[]) copy[i] = Arrays.copyOf((byte[]) copy[i], ((byte[]) copy[i]).length);
        }
        return copy;
    }

    private static void clearOpaqueArguments(Object[] arguments) {
        for (Object argument : arguments) {
            if (argument instanceof byte[]) Arrays.fill((byte[]) argument, (byte) 0);
        }
        Arrays.fill(arguments, null);
    }

    /* ---- Qp current typed page bridge ---- */

    public static Object executeQpVmPage(long entryToken, byte[] encodedHandle, int pageIndex, byte[] callSiteProof, Object[] args) {
        requireQpPageRequest(encodedHandle, pageIndex, callSiteProof, "VM");
        ensureQpNativeKernel();
        requireDefenseForProtectedPath();
        try {
            /* A null result is valid for a virtualized void method and for a
             * reference-returning method whose value is null. The native bridge
             * reports every unsuccessful execution by throwing SecurityException
             * before returning to this call site. */
            return nativeExecuteVmPage(entryToken, packQpPageRequest(encodedHandle, pageIndex, callSiteProof), args);
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("Qp VM page bridge is not registered for the sealed helper", error);
        }
    }

    public static String openQpString(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        requireQpPageRequest(encodedHandle, pageIndex, callSiteProof, "string");
        ensureQpNativeKernel();
        requireDefenseForProtectedPath();
        String result = nativeOpenStringPage(packQpPageRequest(encodedHandle, pageIndex, callSiteProof));
        if (result == null) throw new SecurityException("Qp string page access failed closed");
        return result;
    }

    public static byte[] readQpClassPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        requireQpPageRequest(encodedHandle, pageIndex, callSiteProof, "class");
        ensureQpNativeKernel();
        requireDefenseForProtectedPath();
        return requireQpPageResult(nativeReadClassPage(packQpPageRequest(encodedHandle, pageIndex, callSiteProof)), "class");
    }

    /**
     * Opens and consumes exactly one authenticated native-private chunk inside
     * the JNI kernel.  The decrypted chunk never crosses the JNI boundary.
     */
    public static void consumeQpNativeChunk(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        requireQpPageRequest(encodedHandle, pageIndex, callSiteProof, "native");
        ensureQpNativeKernel();
        requireDefenseForProtectedPath();
        nativeConsumeNativeSegment(packQpPageRequest(encodedHandle, pageIndex, callSiteProof));
    }

    private static byte[] packQpPageRequest(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        requireQpPageRequest(encodedHandle, pageIndex, callSiteProof, "packed");
        byte[] packed = new byte[24 + 4 + callSiteProof.length];
        System.arraycopy(encodedHandle, 0, packed, 0, 24);
        packed[24] = (byte) (pageIndex >>> 24);
        packed[25] = (byte) (pageIndex >>> 16);
        packed[26] = (byte) (pageIndex >>> 8);
        packed[27] = (byte) pageIndex;
        System.arraycopy(callSiteProof, 0, packed, 28, callSiteProof.length);
        return packed;
    }

    private static void requireQpPageRequest(byte[] encodedHandle, int pageIndex, byte[] callSiteProof, String purpose) {
        if (encodedHandle == null || encodedHandle.length != 24 || pageIndex < 0 || callSiteProof == null || callSiteProof.length == 0 || callSiteProof.length > 4096) {
            throw new SecurityException("Qp " + purpose + " page request is invalid");
        }
    }

    private static void ensureQpNativeKernel() {
        if (nativeLoadState == LOAD_UNTRIED) loadQpNativeKernel();
        if (nativeLoadState != LOAD_READY) {
            throw new SecurityException("Qp page access requires the sealed native kernel (" + nativeLoadMessage + ")");
        }
        if (kernelState < KERNEL_NATIVE_READY) {
            kernelState = KERNEL_NATIVE_READY;
        }
    }

    /** Load only the authenticated Qp Rust JNI artifact. */
    private static synchronized void loadQpNativeKernel() {
        if (nativeLoadState != LOAD_UNTRIED) return;
        nativeLoadState = LOAD_LOADING;
        try {
            String platformTarget = detectPlatform();
            if (platformTarget == null) {
                nativeLoadMessage = "qp:native-unavailable";
                nativeLoadState = LOAD_FAILED;
                return;
            }
            if (!tryLoadQpBundledNative(platformTarget)) {
                if (nativeLoadMessage == null || nativeLoadMessage.length() == 0) {
                    nativeLoadMessage = "qp:bundled-native-unavailable:" + platformTarget;
                }
                nativeLoadState = LOAD_FAILED;
                return;
            }
            nativeLoadState = LOAD_READY;
            nativeSelfCheckFailed = false;
            runDiversifiedVmSelfExercise();
        } catch (Throwable error) {
            nativeLoadMessage = debugNativeLoadMessage("qp:native-exception", error);
            nativeLoadState = LOAD_FAILED;
        }
    }

    private static boolean tryLoadQpBundledNative(String platformTarget) {
        QpNativeLibrary locator;
        try {
            locator = readQpLocator(platformTarget);
        } catch (SecurityException error) {
            String detail = error.getMessage();
            nativeLoadMessage = "qp:native-locator-invalid:" + platformTarget +
                (detail == null || detail.length() == 0 ? "" : ":" + detail);
            return false;
        }
        return tryLoadQpBundledNativeResource(platformTarget, locator);
    }

    private static boolean tryLoadQpBundledNativeResource(String platformTarget, QpNativeLibrary locator) {
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
                nativeLoadMessage = "qp:native-resource-missing:" + platformTarget;
                return false;
            }
            nativeBytes = readAllBounded(in, locator.storedLength);
            if (nativeBytes.length != locator.storedLength || hasQpRejectedLegacyHeader(nativeBytes)) {
                nativeLoadMessage = "qp:native-resource-invalid:" + platformTarget;
                return false;
            }
            validateNativeImage(platformTarget, nativeBytes);
            actualDigest = sha256(nativeBytes);
            if (!MessageDigest.isEqual(locator.sha256, actualDigest)) {
                nativeLoadMessage = "qp:native-resource-digest-mismatch:" + platformTarget;
                return false;
            }
            String bindingText = sealedNativeBindingText(locator);
            if (bindingText == null || bindingText.length() == 0) {
                nativeLoadMessage = "qp:native-bindings-invalid:" + platformTarget;
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
                if (!extractedNativeMatchesLocator(tempLib, locator)) {
                    nativeLoadMessage = "qp:native-extract-digest-mismatch:" + platformTarget;
                    return false;
                }
                System.load(tempLib.getAbsolutePath());
                if (!extractedNativeMatchesLocator(tempLib, locator)) {
                    nativeLoadMessage = "qp:native-loaded-digest-mismatch:" + platformTarget;
                    return false;
                }
                int initResult = initializeNativeKernel(platformTarget);
                if (initResult < 0) {
                    nativeLoadMessage = "qp:native-init-failed:" + initResult;
                    return false;
                }
                installQpSessionNonce();
                loadedNativePlatformKey = shortPlatformKey(platformTarget);
                installQpCatalog();
                if (!verifyQpNativeAbiAfterLoad()) {
                    return false;
                }
                nativeLoadMessage = "qp:native:bundled:" + platformTarget + ":" + initResult;
                loaded = true;
                return true;
            }
            nativeLoadMessage = "qp:native-extract-unavailable:" + platformTarget;
            return false;
        } catch (UnsatisfiedLinkError error) {
            nativeLoadMessage = debugNativeLoadMessage("qp:native-load-error", error);
            return false;
        } catch (Throwable error) {
            nativeLoadMessage = debugNativeLoadMessage("qp:native-init-error", error);
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

    private static boolean verifyQpNativeAbiAfterLoad() {
        byte[] handle = new byte[24];
        byte[] proof = new byte[] { 1 };
        try {
            if (nativeHeartbeat() < 0) {
                nativeLoadMessage = "qp:abi-failed:nativeHeartbeat";
                return false;
            }
            byte[] packed = packQpPageRequest(handle, 0, proof);
            try {
                nativeExecuteVmPage(0L, packed, null);
            } catch (SecurityException expectedRouteFailure) {
                // The current native bridge is intentionally fail-closed until page routing lands.
            }
            try {
                nativeOpenStringPage(packed);
            } catch (SecurityException expectedRouteFailure) {
                // Registered typed route reached native code.
            }
            try {
                nativeReadClassPage(packed);
            } catch (SecurityException expectedRouteFailure) {
                // Registered typed route reached native code.
            }
            try {
                nativeConsumeNativeSegment(packed);
            } catch (SecurityException expectedRouteFailure) {
                // Registered typed route reached native code.
            }
            if (nativeInitializeDefenseCode(3, 1) != 0) {
                nativeLoadMessage = "qp:abi-failed:route-1";
                return false;
            }
            if (nativeProbeDefenseCode(3, 1) != 0) {
                nativeLoadMessage = "qp:abi-failed:route-2";
                return false;
            }
            byte[] defenseShare = nativeTransformDefenseCode(new byte[] { 1 }, 1);
            try {
                if (defenseShare == null || defenseShare.length != 32) {
                    nativeLoadMessage = "qp:abi-failed:route-3";
                    return false;
                }
            } finally {
                if (defenseShare != null) Arrays.fill(defenseShare, (byte) 0);
            }
            return true;
        } catch (UnsatisfiedLinkError error) {
            nativeLoadMessage = "qp:abi-missing:typed-page-bridge";
            return false;
        } catch (Throwable error) {
            String detail = error.getMessage();
            nativeLoadMessage = "qp:abi-failed:" + error.getClass().getName()
                + (detail == null || detail.isEmpty() ? "" : ":" + detail);
            return false;
        } finally {
            Arrays.fill(handle, (byte) 0);
            Arrays.fill(proof, (byte) 0);
        }
    }

    private static void validateNativeImage(String platformTarget, byte[] bytes) {
        if (bytes == null || bytes.length < 64 || hasQpRejectedLegacyHeader(bytes)) {
            throw new SecurityException("Qp native image is invalid");
        }
        if ("x86_64-pc-windows-gnu".equals(platformTarget)) {
            if (bytes[0] != 'M' || bytes[1] != 'Z') {
                throw new SecurityException("Qp Windows image is not PE");
            }
            int peOffset = readLittleEndianInt(bytes, 0x3C);
            if (peOffset < 0 || peOffset > bytes.length - 24 || bytes[peOffset] != 'P' ||
                bytes[peOffset + 1] != 'E' || bytes[peOffset + 2] != 0 || bytes[peOffset + 3] != 0 ||
                readLittleEndianShort(bytes, peOffset + 4) != 0x8664) {
                throw new SecurityException("Qp Windows image architecture is invalid");
            }
            int sectionCount = readLittleEndianShort(bytes, peOffset + 6);
            int optionalHeaderSize = readLittleEndianShort(bytes, peOffset + 20);
            int characteristics = readLittleEndianShort(bytes, peOffset + 22);
            int optionalHeaderOffset = peOffset + 24;
            if (sectionCount < 1 || sectionCount > 96 || optionalHeaderSize < 112 ||
                optionalHeaderOffset > bytes.length - optionalHeaderSize ||
                readLittleEndianShort(bytes, optionalHeaderOffset) != 0x20B ||
                (characteristics & 0x2000) == 0) {
                throw new SecurityException("Qp Windows image is not an AMD64 DLL");
            }
            long sectionTableEnd = (long) optionalHeaderOffset + optionalHeaderSize + (long) sectionCount * 40L;
            if (sectionTableEnd > bytes.length) {
                throw new SecurityException("Qp Windows image section table is invalid");
            }
        } else if ("x86_64-unknown-linux-gnu.2.17".equals(platformTarget)) {
            if (bytes[0] != 0x7F || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F' ||
                bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 ||
                readLittleEndianShort(bytes, 16) != 3 || readLittleEndianShort(bytes, 18) != 62 ||
                readLittleEndianInt(bytes, 20) != 1) {
                throw new SecurityException("Qp Linux image is not an AMD64 ELF shared object");
            }
            long programHeaderOffset = readLittleEndianLong(bytes, 32);
            int elfHeaderSize = readLittleEndianShort(bytes, 52);
            int programHeaderEntrySize = readLittleEndianShort(bytes, 54);
            int programHeaderCount = readLittleEndianShort(bytes, 56);
            long programHeaderBytes = (long) programHeaderEntrySize * programHeaderCount;
            if (programHeaderOffset < 0L || elfHeaderSize < 64 || programHeaderEntrySize < 56 ||
                programHeaderCount < 1 || programHeaderCount > 1024 ||
                programHeaderOffset > bytes.length || programHeaderBytes > bytes.length - programHeaderOffset) {
                throw new SecurityException("Qp Linux image program headers are invalid");
            }
        } else {
            throw new SecurityException("Qp target is unsupported");
        }
        /*
         * JNI registration is verified by the typed calls below.  Keeping a
         * table of Java method names here only creates a static oracle and is
         * redundant once RegisterNatives has installed the current binding
         * table.  The native image still has to pass the structural checks and
         * the first heartbeat/page/defense transactions before it is accepted.
         */
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

    private static byte[] requireQpPageResult(byte[] result, String purpose) {
        if (result == null) throw new SecurityException("Qp " + purpose + " page access failed closed");
        return result;
    }

    private static byte[] readQpLocatorBytes() throws Exception {
        try (InputStream in = resourceStream(QP_NATIVE_LOCATOR_RESOURCE)) {
            return in == null ? null : readAllBounded(in, QP_NATIVE_LOCATOR_MAX_BYTES);
        }
    }

    /** Resolve and authenticate one binary Qp locator for the active target. */
    private static QpNativeLibrary readQpLocator(String expectedPlatform) {
        byte[] raw = null;
        byte[] expectedCommitment = null;
        byte[] storedCommitment = null;
        byte[] bindingSha256 = null;
        QpNativeLibrary selected = null;
        boolean completed = false;
        try {
            raw = readQpLocatorBytes();
            if (raw == null) throw new SecurityException("Qp native locator is missing");
            if (raw.length < QP_NATIVE_LOCATOR_HEADER_BYTES + QP_NATIVE_LOCATOR_COMMITMENT_BYTES ||
                hasQpRejectedLegacyHeader(raw) || !hasQpLocatorMagic(raw) ||
                (raw[4] & 0xFF) != QP_NATIVE_LOCATOR_VERSION || (raw[5] & 0xFF) != 0) {
                throw new SecurityException("Qp native locator binary header is invalid");
            }
            int payloadLength = raw.length - QP_NATIVE_LOCATOR_COMMITMENT_BYTES;
            expectedCommitment = nativeLocatorCommitment(raw, payloadLength);
            storedCommitment = Arrays.copyOfRange(raw, payloadLength, raw.length);
            if (!MessageDigest.isEqual(expectedCommitment, storedCommitment)) {
                throw new SecurityException("Qp native locator commitment is invalid");
            }
            int recordCount = readQpLocatorU16(raw, 6, payloadLength);
            if (recordCount < 1 || recordCount > QP_NATIVE_LOCATOR_MAX_RECORDS) {
                throw new SecurityException("Qp native locator record count is invalid");
            }

            int expectedPlatformId = nativePlatformId(expectedPlatform);
            if (expectedPlatformId == 0) {
                throw new SecurityException("Qp native locator requested platform is invalid");
            }
            int offset = QP_NATIVE_LOCATOR_HEADER_BYTES;
            int lastPlatformId = 0;
            boolean bindingSeen = false;
            String bindingResourcePath = null;
            int bindingStoredLength = 0;
            LinkedHashSet<String> seenRoutes = new LinkedHashSet<>();
            for (int recordIndex = 0; recordIndex < recordCount; recordIndex++) {
                if (offset < 0 || offset > payloadLength - QP_NATIVE_LOCATOR_RECORD_FIXED_BYTES) {
                    throw new SecurityException("Qp native locator record is truncated");
                }
                int kind = raw[offset++] & 0xFF;
                int platformId = raw[offset++] & 0xFF;
                int routeLength = readQpLocatorU16(raw, offset, payloadLength);
                offset += 2;
                int storedLength = readQpLocatorPositiveU32(raw, offset, payloadLength);
                offset += 4;
                if (routeLength < 1 || routeLength > QP_NATIVE_LOCATOR_MAX_ROUTE_BYTES ||
                    offset > payloadLength - QP_NATIVE_SHA256_LENGTH ||
                    routeLength > payloadLength - offset - QP_NATIVE_SHA256_LENGTH) {
                    throw new SecurityException("Qp native locator route length is invalid");
                }
                byte[] digest = Arrays.copyOfRange(raw, offset, offset + QP_NATIVE_SHA256_LENGTH);
                offset += QP_NATIVE_SHA256_LENGTH;
                byte[] maskedRoute = Arrays.copyOfRange(raw, offset, offset + routeLength);
                offset += routeLength;
                byte[] routeBytes = null;
                boolean digestTransferred = false;
                try {
                    routeBytes = unmaskQpLocatorRoute(
                        maskedRoute,
                        kind,
                        platformId,
                        storedLength,
                        digest
                    );
                    if (!isQpNativeRouteBytes(routeBytes)) {
                        throw new SecurityException("Qp native locator route encoding is invalid");
                    }
                    String resourcePath = new String(routeBytes, StandardCharsets.US_ASCII);
                    if (!isQpNativeResourcePath(resourcePath) || !seenRoutes.add(resourcePath)) {
                        throw new SecurityException("Qp native locator route is invalid or duplicated");
                    }

                    if (kind == QP_NATIVE_LOCATOR_KIND_LIBRARY) {
                        if (bindingSeen || platformId <= lastPlatformId || platformId > 2 ||
                            storedLength > QP_NATIVE_MAX_LIBRARY_BYTES) {
                            throw new SecurityException("Qp native locator platform record is invalid");
                        }
                        lastPlatformId = platformId;
                        String fileSuffix = nativeSuffix(platformId);
                        if (fileSuffix == null || !resourcePath.endsWith(fileSuffix)) {
                            throw new SecurityException("Qp native locator suffix binding is invalid");
                        }
                        if (platformId == expectedPlatformId) {
                            if (selected != null) {
                                throw new SecurityException("Qp native locator has duplicate active platform");
                            }
                            selected = new QpNativeLibrary(resourcePath, fileSuffix, storedLength, digest);
                            digestTransferred = true;
                        }
                    } else if (kind == QP_NATIVE_LOCATOR_KIND_BINDINGS) {
                        if (platformId != 0 || bindingSeen || recordIndex != recordCount - 1 ||
                            storedLength > QP_NATIVE_BINDINGS_MAX_BYTES) {
                            throw new SecurityException("Qp native bindings locator record is invalid");
                        }
                        bindingSeen = true;
                        bindingResourcePath = resourcePath;
                        bindingStoredLength = storedLength;
                        bindingSha256 = digest;
                        digestTransferred = true;
                    } else {
                        throw new SecurityException("Qp native locator record kind is invalid");
                    }
                } finally {
                    Arrays.fill(maskedRoute, (byte) 0);
                    if (routeBytes != null) Arrays.fill(routeBytes, (byte) 0);
                    if (!digestTransferred) Arrays.fill(digest, (byte) 0);
                }
            }
            if (offset != payloadLength) throw new SecurityException("Qp native locator has trailing bytes");
            if (selected == null) throw new SecurityException("Qp native locator has no active platform route");
            if (!bindingSeen || bindingResourcePath == null || bindingSha256 == null) {
                throw new SecurityException("Qp native locator has no final binding route");
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
            throw new SecurityException("Qp native locator is unreadable", error);
        } finally {
            if (raw != null) Arrays.fill(raw, (byte) 0);
            if (expectedCommitment != null) Arrays.fill(expectedCommitment, (byte) 0);
            if (storedCommitment != null) Arrays.fill(storedCommitment, (byte) 0);
            if (bindingSha256 != null) Arrays.fill(bindingSha256, (byte) 0);
            if (!completed && selected != null) selected.clear();
        }
    }

    private static boolean hasQpLocatorMagic(byte[] bytes) {
        return bytes != null && bytes.length >= 4 &&
            (bytes[0] & 0xFF) == QP_NATIVE_LOCATOR_MAGIC_0 &&
            (bytes[1] & 0xFF) == QP_NATIVE_LOCATOR_MAGIC_1 &&
            (bytes[2] & 0xFF) == QP_NATIVE_LOCATOR_MAGIC_2 &&
            (bytes[3] & 0xFF) == QP_NATIVE_LOCATOR_MAGIC_3;
    }

    private static int nativePlatformId(String platform) {
        if ("x86_64-pc-windows-gnu".equals(platform) || "windows-x64".equals(platform)) return 1;
        if ("x86_64-unknown-linux-gnu.2.17".equals(platform) || "linux-x64".equals(platform)) return 2;
        return 0;
    }

    private static String nativeSuffix(int platformId) {
        if (platformId == 1) return ".dll";
        if (platformId == 2) return ".so";
        return null;
    }

    private static boolean isQpNativeResourcePath(String resourcePath) {
        if (resourcePath == null || !resourcePath.startsWith(QP_NATIVE_RESOURCE_ROOT) ||
            resourcePath.length() == QP_NATIVE_RESOURCE_ROOT.length() || resourcePath.indexOf('\\') >= 0 ||
            resourcePath.indexOf('\u0000') >= 0 || resourcePath.indexOf('|') >= 0 ||
            resourcePath.indexOf('\r') >= 0 || resourcePath.indexOf('\n') >= 0) {
            return false;
        }
        String normalizedPath = resourcePath.toLowerCase(Locale.ROOT);
        if (normalizedPath.startsWith("meta-inf/.r/") ||
            normalizedPath.startsWith("meta-inf/js-native/") || normalizedPath.startsWith("meta-inf/native-src/") ||
            normalizedPath.startsWith("meta-inf/jsrt/") ||
            !hasCurrentNativeResourceSuffix(normalizedPath)) {
            return false;
        }
        String tail = resourcePath.substring(QP_NATIVE_RESOURCE_ROOT.length());
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
        return lower.equals("qp") || lower.equals(".qp") || lower.equals(".r") ||
            lower.equals("js-native") || lower.equals("native-src") ||
            lower.contains(new String(new char[] {'m', 'a', 'c', 'o', 's'})) ||
            lower.contains(new String(new char[] {'d', 'a', 'r', 'w', 'i', 'n'})) ||
            lower.contains(new String(new char[] {'m', 'a', 'c', 'h', 'o'})) ||
            lower.contains(new String(new char[] {'m', 'a', 'c', 'h', '-', 'o'})) ||
            lower.startsWith(new String(new char[] {'j', 's', '_', 'k', 'e', 'r', 'n', 'e', 'l', '_'})) ||
            lower.startsWith(new String(new char[] {'z', 'i', 'g'}));
    }

    private static boolean hasCurrentNativeResourceSuffix(String normalizedPath) {
        return normalizedPath.endsWith(".dll") || normalizedPath.endsWith(".so") ||
            normalizedPath.endsWith(".properties") || normalizedPath.endsWith(".xml") ||
            normalizedPath.endsWith(".json") || normalizedPath.endsWith(".yml") ||
            normalizedPath.endsWith(".cfg") || normalizedPath.endsWith(".conf") ||
            normalizedPath.endsWith(".ini") || normalizedPath.endsWith(".txt");
    }

    private static int readQpLocatorU16(byte[] bytes, int offset, int limit) {
        if (bytes == null || offset < 0 || limit < 0 || offset > limit - 2 || limit > bytes.length) {
            throw new SecurityException("Qp native locator u16 is truncated");
        }
        return ((bytes[offset] & 0xFF) << 8) | (bytes[offset + 1] & 0xFF);
    }

    private static int readQpLocatorPositiveU32(byte[] bytes, int offset, int limit) {
        if (bytes == null || offset < 0 || limit < 0 || offset > limit - 4 || limit > bytes.length) {
            throw new SecurityException("Qp native locator u32 is truncated");
        }
        long value = ((long) (bytes[offset] & 0xFF) << 24) |
            ((long) (bytes[offset + 1] & 0xFF) << 16) |
            ((long) (bytes[offset + 2] & 0xFF) << 8) |
            (long) (bytes[offset + 3] & 0xFF);
        if (value <= 0L || value > Integer.MAX_VALUE) {
            throw new SecurityException("Qp native locator length is invalid");
        }
        return (int) value;
    }

    private static byte[] nativeLocatorCommitment(byte[] payload, int payloadLength) {
        byte[] domain = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            domain = QP_NATIVE_LOCATOR_COMMITMENT_DOMAIN.getBytes(StandardCharsets.US_ASCII);
            digest.update(domain);
            digest.update(payload, 0, payloadLength);
            return digest.digest();
        } catch (Exception error) {
            throw new SecurityException("Qp native locator commitment is unavailable", error);
        } finally {
            if (domain != null) Arrays.fill(domain, (byte) 0);
        }
    }

    private static byte[] unmaskQpLocatorRoute(
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
            domain = QP_NATIVE_LOCATOR_ROUTE_MASK_DOMAIN.getBytes(StandardCharsets.US_ASCII);
            while (offset < route.length) {
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                digest.update(domain);
                digest.update((byte) kind);
                digest.update((byte) platformId);
                updateQpLocatorInt(digest, storedLength);
                digest.update(digestBytes);
                updateQpLocatorInt(digest, blockIndex++);
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
            throw new SecurityException("Qp native locator route mask is unavailable", error);
        } finally {
            if (domain != null) Arrays.fill(domain, (byte) 0);
        }
    }

    private static void updateQpLocatorInt(MessageDigest digest, int value) {
        digest.update((byte) (value >>> 24));
        digest.update((byte) (value >>> 16));
        digest.update((byte) (value >>> 8));
        digest.update((byte) value);
    }

    private static boolean isQpNativeRouteBytes(byte[] bytes) {
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

    private static boolean hasQpRejectedLegacyHeader(byte[] bytes) {
        return hasQpHeader(bytes, 'J', 'S', 'R', 'P') ||
            hasQpHeader(bytes, 'J', 'S', 'B', 'I') ||
            hasQpHeader(bytes, 'J', 'S', 'B', 'M') ||
            hasQpHeader(bytes, 'J', 'S', 'B', 'K');
    }

    private static boolean hasQpHeader(byte[] bytes, char first, char second, char third, char fourth) {
        return bytes != null && bytes.length >= 4 &&
            (bytes[0] & 0xFF) == first &&
            (bytes[1] & 0xFF) == second &&
            (bytes[2] & 0xFF) == third &&
            (bytes[3] & 0xFF) == fourth;
    }

    /* Retained Java entrypoints fail closed; the current runtime exposes no generic resource ABI. */
    public static Object executeVmResource(long entryToken, String resourcePath, Object[] args) {
        throw new SecurityException("generic VM resource execution is not part of the current runtime");
    }

    public static Object executeVmResource(long entryToken, Object[] args) {
        throw new SecurityException("generic VM resource execution is not part of the current runtime");
    }

    public static void executeVmResourceVoid(long entryToken) {
        throw new SecurityException("generic VM resource execution is not part of the current runtime");
    }

    public static int executeVmResourceInt(long entryToken) {
        throw new SecurityException("generic VM resource execution is not part of the current runtime");
    }

    public static int executeVmResourceIntInt(long entryToken, int arg0) {
        throw new SecurityException("generic VM resource execution is not part of the current runtime");
    }

    public static void executeVmResourceIntVoid(long entryToken, int arg0) {
        throw new SecurityException("generic VM resource execution is not part of the current runtime");
    }

    /**
     * Materialize a StringConcatFactory recipe for the native VM bridge.  The
     * native side supplies the original recipe and typed static constants while
     * the JVM performs the actual StringBuilder append/coercion semantics.
     */
    public static String concatStringRecipe(String recipe, Object[] constants, Object[] arguments) {
        if (recipe == null) throw new IllegalArgumentException("StringConcatFactory recipe is null");
        Object[] staticConstants = constants == null ? new Object[0] : constants;
        Object[] dynamicArguments = arguments == null ? new Object[0] : arguments;
        StringBuilder result = new StringBuilder();
        int dynamicIndex = 0;
        int constantIndex = 0;
        for (int index = 0; index < recipe.length(); index++) {
            char marker = recipe.charAt(index);
            if (marker == '\u0001') {
                if (dynamicIndex >= dynamicArguments.length) throw new IllegalArgumentException("StringConcatFactory dynamic argument count mismatch");
                result.append(dynamicArguments[dynamicIndex++]);
            } else if (marker == '\u0002') {
                if (constantIndex >= staticConstants.length) throw new IllegalArgumentException("StringConcatFactory constant count mismatch");
                result.append(staticConstants[constantIndex++]);
            } else {
                result.append(marker);
            }
        }
        if (dynamicIndex != dynamicArguments.length || constantIndex != staticConstants.length) {
            throw new IllegalArgumentException("StringConcatFactory recipe arity mismatch");
        }
        return result.toString();
    }

    /* ---- Public status API ---- */

    public static String getLoadStatus() {
        return loadState == LOAD_UNTRIED && (loadMessage == null || loadMessage.length() == 0) ? "untried" : loadMessage;
    }

    public static boolean isNativeLoaded() {
        return loadState == LOAD_READY || nativeLoadState == LOAD_READY;
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
        if (loadState == LOAD_LOADING || nativeLoadState == LOAD_LOADING) return;
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
            loadQpNativeKernel();
            if (nativeLoadState == LOAD_READY) {
                loadState = LOAD_UNTRIED;
                loadMessage = "";
                runDiversifiedVmSelfExercise();
                return;
            }
            loadMessage = nativeLoadMessage == null || nativeLoadMessage.length() == 0
                ? "qp:bundled-native-unavailable"
                : nativeLoadMessage;
            loadState = LOAD_FAILED;
            runDiversifiedVmSelfExercise();
        } catch (Throwable e) {
            loadMessage = debugNativeLoadMessage("qp:native-exception", e);
            loadState = LOAD_FAILED;
        }
    }

    /**
     * Generated protected classes use numeric route codes so loader policy
     * labels do not appear in their constant pools. The source-level string
     * overload remains for callers that use the public helper directly.
     */
    public static void loadKernel(int kernelComponentsCode, int targetPlatformCode, int vmModeCode) {
        if (kernelComponentsCode < 1 || kernelComponentsCode > 5 ||
            targetPlatformCode < 0 || targetPlatformCode > 3 ||
            (vmModeCode != 0 && vmModeCode != 1)) {
            throw new SecurityException("Qp native loader route is invalid");
        }
        // Production helper classes use this route. The code values are
        // authenticated by the generated/native binding contract; no policy
        // labels are reconstructed in the protected class constant pool.
        diversifiedVmEnabled = vmModeCode == 1;
        if (isNativeLoaded()) {
            runDiversifiedVmSelfExercise();
            return;
        }
        if (loadState == LOAD_LOADING || nativeLoadState == LOAD_LOADING) return;
        loadState = LOAD_LOADING;
        try {
            loadQpNativeKernel();
            if (nativeLoadState == LOAD_READY) {
                loadState = LOAD_UNTRIED;
                loadMessage = "";
                runDiversifiedVmSelfExercise();
                return;
            }
            loadMessage = nativeLoadMessage == null || nativeLoadMessage.length() == 0
                ? "qp:bundled-native-unavailable"
                : nativeLoadMessage;
            loadState = LOAD_FAILED;
            runDiversifiedVmSelfExercise();
        } catch (Throwable error) {
            loadMessage = debugNativeLoadMessage("qp:native-exception", error);
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

    /** True only after the authenticated native defense state reached DEFENSE_READY. */
    public static boolean isKernelIntegrityReady() {
        return kernelState == KERNEL_DEFENSE_READY && nativeLoadState == LOAD_READY && !nativeSelfCheckFailed;
    }

    /** Arm protected-data gates even if initialize() is later skipped or nopped. */
    public static void expectDefenseForProtectedPath() {
        defenseRequired = true;
    }

    public static synchronized void markDefenseBindingsVerified() {
        if (kernelState == KERNEL_FAILED || kernelState == KERNEL_TAMPERED || kernelState == KERNEL_SUSPECT) {
            throw new SecurityException("Unified defense kernel is not usable");
        }
        kernelState = KERNEL_BINDINGS_VERIFIED;
        defenseRequired = true;
    }

    public static synchronized void markDefenseReady() {
        if (nativeLoadState != LOAD_READY || nativeSelfCheckFailed) {
            kernelState = KERNEL_FAILED;
            defenseRequired = true;
            throw new SecurityException("Unified defense native readiness is incomplete");
        }
        kernelState = KERNEL_DEFENSE_READY;
        defenseRequired = true;
    }

    public static synchronized void markDefenseFailed() {
        kernelState = KERNEL_FAILED;
        defenseRequired = true;
    }

    private static void requireDefenseForProtectedPath() {
        if (!defenseRequired) return;
        requireHealthyKernel();
        QpGuard.authorizeProtectedData();
    }

    /** Status string for the diversified-VM load-time self-exercise. */
    public static String getVmSelfCheck() {
        return vmSelfCheckCode == 0 ? "" : Integer.toString(vmSelfCheckCode);
    }

    /*
     * Diversified virtualization is native-only in native VM mode. The Java helper
     * records whether the mode was requested and relies on ABI/boot-token gates
     * after native load instead of running any Java VM fallback path.
     */
    private static void runDiversifiedVmSelfExercise() {
        if (!diversifiedVmEnabled) {
            vmSelfCheckCode = 0;
            return;
        }
        vmSelfCheckCode = isNativeLoaded() ? 1 : 2;
    }

    /** Require the current unified defense state before accessing protected data. */
    public static void requireHealthyKernel() {
        if (!isKernelIntegrityReady() || vmSelfCheckCode == 3) {
            kernelState = KERNEL_TAMPERED;
            throw new SecurityException("Kernel integrity mismatch");
        }
    }

    private static byte[] createVmStartupNonce() {
        byte[] nonce = new byte[32];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static String sealedBindingKey(String value) {
        byte[] encoded = ("QP-BINDING-V1|" + value).getBytes(StandardCharsets.UTF_8);
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

    /* ---- Locked current host targets ---- */
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

    private static void installQpSessionNonce() {
        byte[] startupNonce = createVmStartupNonce();
        try {
            if (!nativeInstallSessionNonce(startupNonce)) {
                throw new SecurityException("Qp runtime session nonce installation failed");
            }
        } finally {
            Arrays.fill(startupNonce, (byte) 0);
        }
    }

    /** Install the authenticated current-format page directory into native state. */
    private static void installQpCatalog() {
        CatalogBundle bundle = readQpCatalogBundle();
        if (bundle == null) return;
        try {
            byte[] pack = bundle.pack != null ? bundle.pack : new byte[0];
            try {
                int installed = nativeInstallCatalog(bundle.directory, bundle.pages, pack);
                if (installed <= 0) {
                    throw new SecurityException("Qp current catalog installed no pages");
                }
            } finally {
                if (bundle.pack != null) Arrays.fill(pack, (byte) 0);
            }
        } finally {
            bundle.clear();
        }
    }

    /**
     * Read the sealed directory and page resources into one bounded JNI bundle.
     * Bundle format: u32 count, then repeated u32 UTF-8 path length + path,
     * followed by u32 byte length + page bytes. The directory itself is passed
     * separately so native can authenticate it before accepting page frames.
     */
    private static CatalogBundle readQpCatalogBundle() {
        InputStream indexStream = resourceStream(QP_CATALOG_INDEX_RESOURCE);
        if (indexStream == null) return null;
        byte[] directory = null;
        byte[][] paths = new byte[4][];
        byte[][] blobs = new byte[4][];
        int count = 0;
        int framedSize = 4;
        try (InputStream in = indexStream) {
            byte[] indexBytes = readAllBounded(in, 256 * 1024);
            String index = new String(indexBytes, StandardCharsets.US_ASCII);
            Arrays.fill(indexBytes, (byte) 0);
            byte[] pack = null;
            String[] entries = index.split("\\r?\\n", -1);
            for (String raw : entries) {
                String line = raw.trim();
                if (line.length() == 0) continue;
                if (line.startsWith("pack|")) {
                    int second = line.indexOf('|', 5);
                    if (second < 0) throw new SecurityException("Qp catalog pack entry is invalid");
                    String packPlatform = line.substring(5, second);
                    String packRelative = line.substring(second + 1);
                    validateCatalogRelativePath(packRelative);
                    if (pack != null) throw new SecurityException("Qp catalog pack is duplicated");
                    if (!packPlatform.equals(loadedNativePlatformKey)) continue;
                    try (InputStream source = resourceStream(packRelative)) {
                        if (source == null) throw new SecurityException("Qp catalog pack is missing: " + packRelative);
                        pack = readAllBounded(source, 16 * 1024 * 1024);
                    }
                    continue;
                }
                String relative = line.trim();
                if (relative.length() == 0) continue;
                validateCatalogRelativePath(relative);
                if (relative.indexOf('/') < 0) {
                    if (directory != null) throw new SecurityException("Qp catalog directory is duplicated");
                    try (InputStream source = resourceStream(QP_CATALOG_RESOURCE_ROOT + relative)) {
                        if (source == null) throw new SecurityException("Qp catalog directory is missing");
                        directory = readAllBounded(source, 64 * 1024 * 1024);
                    }
                    continue;
                }
                try (InputStream source = resourceStream(relative)) {
                    if (source == null) throw new SecurityException("Qp catalog page is missing: " + relative);
                    if (count == paths.length) {
                        paths = java.util.Arrays.copyOf(paths, paths.length * 2);
                        blobs = java.util.Arrays.copyOf(blobs, blobs.length * 2);
                    }
                    byte[] path = relative.getBytes(StandardCharsets.UTF_8);
                    byte[] page = readAllBounded(source, 16 * 1024 * 1024 + 1024);
                    paths[count] = path;
                    blobs[count] = page;
                    framedSize += 8 + path.length + page.length;
                    count++;
                }
            }
            if (directory == null || count == 0) {
                throw new SecurityException("Qp current catalog is incomplete");
            }
            byte[] framed = new byte[framedSize];
            int pos = writeBe32(framed, 0, count);
            for (int i = 0; i < count; i++) {
                byte[] path = paths[i];
                byte[] page = blobs[i];
                pos = writeBe32(framed, pos, path.length);
                System.arraycopy(path, 0, framed, pos, path.length);
                pos += path.length;
                pos = writeBe32(framed, pos, page.length);
                System.arraycopy(page, 0, framed, pos, page.length);
                pos += page.length;
                Arrays.fill(path, (byte) 0);
                Arrays.fill(page, (byte) 0);
                paths[i] = null;
                blobs[i] = null;
            }
            if (pos != framed.length) {
                Arrays.fill(framed, (byte) 0);
                throw new SecurityException("Qp current catalog bundle length mismatch");
            }
            return new CatalogBundle(directory, framed, pack);
        } catch (IOException error) {
            if (directory != null) Arrays.fill(directory, (byte) 0);
            throw new SecurityException("Qp current catalog is unreadable", error);
        }
    }

    private static int writeBe32(byte[] dest, int offset, int value) {
        dest[offset] = (byte) (value >>> 24);
        dest[offset + 1] = (byte) (value >>> 16);
        dest[offset + 2] = (byte) (value >>> 8);
        dest[offset + 3] = (byte) value;
        return offset + 4;
    }

    private static void validateCatalogRelativePath(String relative) {
        if (relative.length() == 0 || relative.length() > 4096 ||
            relative.indexOf('\\') >= 0 || relative.indexOf('\0') >= 0 ||
            relative.startsWith("/") || relative.contains("..")) {
            throw new SecurityException("Qp catalog path is invalid");
        }
    }

    private static final class CatalogBundle {
        private byte[] directory;
        private byte[] pages;
        private byte[] pack;
        private CatalogBundle(byte[] directory, byte[] pages, byte[] pack) {
            this.directory = directory;
            this.pages = pages;
            this.pack = pack;
        }
        private void clear() {
            if (directory != null) Arrays.fill(directory, (byte) 0);
            if (pages != null) Arrays.fill(pages, (byte) 0);
            if (pack != null) Arrays.fill(pack, (byte) 0);
            directory = null;
            pages = null;
            pack = null;
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
        InputStream in = QpBridge.class.getResourceAsStream("/" + resourcePath);
        if (in != null) return in;
        ClassLoader loader = QpBridge.class.getClassLoader();
        return loader == null ? null : loader.getResourceAsStream(resourcePath);
    }

    private static void publishSealedNativeBindings(String bindingText) {
        if (bindingText == null || bindingText.length() == 0) {
            throw new SecurityException("Qp native bindings are unavailable");
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
                    throw new SecurityException("Qp native bindings record is malformed");
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
                    throw new SecurityException("Qp native bindings record type is invalid");
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
            throw new SecurityException("Qp native bindings are unavailable", error);
        }
    }

    private static void publishSealedNativeLoaderOwner() {
        System.setProperty(sealedLoaderPropertyName(), QpBridge.class.getName().replace('.', '/'));
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

    private static String sealedNativeBindingText(QpNativeLibrary locator) {
        String resourcePath = locator == null ? null : locator.bindingResourcePath;
        if (resourcePath == null || !isQpNativeResourcePath(resourcePath)) {
            throw new SecurityException("Qp native bindings resource path is unavailable");
        }
        try (InputStream in = resourceStream(resourcePath)) {
            if (in == null) return null;
            byte[] raw = readAllBounded(in, QP_NATIVE_BINDINGS_MAX_BYTES);
            try {
                if (locator != null) verifyQpNativeBinding(locator, raw);
                if (raw.length == 0 || hasQpRejectedLegacyHeader(raw) || !isAscii(raw)) {
                    throw new SecurityException("Qp native bindings are not raw relocation metadata");
                }
                return new String(raw, StandardCharsets.UTF_8);
            } finally {
                Arrays.fill(raw, (byte) 0);
            }
        } catch (SecurityException error) {
            throw error;
        } catch (Exception error) {
            throw new SecurityException("Qp native bindings are unavailable", error);
        }
    }

    private static void verifyQpNativeBinding(QpNativeLibrary locator, byte[] raw) {
        if (locator.bindingResourcePath == null ||
            !isQpNativeResourcePath(locator.bindingResourcePath) ||
            locator.bindingSha256 == null || raw.length != locator.bindingStoredLength) {
            throw new SecurityException("Qp native binding locator does not match the sealed resource");
        }
        byte[] actualDigest = sha256(raw);
        try {
            if (!MessageDigest.isEqual(locator.bindingSha256, actualDigest)) {
                throw new SecurityException("Qp native binding digest mismatch");
            }
        } finally {
            Arrays.fill(actualDigest, (byte) 0);
        }
    }

    public static byte[] decodeRuntimeResourceForNative(byte[] raw) {
        throw new SecurityException("generic runtime-resource decoding is not part of the current runtime");
    }

    public static byte[] decodeRuntimeResourceEnvelope(byte[] raw) {
        throw new SecurityException("generic runtime-resource decoding is not part of the current runtime");
    }

    public static byte[] deriveClassEncryptionKey(byte[] keyId, byte[] salt, int length) {
        throw new SecurityException("class-encryption key derivation is not part of the current Java helper");
    }

    public static byte[] decryptClassBytes(byte[] keyId, byte[] salt, byte[] nonce, byte[] ciphertext, byte[] aad, int keyLength) {
        throw new SecurityException("class-encryption decryption is not part of the current Java helper");
    }

    private static boolean extractedNativeMatchesLocator(File extracted, QpNativeLibrary locator) {
        byte[] digest = null;
        try {
            digest = sha256File(extracted, locator.storedLength);
            return digest != null && MessageDigest.isEqual(locator.sha256, digest);
        } catch (SecurityException error) {
            return false;
        } finally {
            if (digest != null) Arrays.fill(digest, (byte) 0);
        }
    }

    private static byte[] sha256File(File file, int expectedLength) {
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] bytes = readAllBounded(in, expectedLength);
            try {
                if (bytes.length != expectedLength) {
                    throw new SecurityException("native extract length mismatch");
                }
                return sha256(bytes);
            } finally {
                Arrays.fill(bytes, (byte) 0);
            }
        } catch (SecurityException error) {
            throw error;
        } catch (Exception error) {
            throw new SecurityException("native extract digest is unavailable", error);
        }
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

    private static final class QpNativeLibrary {
        final String resourcePath;
        final String fileSuffix;
        final int storedLength;
        final byte[] sha256;
        String bindingResourcePath;
        int bindingStoredLength;
        byte[] bindingSha256;

        QpNativeLibrary(String resourcePath, String fileSuffix, int storedLength, byte[] sha256) {
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
