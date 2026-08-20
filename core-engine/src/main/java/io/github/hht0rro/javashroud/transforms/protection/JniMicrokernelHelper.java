package io.github.hht0rro.javashroud.transforms.protection;

import java.io.File;
import java.io.FileInputStream;
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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Runtime helper for JNI microkernel loader.
 * Pure Java - no Kotlin runtime dependency.
 *
 * Attempts to load a bundled native kernel from the JAR resources.
 * In pure VBC4-only mode this helper is strictly fail-closed:
 * native bootstrap and load logic remain, but there is no Java fallback
 * and native ABI failures reject execution.
 */
public final class JniMicrokernelHelper {

    private static final int LOAD_FAILED = -1;
    private static final int LOAD_UNTRIED = 0;
    private static final int LOAD_LOADING = 1;
    private static final int LOAD_READY = 2;
    private static volatile int loadState = LOAD_UNTRIED;
    private static volatile String loadMessage = "";
    /* AKEN readiness is deliberately independent from the legacy boot-material loader. */
    private static volatile int akenLoadState = LOAD_UNTRIED;
    private static volatile String akenLoadMessage = "";
    private static volatile boolean diversifiedVmEnabled = false;
    private static volatile String vmSelfCheck = "";
    private static volatile long nativeBootToken = 0L;
    private static volatile boolean nativeSelfCheckFailed = false;
    private static volatile boolean sealedNativeBindingsPublished = false;
    private static volatile boolean bootSecretEnvBindingEnabled = false;
    private static volatile String[] bootSecretExpectedFingerprints = new String[0];
    private static volatile byte[][] runtimeResourceKeys;
    private static volatile int runtimeResourcePartitionCount;
    private static volatile int anchorResourcePartition = -1;
    private static volatile byte[] expectedShellBindingCommitment;
    private static volatile Thread expectedShellBindingThread;
    private static volatile int shellBindingHandoffState;
    private static volatile byte[] nativeShellBootSecret;
    private static volatile Thread nativeShellBootSecretThread;
    private static final String SEALED_NATIVE_INDEX_RESOURCE = "META-INF/.r/0.dat";
    private static final String SEALED_NATIVE_BINDINGS_RESOURCE = "META-INF/.r/bindings.dat";
    private static final String AKEN_NATIVE_LOCATOR_RESOURCE = "META-INF/aken/native.locator";
    private static final String AKEN_NATIVE_BINDINGS_LOCATOR_RESOURCE = "META-INF/aken/native.bindings.locator";
    private static final String AKEN_NATIVE_RESOURCE_ROOT = "META-INF/";
    private static final String AKEN_NATIVE_LOCATOR_RECORD = "AKEN_NATIVE_LOCATOR_V1";
    private static final String AKEN_NATIVE_BINDINGS_LOCATOR_RECORD = "AKEN_NATIVE_BINDINGS_V1";
    private static final int AKEN_NATIVE_LOCATOR_MAX_BYTES = 16 * 1024;
    private static final int AKEN_NATIVE_MAX_LIBRARY_BYTES = 256 * 1024 * 1024;
    private static final int AKEN_NATIVE_SHA256_LENGTH = 32;
    private static final int AKEN_NATIVE_BINDINGS_MAX_BYTES = 4 * 1024 * 1024;
    private static final String BOOT_MATERIAL_RESOURCE = "META-INF/.r/boot.dat";
    private static final String EMBEDDED_BOOT_SECRET_RESOURCE = "META-INF/.r/kek.dat";
    private static final String BOOT_SECRET_ENV = "JAVASHROUD_BOOT_SECRET_V1";
    private static final String BOOT_SECRET_FILE_ENV = "JAVASHROUD_BOOT_SECRET_FILE_V1";
    private static final int BOOT_MATERIAL_VERSION = 2;
    private static final int HARDENED_BOOT_MATERIAL_VERSION = 3;
    private static final int SHELL_BINDING_COMMITMENT_SIZE = 32;
    private static final byte[] BOOT_MATERIAL_AAD = "javashroud-boot-material-v2".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] HARDENED_BOOT_MATERIAL_AAD = "javashroud-boot-material-v3".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] BOOT_SIDECAR_TEXT_PREFIX = "JSBK1.".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] BOOT_SIDECAR_KEY_DOMAIN = "JavaShroud/BootKekSidecar/v1/key".getBytes(StandardCharsets.US_ASCII);
    private static final String VM_CATALOG_RESOURCE = "META-INF/.r/vm.catalog";
    private static final int RUNTIME_RESOURCE_VERSION = 7;
    private static final int RUNTIME_RESOURCE_HEADER_SIZE = 27;
    private static final int NATIVE_ANCHOR_KEY_SLOT = 16;
    private static final int ZSTD_MAGIC = 0xFD2FB528;
    private static final int LAMBDA_FLAG_SERIALIZABLE = 1;
    private static final int LAMBDA_FLAG_MARKERS = 2;
    private static final int LAMBDA_FLAG_BRIDGES = 4;
    private static final int LAMBDA_SUPPORTED_FLAGS = LAMBDA_FLAG_SERIALIZABLE | LAMBDA_FLAG_MARKERS | LAMBDA_FLAG_BRIDGES;
    private static final ConcurrentMap<String, MethodHandle> SAM_LAMBDA_CACHE = new ConcurrentHashMap<>();
    private static final ConcurrentMap<String, Class<?>> SAM_BRIDGE_INTERFACE_CACHE = new ConcurrentHashMap<>();

    private JniMicrokernelHelper() { }

    /* ---- JNI native methods (implemented in js_kernel.c) ---- */

    static native int nativeInit(String platform);
    static native int nativeVerify(byte[] data, byte[] expectedMac);
    static native int nativeHeartbeat();
    static native String nativeGetVersion();
    static native long nativeGetBootToken();
    static native boolean nativeInstallBootMaterial(byte[] material);
    static native boolean nativeInstallBootEnvelope(byte[] envelope, byte[] sidecar);
    static native boolean nativeIsBootMaterialReady();
    static native void nativeAbortBootMaterial();
    static native void nativePreloadRuntimeResources(byte[] preloadIndex, byte[] commitments, byte[] startupNonce);
    static native boolean nativeInstallAkenSessionNonce(byte[] startupNonce);
    static native byte[] nativeDecodeRuntimeResource(byte[] encoded);
    public static native byte[] nativeDecryptAes(byte[] encrypted, byte[] key, byte[] iv);
    public static native byte[] nativeDeriveClassEncryptionKey(byte[] keyId, byte[] salt, int length);
    static native byte[] nativeDecryptClassBytes(byte[] keyId, byte[] salt, byte[] nonce, byte[] ciphertext, byte[] aad, int keyLength);
    static native String nativeSealedBindingKey(byte[] value);
    public static native String nativeGetMachineFingerprint();

    /* ---- AKEN v4 typed page bridge ----
     * These declarations intentionally accept only a page-local handle, page index,
     * and call-site proof.  They never accept caller-supplied ciphertext, key bytes,
     * locator metadata, or a generic resource buffer.
     */
    static native Object nativeExecuteAkenVmPage(long entryToken, byte[] encodedHandle, int pageIndex, byte[] callSiteProof, Object[] args);
    static native byte[] nativeDecodeAkenStringPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);
    static native byte[] nativeReadAkenClassPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);
    static native void nativeConsumeAkenNativeChunk(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);
    /* Fixture-only, de-identified runtime counters.  The production runtime
     * never calls this method; the diagnostics build registers it only for
     * attached-JVM benchmark evidence. */
    static native long[] nativeRuntimeMetricsSnapshot();
    /* Fixture-only effective crypto capability probe.  The result contains
     * only two boolean flags: AES dispatch availability and GHASH/PCLMUL
     * dispatch availability.  No CPU identity or sensitive runtime state is
     * exposed. */
    static native long[] nativeRuntimeCryptoCapabilities();

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

    public static byte[] decodeAkenStringPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        requireAkenPageRequest(encodedHandle, pageIndex, callSiteProof, "string");
        ensureAkenNativeKernel();
        return requireAkenPageResult(nativeDecodeAkenStringPage(encodedHandle, pageIndex, callSiteProof), "string");
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
            throw new SecurityException("AKEN page access requires the sealed native kernel; no Java fallback (" + akenLoadMessage + ")");
        }
    }

    /**
     * Load only the AKEN-specific raw JNI artifact.  This path intentionally
     * does not read boot material, publish legacy sealed bindings, install a
     * boot envelope, or preload the old VM catalog.
     */
    private static synchronized void loadAkenNativeKernel() {
        if (akenLoadState != LOAD_UNTRIED) return;
        akenLoadState = LOAD_LOADING;
        try {
            String platformSuffix = detectPlatform();
            if (platformSuffix == null) {
                akenLoadMessage = "aken:native-unavailable";
                akenLoadState = LOAD_FAILED;
                return;
            }
            if (!tryLoadAkenBundledNative(platformSuffix)) {
                if (akenLoadMessage == null || akenLoadMessage.length() == 0) {
                    akenLoadMessage = "aken:bundled-native-unavailable";
                }
                akenLoadState = LOAD_FAILED;
                return;
            }
            akenLoadState = LOAD_READY;
            /*
             * nativeInit deliberately defers optional helper registration while
             * the loader is in LOAD_LOADING: resolving those classes can trigger
             * an AKEN string bootstrap before its typed bridge is ready.  A
             * heartbeat after READY completes that registration without a
             * re-entrant page-open failure.
             */
            activateAkenDeferredNativeBindings();
            nativeSelfCheckFailed = false;
            runDiversifiedVmSelfExercise();
        } catch (Throwable error) {
            akenLoadMessage = debugNativeLoadMessage("aken:native-exception", error);
            akenLoadState = LOAD_FAILED;
        }
    }

    private static void activateAkenDeferredNativeBindings() {
        final int heartbeat;
        try {
            heartbeat = nativeHeartbeat();
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("AKEN deferred native bindings are not registered", error);
        }
        if (heartbeat < 0) {
            throw new SecurityException("AKEN deferred native bindings registration failed");
        }
    }

    private static boolean tryLoadAkenBundledNative(String platformSuffix) {
        AkenNativeLibrary locator;
        try {
            locator = readAkenNativeLocator(platformSuffix);
        } catch (SecurityException error) {
            akenLoadMessage = "aken:native-locator-invalid:" + platformSuffix;
            return false;
        }
        return tryLoadAkenBundledNativeResource(platformSuffix, locator);
    }

    private static boolean tryLoadAkenBundledNativeResource(String platformSuffix, AkenNativeLibrary locator) {
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
                akenLoadMessage = "aken:native-resource-missing:" + platformSuffix;
                return false;
            }
            nativeBytes = readAllBounded(in, locator.storedLength);
            if (nativeBytes.length != locator.storedLength || hasAkenRejectedLegacyHeader(nativeBytes)) {
                akenLoadMessage = "aken:native-resource-invalid:" + platformSuffix;
                return false;
            }
            actualDigest = sha256(nativeBytes);
            if (!MessageDigest.isEqual(locator.sha256, actualDigest)) {
                akenLoadMessage = "aken:native-resource-digest-mismatch:" + platformSuffix;
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
                // AKEN v4 relocation metadata is public binding material.  Publish
                // only the active locator-selected binding route before System.load.
                publishSealedNativeBindings(locator);
                sealedNativeBindingsPublished = true;
                System.load(tempLib.getAbsolutePath());
                int initResult = initializeNativeKernel(platformSuffix);
                if (initResult < 0) {
                    akenLoadMessage = "aken:native-init-failed:" + initResult;
                    return false;
                }
                installAkenSessionNonce();
                if (!verifyAkenNativeAbiAfterLoad()) return false;
                akenLoadMessage = "aken:native:bundled:" + platformSuffix + ":" + initResult;
                loaded = true;
                return true;
            }
            akenLoadMessage = "aken:native-extract-unavailable:" + platformSuffix;
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
            try {
                nativeExecuteAkenVmPage(0L, handle, 0, proof, null);
            } catch (SecurityException expectedRouteFailure) {
                // The current native bridge is intentionally fail-closed until page routing lands.
            }
            try {
                nativeDecodeAkenStringPage(handle, 0, proof);
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

    private static byte[] requireAkenPageResult(byte[] result, String purpose) {
        if (result == null) throw new SecurityException("AKEN " + purpose + " page access failed closed");
        return result;
    }

    /**
     * Resolve exactly one raw AKEN native artifact for the active platform.
     * This parser intentionally has no compatibility branch for JSBI, JSRP,
     * boot envelopes, bindings, or a general resource catalog.
     */
    private static AkenNativeLibrary readAkenNativeLocator(String expectedPlatform) {
        byte[] raw = null;
        byte[] bindingSha256 = null;
        try (InputStream in = resourceStream(AKEN_NATIVE_LOCATOR_RESOURCE)) {
            if (in == null) throw new SecurityException("AKEN native locator is missing");
            raw = readAllBounded(in, AKEN_NATIVE_LOCATOR_MAX_BYTES);
            if (raw.length == 0 || hasAkenRejectedLegacyHeader(raw) || !isAscii(raw)) {
                throw new SecurityException("AKEN native locator is not raw metadata");
            }
            String text = new String(raw, StandardCharsets.US_ASCII);
            AkenNativeLibrary selected = null;
            String bindingResourcePath = null;
            int bindingStoredLength = 0;
            String[] lines = text.split("\\n", -1);
            if (lines.length == 0 || (lines.length > 1 && lines[lines.length - 1].length() == 0)) {
                throw new SecurityException("AKEN native locator has invalid line layout");
            }
            LinkedHashSet<String> seenPlatforms = new LinkedHashSet<>();
            for (String line : lines) {
                if (line.length() == 0 || line.indexOf('\r') >= 0) {
                    throw new SecurityException("AKEN native locator has an empty or CRLF record");
                }
                String[] fields = line.split("\\|", -1);
                if (AKEN_NATIVE_BINDINGS_LOCATOR_RECORD.equals(fields[0])) {
                    if (fields.length != 4 || bindingResourcePath != null ||
                        !isAkenNativeResourcePath(fields[1])) {
                        throw new SecurityException("AKEN native bindings locator record is malformed");
                    }
                    int storedLength = parseAkenNativeLength(fields[2]);
                    if (storedLength > AKEN_NATIVE_BINDINGS_MAX_BYTES) {
                        throw new SecurityException("AKEN native bindings locator length is invalid");
                    }
                    bindingResourcePath = fields[1];
                    bindingStoredLength = storedLength;
                    bindingSha256 = parseAkenNativeSha256(fields[3]);
                    continue;
                }
                if (fields.length != 6 || !AKEN_NATIVE_LOCATOR_RECORD.equals(fields[0])) {
                    throw new SecurityException("AKEN native locator record is malformed");
                }
                String platform = fields[1];
                String resourcePath = fields[2];
                String fileSuffix = fields[3];
                if (!isAkenNativePlatform(platform) || !seenPlatforms.add(platform)) {
                    throw new SecurityException("AKEN native locator platform is invalid or duplicated");
                }
                if (!isAkenNativeResourcePath(resourcePath) || !isAkenNativeSuffix(platform, fileSuffix) ||
                    !resourcePath.endsWith(fileSuffix)) {
                    throw new SecurityException("AKEN native locator route is invalid");
                }
                int storedLength = parseAkenNativeLength(fields[4]);
                byte[] digest = parseAkenNativeSha256(fields[5]);
                if (platform.equals(expectedPlatform)) {
                    if (selected != null) {
                        Arrays.fill(digest, (byte) 0);
                        throw new SecurityException("AKEN native locator has duplicate active platform");
                    }
                    selected = new AkenNativeLibrary(resourcePath, fileSuffix, storedLength, digest);
                } else {
                    Arrays.fill(digest, (byte) 0);
                }
            }
            if (selected == null) throw new SecurityException("AKEN native locator has no active platform route");
            selected.bindingResourcePath = bindingResourcePath;
            selected.bindingStoredLength = bindingStoredLength;
            selected.bindingSha256 = bindingSha256;
            bindingSha256 = null;
            return selected;
        } catch (SecurityException error) {
            throw error;
        } catch (Exception error) {
            throw new SecurityException("AKEN native locator is unreadable", error);
        } finally {
            if (raw != null) Arrays.fill(raw, (byte) 0);
            if (bindingSha256 != null) Arrays.fill(bindingSha256, (byte) 0);
        }
    }

    private static boolean isAkenNativePlatform(String platform) {
        return "windows-x64".equals(platform) ||
            "linux-x64".equals(platform) ||
            "macos-x64".equals(platform) ||
            "macos-arm64".equals(platform);
    }

    private static boolean isAkenNativeSuffix(String platform, String suffix) {
        return ("windows-x64".equals(platform) && ".dll".equals(suffix)) ||
            ("linux-x64".equals(platform) && ".so".equals(suffix)) ||
            (("macos-x64".equals(platform) || "macos-arm64".equals(platform)) && ".dylib".equals(suffix));
    }

    private static boolean isAkenNativeResourcePath(String resourcePath) {
        if (resourcePath == null || !resourcePath.startsWith(AKEN_NATIVE_RESOURCE_ROOT) ||
            resourcePath.length() == AKEN_NATIVE_RESOURCE_ROOT.length() || resourcePath.indexOf('\\') >= 0 ||
            resourcePath.indexOf('\u0000') >= 0 || resourcePath.indexOf('|') >= 0 ||
            resourcePath.indexOf('\r') >= 0 || resourcePath.indexOf('\n') >= 0) {
            return false;
        }
        String tail = resourcePath.substring(AKEN_NATIVE_RESOURCE_ROOT.length());
        String[] segments = tail.split("/", -1);
        for (String segment : segments) {
            if (segment.length() == 0 || ".".equals(segment) || "..".equals(segment)) return false;
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

    private static int parseAkenNativeLength(String value) {
        if (!isDecimal(value)) throw new SecurityException("AKEN native locator length is invalid");
        try {
            int parsed = Integer.parseInt(value);
            if (parsed <= 0 || parsed > AKEN_NATIVE_MAX_LIBRARY_BYTES) {
                throw new SecurityException("AKEN native locator length is invalid");
            }
            return parsed;
        } catch (NumberFormatException error) {
            throw new SecurityException("AKEN native locator length is invalid", error);
        }
    }

    private static byte[] parseAkenNativeSha256(String value) {
        if (value == null || value.length() != AKEN_NATIVE_SHA256_LENGTH * 2) {
            throw new SecurityException("AKEN native locator SHA-256 is invalid");
        }
        byte[] digest = new byte[AKEN_NATIVE_SHA256_LENGTH];
        for (int index = 0; index < digest.length; index++) {
            char hi = value.charAt(index * 2);
            char lo = value.charAt(index * 2 + 1);
            if (hi < '0' || hi > 'f' || lo < '0' || lo > 'f' ||
                (hi > '9' && hi < 'a') || (lo > '9' && lo < 'a')) {
                Arrays.fill(digest, (byte) 0);
                throw new SecurityException("AKEN native locator SHA-256 is invalid");
            }
            int high = Character.digit(hi, 16);
            int low = Character.digit(lo, 16);
            if (high < 0 || low < 0) {
                Arrays.fill(digest, (byte) 0);
                throw new SecurityException("AKEN native locator SHA-256 is invalid");
            }
            digest[index] = (byte) ((high << 4) | low);
        }
        return digest;
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

    public static native Object nativeExecuteVmResource(long entryToken, String resourcePath, Object[] args);
    public static native Object nativeExecuteVmResourceByToken(long entryToken, Object[] args);
    public static Object executeVmResource(long entryToken, String resourcePath, Object[] args) {
        if (loadState == LOAD_UNTRIED) {
            loadKernel("vm", "auto", "vm-diverse");
        }
        if (isNativeLoaded()) {
            ensureSealedNativeBindingsPublished();
            return nativeExecuteVmResource(entryToken, resourcePath, args);
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }
    public static Object executeVmResource(long entryToken, Object[] args) {
        if (loadState == LOAD_UNTRIED) {
            loadKernel("vm", "auto", "vm-diverse");
        }
        if (isNativeLoaded()) {
            ensureSealedNativeBindingsPublished();
            return nativeExecuteVmResourceByToken(entryToken, args);
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }

    public static native void nativeExecuteVmResourceVoid(long entryToken);
    public static native int nativeExecuteVmResourceInt(long entryToken);
    public static native int nativeExecuteVmResourceIntInt(long entryToken, int arg0);
    public static native void nativeExecuteVmResourceIntVoid(long entryToken, int arg0);
    public static void executeVmResourceVoid(long entryToken) {
        if (loadState == LOAD_UNTRIED) {
            loadKernel("vm", "auto", "vm-diverse");
        }
        if (isNativeLoaded()) {
            ensureSealedNativeBindingsPublished();
            nativeExecuteVmResourceVoid(entryToken);
            return;
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }
    public static int executeVmResourceInt(long entryToken) {
        if (loadState == LOAD_UNTRIED) {
            loadKernel("vm", "auto", "vm-diverse");
        }
        if (isNativeLoaded()) {
            ensureSealedNativeBindingsPublished();
            return nativeExecuteVmResourceInt(entryToken);
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }
    public static int executeVmResourceIntInt(long entryToken, int arg0) {
        if (loadState == LOAD_UNTRIED) {
            loadKernel("vm", "auto", "vm-diverse");
        }
        if (isNativeLoaded()) {
            ensureSealedNativeBindingsPublished();
            return nativeExecuteVmResourceIntInt(entryToken, arg0);
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }
    public static void executeVmResourceIntVoid(long entryToken, int arg0) {
        if (loadState == LOAD_UNTRIED) {
            loadKernel("vm", "auto", "vm-diverse");
        }
        if (isNativeLoaded()) {
            ensureSealedNativeBindingsPublished();
            nativeExecuteVmResourceIntVoid(entryToken, arg0);
            return;
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
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
            String platformSuffix = detectPlatform();
            if (platformSuffix == null) {
                loadMessage = "native-unavailable";
                loadState = LOAD_FAILED;
                runDiversifiedVmSelfExercise();
                return;
            }
            if (!targetPlatformAllowsCurrent(targetPlatform, platformSuffix)) {
                loadMessage = "native-platform-not-requested:" + platformSuffix;
                loadState = LOAD_FAILED;
                return;
            }
            loadAkenNativeKernel();
            if (akenLoadState == LOAD_READY) {
                /* AKEN readiness must not publish the legacy kernel state. */
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

    private static boolean targetPlatformAllowsCurrent(String targetPlatform, String platformSuffix) {
        if (targetPlatform == null || platformSuffix == null) return false;
        String requested = targetPlatform.trim();
        if ("auto".equals(requested) || "all".equals(requested)) return true;
        String[] platforms = requested.split(",", -1);
        for (String platform : platforms) {
            if (platformSuffix.equals(platform.trim())) return true;
        }
        return false;
    }

    /** Whether diversified virtualization was requested for this load. */
    public static boolean isDiversifiedVmEnabled() {
        return diversifiedVmEnabled;
    }

    /**
     * True once the native kernel finished loading and did not fail ABI or boot-token self-checks.
     * This distinguishes a genuine integrity failure from early call sites that race helper initialization.
     */
    public static boolean isKernelIntegrityReady() {
        if (akenLoadState == LOAD_READY) return !nativeSelfCheckFailed;
        return loadState == LOAD_READY && !nativeSelfCheckFailed && nativeIsBootMaterialReady();
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

    /**
     * Multi-point kernel integrity gate.
     * Requires native kernel loaded AND no self-check or boot token failures.
     * Used by distributed call sites so patching a single check is insufficient.
     */
    public static void requireHealthyKernel() {
        boolean akenReady = akenLoadState == LOAD_READY;
        if (nativeSelfCheckFailed || !isNativeLoaded() || (!akenReady && !nativeIsBootMaterialReady()) ||
            (vmSelfCheck != null && vmSelfCheck.contains("mismatch"))) {
            throw new SecurityException("Kernel integrity mismatch");
        }
    }

    /**
     * Verify the native kernel boot token after loading.
     * If native library was replaced (e.g. Frida Interceptor.replace),
     * the token will not match and all subsequent critical calls are blocked.
     */
    private static boolean verifyNativeAbiAfterLoad() {
        try {
            nativeExecuteVmResource(0L, null, null);
            return true;
        } catch (UnsatisfiedLinkError e) {
            loadMessage = "native:abi-missing:nativeExecuteVmResource";
            return false;
        } catch (Throwable ignored) {
            return true;
        }
    }

    private static void verifyBootTokenAfterLoad(String platformSuffix) {
        try {
            long expected = computeExpectedBootToken(platformSuffix);
            long actual = nativeGetBootToken();
            nativeBootToken = actual;
            if (actual != expected) {
                nativeSelfCheckFailed = true;
                loadMessage = "native:integrity-mismatch";
            }
        } catch (UnsatisfiedLinkError e) {
            nativeSelfCheckFailed = true;
            loadMessage = "native:abi-missing:nativeGetBootToken";
        } catch (Throwable t) {
            nativeSelfCheckFailed = true;
            loadMessage = "native:integrity-check-failed";
        }
    }

    private static long computeExpectedBootToken(String platformSuffix) {
        if (platformSuffix == null) platformSuffix = "";
        long token = 0xCBF29CE484222325L;
        token ^= 0xCC4A1511L; // FNV1a(decoded native key), mirrored from js_kernel.c
        token *= 0x100000001B3L;
        token ^= 1L; // g_initialized after nativeInit succeeds
        token *= 0x100000001B3L;
        token ^= fnv1a32(platformSuffix);
        token *= 0x100000001B3L;
        token ^= 1L; // g_key_valid after native key self-check succeeds
        token *= 0x100000001B3L;
        return token;
    }

    private static long fnv1a32(String value) {
        long hash = 0x811C9DC5L;
        for (int i = 0; i < value.length(); i++) {
            hash ^= value.charAt(i) & 0xFFL;
            hash = (hash * 0x01000193L) & 0xFFFFFFFFL;
        }
        return hash;
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

    private static void preloadRuntimeResourcesIntoNative() {
        // Class-encryption-only artifacts still require the native boot/decrypt
        // bridge but intentionally have no VM catalog.  Do not make loader-only
        // startup fail closed on a catalog that is not part of this artifact;
        // VM-producing artifacts continue through the authenticated catalog path.
        if (!hasVmCatalogResource()) return;
        byte[][] catalog = null;
        byte[] startupNonce = createVmStartupNonce();
        try {
            catalog = verifiedVmCatalogPayload();
            nativePreloadRuntimeResources(catalog[0], catalog[1], startupNonce);
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable e) {
            throw new SecurityException("VM preload failed", e);
        } finally {
            if (catalog != null) {
                Arrays.fill(catalog[0], (byte) 0);
                Arrays.fill(catalog[1], (byte) 0);
            }
            Arrays.fill(startupNonce, (byte) 0);
        }
    }

    private static boolean hasVmCatalogResource() {
        JarFile catalogJar = openCatalogJar();
        if (catalogJar != null) {
            try {
                JarEntry entry = catalogJar.getJarEntry(VM_CATALOG_RESOURCE);
                return entry != null && !entry.isDirectory();
            } catch (Exception ignored) {
                return false;
            } finally {
                try {
                    catalogJar.close();
                } catch (Exception ignored) {
                }
            }
        }
        try (InputStream in = resourceStream(VM_CATALOG_RESOURCE)) {
            return in != null;
        } catch (Exception ignored) {
            return false;
        }
    }

    private static byte[] createVmStartupNonce() {
        byte[] nonce = new byte[32];
        vmStartupSecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static SecureRandom vmStartupSecureRandom() {
        if (File.separatorChar == '\\') {
            try {
                return SecureRandom.getInstance("Windows-PRNG");
            } catch (NoSuchAlgorithmException ignored) {
                // Retain the portable JCA provider path on non-standard Windows runtimes.
            }
        }
        return new SecureRandom();
    }

    private static void verifyVmPreloadIndexBeforeNative(String index, Set<String> committedPaths) {
        if (index == null || index.length() == 0) throw new SecurityException("missing VM preload index");
        Set<String> tokens = new HashSet<>();
        String[] lines = index.split("\n");
        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (line.length() == 0 || line.startsWith("A|")) continue;
            String[] parts = line.split("\\|", -1);
            if (parts.length < 7 || !isHex(parts[0], 1, 16) || !isHex(parts[4], 64, 64) ||
                !isHex(parts[5], 1, 8) || !isHex(parts[6], 16, 16)) {
                throw new SecurityException("malformed VM preload entry");
            }
            if (!tokens.add(parts[0]) || !committedPaths.contains(parts[1]) || !committedPaths.contains(parts[2])) {
                throw new SecurityException("invalid VM preload catalog reference");
            }
            String actual = vmPreloadEntryAuthTag(parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
            if (!constantTimeAsciiEquals(actual, parts[6])) {
                throw new SecurityException("invalid VM preload profile auth");
            }
        }
        if (tokens.isEmpty()) throw new SecurityException("empty VM preload index");
    }

    private static byte[][] verifiedVmCatalogPayload() throws Exception {
        JarFile catalogJar = openCatalogJar();
        try {
        byte[] rootEnvelope = readRequiredResource(VM_CATALOG_RESOURCE, catalogJar);
        byte[] rootRaw = decodeRuntimeResource(rootEnvelope, true);
        if (rootRaw == null) throw new SecurityException("invalid VM catalog root envelope");
        int tagMarker = lastIndexOf(rootRaw, new byte[] {'\n', 'H', '|'});
        if (tagMarker < 0) throw new SecurityException("malformed VM catalog root");
        byte[] rootBody = Arrays.copyOfRange(rootRaw, 0, tagMarker + 1);
        String rootText = new String(rootRaw, StandardCharsets.UTF_8);
        String rootTagText = rootText.substring(tagMarker + 3).trim();
        if (!isHex(rootTagText, 64, 64)) throw new SecurityException("malformed VM catalog root tag");
        byte[] anchorKey = partitionResourceKey(anchorResourcePartition());
        try {
            byte[] expectedTag = hmacSha256(anchorKey, concat(
                "jsc1-root-auth-v1".getBytes(StandardCharsets.US_ASCII),
                rootBody
            ));
            if (!MessageDigest.isEqual(expectedTag, hexToBytes(rootTagText))) {
                throw new SecurityException("invalid VM catalog root tag");
            }
        } finally {
            Arrays.fill(anchorKey, (byte) 0);
        }

        String[] rootLines = new String(rootBody, StandardCharsets.UTF_8).split("\n");
        if (rootLines.length < 2) throw new SecurityException("empty VM catalog root");
        String[] header = rootLines[0].split("\\|", -1);
        if (header.length != 6 || !"JSC1".equals(header[0]) || !isHex(header[1], 32, 32) ||
            !isDecimal(header[2]) || !isDecimal(header[3]) || !isDecimal(header[4]) || !isHex(header[5], 64, 64)) {
            throw new SecurityException("malformed VM catalog header");
        }
        byte[] catalogId = hexToBytes(header[1]);
        int partitionCount = parsePositiveInt(header[2], "partition count");
        int expectedMethodCount = parsePositiveInt(header[3], "method count");
        int expectedResourceCount = parsePositiveInt(header[4], "resource count");
        if (partitionCount != runtimeResourcePartitionCount()) throw new SecurityException("VM catalog partition mismatch");
        byte[] expectedCatalogRoot = hexToBytes(header[5]);

        List<String[]> directories = new ArrayList<>();
        for (int i = 1; i < rootLines.length; i++) {
            String line = rootLines[i].trim();
            if (line.length() == 0) continue;
            String[] parts = line.split("\\|", -1);
            if (parts.length != 8 || !"D".equals(parts[0])) throw new SecurityException("malformed VM catalog directory");
            directories.add(parts);
        }
        if (directories.size() != partitionCount) throw new SecurityException("incomplete VM catalog directories");
        sortVmCatalogDirectories(directories);

        StringBuilder preloadIndex = new StringBuilder();
        StringBuilder commitments = new StringBuilder();
        Set<String> committedPaths = new HashSet<>();
        List<byte[]> partitionRoots = new ArrayList<>();
        int totalMethods = 0;
        int totalResources = 0;
        for (int directoryOrdinal = 0; directoryOrdinal < directories.size(); directoryOrdinal++) {
            String[] descriptor = directories.get(directoryOrdinal);
            int partitionId = parsePositiveInt(descriptor[1], "partition id");
            if (partitionId != directoryOrdinal || !isHex(descriptor[4], 64, 64) || !isHex(descriptor[7], 64, 64)) {
                throw new SecurityException("invalid VM catalog directory ordering");
            }
            String directoryPath = descriptor[2];
            int directoryLength = parsePositiveInt(descriptor[3], "directory length");
            int directoryMethodCount = parsePositiveInt(descriptor[5], "directory method count");
            int directoryResourceCount = parsePositiveInt(descriptor[6], "directory resource count");
            byte[] descriptorRoot = hexToBytes(descriptor[7]);
            byte[] directoryRaw = readRequiredResource(directoryPath, catalogJar);
            if (directoryRaw.length != directoryLength || !MessageDigest.isEqual(sha256(directoryRaw), hexToBytes(descriptor[4]))) {
                throw new SecurityException("invalid VM catalog directory ciphertext");
            }
            if (!hasPartitionedRuntimeResourceHeader(directoryRaw, partitionId)) {
                throw new SecurityException("VM catalog directory partition mismatch");
            }
            byte[] directoryPlain = decodeRuntimeResource(directoryRaw, true);
            if (directoryPlain == null) throw new SecurityException("invalid VM catalog directory envelope");
            String[] directoryLines = new String(directoryPlain, StandardCharsets.UTF_8).split("\n");
            if (directoryLines.length == 0) throw new SecurityException("empty VM catalog directory");
            String[] directoryHeader = directoryLines[0].split("\\|", -1);
            if (directoryHeader.length != 6 || !"JSD1".equals(directoryHeader[0]) ||
                !header[1].equals(directoryHeader[1]) || partitionId != parsePositiveInt(directoryHeader[2], "directory partition") ||
                directoryMethodCount != parsePositiveInt(directoryHeader[3], "directory method count") ||
                directoryResourceCount != parsePositiveInt(directoryHeader[4], "directory resource count") ||
                !descriptor[7].equals(directoryHeader[5])) {
                throw new SecurityException("invalid VM catalog directory header");
            }
            List<byte[]> leaves = new ArrayList<>();
            int actualMethodCount = 0;
            int actualResourceCount = 0;
            for (int lineIndex = 1; lineIndex < directoryLines.length; lineIndex++) {
                String line = directoryLines[lineIndex];
                if (line.length() == 0) continue;
                if (line.length() >= 2 && line.charAt(0) == 'M' && line.charAt(1) == '|') {
                    preloadIndex.append(line.substring(2)).append('\n');
                    actualMethodCount++;
                    continue;
                }
                String[] resource = line.split("\\|", -1);
                if (resource.length != 5 || !"R".equals(resource[0]) || !isDecimal(resource[3]) || !isHex(resource[4], 64, 64)) {
                    throw new SecurityException("malformed VM catalog resource");
                }
                String logicalPath = resource[1];
                String storagePath = resource[2];
                int rawLength = parsePositiveInt(resource[3], "resource length");
                byte[] rawDigest = hexToBytes(resource[4]);
                if (!committedPaths.add(storagePath)) throw new SecurityException("duplicate VM catalog resource");
                byte[] raw = readRequiredResource(storagePath, catalogJar);
                if (raw.length != rawLength || !MessageDigest.isEqual(sha256(raw), rawDigest) ||
                    !hasPartitionedRuntimeResourceHeader(raw, partitionId)) {
                    throw new SecurityException("invalid VM catalog resource ciphertext");
                }
                leaves.add(vmCatalogLeaf(catalogId, partitionId, logicalPath, storagePath, rawLength, rawDigest));
                commitments.append("R|").append(storagePath).append('|').append(rawLength).append('|')
                    .append(resource[4]).append('|').append(partitionId).append('\n');
                actualResourceCount++;
            }
            if (actualMethodCount != directoryMethodCount || actualResourceCount != directoryResourceCount) {
                throw new SecurityException("VM catalog directory count mismatch");
            }
            byte[] actualRoot = vmCatalogMerkleRoot(leaves, catalogId, partitionId);
            if (!MessageDigest.isEqual(actualRoot, descriptorRoot)) throw new SecurityException("VM catalog partition root mismatch");
            partitionRoots.add(actualRoot);
            totalMethods += actualMethodCount;
            totalResources += actualResourceCount;
        }
        if (totalMethods != expectedMethodCount || totalResources != expectedResourceCount) {
            throw new SecurityException("VM catalog count mismatch");
        }
        if (!MessageDigest.isEqual(vmCatalogRoot(catalogId, partitionRoots), expectedCatalogRoot)) {
            throw new SecurityException("VM catalog root mismatch");
        }
        verifyVmPreloadIndexBeforeNative(preloadIndex.toString(), committedPaths);
        return new byte[][] {
            preloadIndex.toString().getBytes(StandardCharsets.UTF_8),
            commitments.toString().getBytes(StandardCharsets.UTF_8),
        };
        } finally {
            if (catalogJar != null) catalogJar.close();
        }
    }

    private static JarFile openCatalogJar() {
        try {
            java.security.CodeSource source = JniMicrokernelHelper.class.getProtectionDomain().getCodeSource();
            if (source == null || source.getLocation() == null || !"file".equalsIgnoreCase(source.getLocation().getProtocol())) return null;
            File file = new File(source.getLocation().toURI());
            return file.isFile() ? new JarFile(file, false) : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static byte[] readRequiredResource(String resourcePath, JarFile catalogJar) throws Exception {
        if (catalogJar != null) {
            JarEntry entry = catalogJar.getJarEntry(resourcePath);
            if (entry == null || entry.isDirectory()) throw new SecurityException("missing VM catalog resource");
            try (InputStream in = catalogJar.getInputStream(entry)) {
                return readAll(in);
            }
        }
        try (InputStream in = resourceStream(resourcePath)) {
            if (in == null) throw new SecurityException("missing VM catalog resource");
            return readAll(in);
        }
    }

    private static String vmPreloadEntryAuthTag(String tokenHex, String resourcePath, String manifestPath, String shardCount, String mesh, String profile) {
        byte[] digest = sha256(concat(
            "jsc1-method-auth-v1".getBytes(StandardCharsets.US_ASCII), new byte[] { 0 },
            tokenHex.getBytes(StandardCharsets.US_ASCII), new byte[] { 0 },
            resourcePath.getBytes(StandardCharsets.UTF_8), new byte[] { 0 },
            manifestPath.getBytes(StandardCharsets.UTF_8), new byte[] { 0 },
            shardCount.getBytes(StandardCharsets.US_ASCII), new byte[] { 0 },
            mesh.getBytes(StandardCharsets.US_ASCII), new byte[] { 0 },
            profile.getBytes(StandardCharsets.US_ASCII)
        ));
        return hexLower(Arrays.copyOf(digest, 8));
    }

    private static boolean isHex(String text, int minLength, int maxLength) {
        if (text == null || text.length() < minLength || text.length() > maxLength) return false;
        for (int i = 0; i < text.length(); i++) if (Character.digit(text.charAt(i), 16) < 0) return false;
        return true;
    }

    private static boolean constantTimeAsciiEquals(String expected, String actual) {
        if (expected == null || actual == null || expected.length() != actual.length()) return false;
        int diff = 0;
        for (int i = 0; i < expected.length(); i++) diff |= expected.charAt(i) ^ actual.charAt(i);
        return diff == 0;
    }

    private static String hexLower(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        char[] hex = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int value = bytes[i] & 0xFF;
            out[i * 2] = hex[value >>> 4];
            out[i * 2 + 1] = hex[value & 0x0F];
        }
        return new String(out);
    }

    private static void installBootMaterialIntoNative(String platformSuffix) throws Exception {
        byte[] envelope;
        try (InputStream in = resourceStream(BOOT_MATERIAL_RESOURCE)) {
            if (in == null) throw new SecurityException("missing encrypted boot material envelope");
            envelope = readAll(in);
        }
        int envelopeVersion = envelope.length > 4 ? envelope[4] & 0xFF : -1;
        if (envelopeVersion == HARDENED_BOOT_MATERIAL_VERSION) {
            byte[] sidecar = null;
            try {
                if (runtimeResourceKeys == null) {
                    throw new SecurityException("hardened Java boot material was not prepared for native load");
                }
                sidecar = readBootKekSidecarBinary();
                if (!nativeInstallBootEnvelope(envelope, sidecar) || !nativeIsBootMaterialReady()) {
                    throw new SecurityException("native boot envelope installation failed");
                }
                clearExpectedShellBindingCommitment();
            } catch (Throwable error) {
                clearJavaBootMaterial();
                try {
                    nativeAbortBootMaterial();
                } catch (Throwable ignored) {
                }
                throw error;
            } finally {
                if (sidecar != null) Arrays.fill(sidecar, (byte) 0);
                Arrays.fill(envelope, (byte) 0);
            }
            return;
        }

        clearJavaBootMaterial();
        byte[] bootSecret = null;
        byte[] material = null;
        boolean published = false;
        try {
            bootSecret = loadBootSecret(envelope);
            publishNativeShellBootSecret(bootSecret);
            material = decryptBootMaterial(envelope, bootSecret);
            validateAndPublishJavaBootMaterial(material, platformSuffix);
            published = true;
            if (!nativeInstallBootMaterial(material) || !nativeIsBootMaterialReady()) {
                throw new SecurityException("native boot material installation failed");
            }
            clearExpectedShellBindingCommitment();
            Arrays.fill(material, 4, 68, (byte) 0);
        } catch (Throwable error) {
            if (published) {
                clearJavaBootMaterial();
                try {
                    nativeAbortBootMaterial();
                } catch (Throwable ignored) {
                }
            }
            throw error;
        } finally {
            if (bootSecret != null) Arrays.fill(bootSecret, (byte) 0);
            if (material != null) Arrays.fill(material, (byte) 0);
            Arrays.fill(envelope, (byte) 0);
        }
    }

    private static byte[] readBootKekSidecarBinary() throws Exception {
        String explicitEnvironmentSecret = System.getenv(BOOT_SECRET_ENV);
        if (explicitEnvironmentSecret != null) {
            throw new SecurityException("hardened boot material requires JAVASHROUD_BOOT_SECRET_FILE_V1 or the embedded Boot KEK sidecar");
        }
        String fileName = System.getenv(BOOT_SECRET_FILE_ENV);
        byte[] bytes;
        if (fileName != null) {
            if (fileName.length() == 0) throw new SecurityException("Boot KEK sidecar file path is empty");
            try (InputStream in = new FileInputStream(fileName)) {
                bytes = readAll(in);
            }
        } else {
            try (InputStream in = resourceStream(EMBEDDED_BOOT_SECRET_RESOURCE)) {
                if (in == null) throw new SecurityException("Boot KEK sidecar is missing");
                bytes = readAll(in);
            }
        }
        byte[] encoded = null;
        byte[] binary = null;
        boolean accepted = false;
        try {
            boolean text = bytes.length >= BOOT_SIDECAR_TEXT_PREFIX.length;
            for (int index = 0; text && index < BOOT_SIDECAR_TEXT_PREFIX.length; index++) {
                text = bytes[index] == BOOT_SIDECAR_TEXT_PREFIX[index];
            }
            if (text) {
                encoded = Arrays.copyOfRange(bytes, BOOT_SIDECAR_TEXT_PREFIX.length, bytes.length);
                if (encoded.length == 0) throw new SecurityException("empty Boot KEK sidecar");
                try {
                    binary = Base64.getUrlDecoder().decode(encoded);
                } catch (IllegalArgumentException error) {
                    throw new SecurityException("Boot KEK sidecar encoding is invalid", error);
                }
            } else {
                binary = bytes.clone();
            }
            if (binary.length != 118 || !isBootKekSidecar(binary)) {
                throw new SecurityException("unsupported Boot KEK sidecar");
            }
            accepted = true;
            return binary;
        } finally {
            Arrays.fill(bytes, (byte) 0);
            if (encoded != null) Arrays.fill(encoded, (byte) 0);
            if (!accepted && binary != null) Arrays.fill(binary, (byte) 0);
        }
    }

    private static void prepareJavaBootMaterialForLoad(String platformSuffix) throws Exception {
        clearJavaBootMaterial();
        byte[] envelope;
        try (InputStream in = resourceStream(BOOT_MATERIAL_RESOURCE)) {
            if (in == null) throw new SecurityException("missing encrypted boot material envelope");
            envelope = readAll(in);
        }
        byte[] bootSecret = null;
        byte[] material = null;
        boolean published = false;
        try {
            bootSecret = loadBootSecret(envelope);
            // JNI_OnLoad decrypts the max shell before Java can invoke any native method.
            // Keep the validated KEK available for the fixed Java bridge until System.load returns.
            publishNativeShellBootSecret(bootSecret);
            material = decryptBootMaterial(envelope, bootSecret);
            validateAndPublishJavaBootMaterial(material, platformSuffix);
            published = true;
        } finally {
            if (!published) clearJavaBootMaterial();
            if (bootSecret != null) Arrays.fill(bootSecret, (byte) 0);
            if (material != null) Arrays.fill(material, (byte) 0);
            Arrays.fill(envelope, (byte) 0);
        }
    }

    private static byte[] loadBootSecret(byte[] bootEnvelope) throws Exception {
        String encoded = System.getenv(BOOT_SECRET_ENV);
        byte[] decoded;
        byte[] sidecarBinding = bootSidecarBinding(bootEnvelope);
        try {
            if (encoded != null) {
                if (sidecarBinding != null) throw new SecurityException("hardened boot material requires a sealed Boot KEK sidecar file");
                if (encoded.length() != 64) throw new SecurityException("boot KEK must be 64 hexadecimal characters");
                try {
                    decoded = hexToBytes(encoded);
                } catch (IllegalArgumentException error) {
                    throw new SecurityException("boot KEK must be hexadecimal", error);
                }
                if (decoded.length != 32) throw new SecurityException("boot KEK must be 32 bytes");
            } else {
                String fileName = System.getenv(BOOT_SECRET_FILE_ENV);
                byte[] bytes;
                if (fileName != null) {
                    if (fileName.length() == 0) throw new SecurityException("boot KEK sidecar file path is empty");
                    try (InputStream in = new FileInputStream(fileName)) {
                        bytes = readAll(in);
                    }
                } else {
                    try (InputStream in = resourceStream(EMBEDDED_BOOT_SECRET_RESOURCE)) {
                        if (in == null) throw new SecurityException("boot KEK is missing");
                        bytes = readAll(in);
                    }
                }
                try {
                    decoded = decodeBootSecretBytes(bytes, sidecarBinding);
                } catch (IllegalArgumentException error) {
                    throw new SecurityException("boot KEK sidecar or hexadecimal file is invalid", error);
                } finally {
                    Arrays.fill(bytes, (byte) 0);
                }
            }
        } finally {
            if (sidecarBinding != null) Arrays.fill(sidecarBinding, (byte) 0);
        }
        if (bootSecretEnvBindingEnabled) {
            try {
                decoded = unmaskBootSecret(decoded);
            } catch (SecurityException error) {
                Arrays.fill(decoded, (byte) 0);
                throw error;
            }
        }
        return decoded;
    }

    private static byte[] decodeBootSecretBytes(byte[] bytes, byte[] sidecarBinding) throws Exception {
        if (isBootKekSidecar(bytes)) {
            if (sidecarBinding == null) throw new SecurityException("sealed Boot KEK sidecar requires a hardened boot envelope");
            return decodeBootKekSidecar(bytes, sidecarBinding);
        }
        if (bytes.length == 32) {
            if (sidecarBinding != null) throw new SecurityException("hardened boot material rejects raw Boot KEK files");
            return bytes.clone();
        }
        if (sidecarBinding != null) throw new SecurityException("hardened boot material rejects hexadecimal Boot KEK files");
        if (bytes.length != 64) throw new SecurityException("boot KEK file must contain 32 raw bytes or 64 hexadecimal characters");
        return hexToBytes(bytes);
    }

    private static byte[] unmaskBootSecret(byte[] maskedKek) throws Exception {
        if (maskedKek == null || maskedKek.length != 32) {
            throw new SecurityException("masked boot KEK must be 32 bytes");
        }
        String fingerprint = nativeGetMachineFingerprint();
        if (fingerprint == null || fingerprint.length() == 0) {
            throw new SecurityException("boot KEK environment binding requires a machine fingerprint");
        }
        String[] expected = bootSecretExpectedFingerprints;
        boolean matched = false;
        for (String candidate : expected) {
            if (candidate != null && constantTimeStringEqual(fingerprint, candidate.trim())) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            throw new SecurityException("boot KEK environment binding mismatch");
        }
        byte[] fingerprintBytes = fingerprint.getBytes(StandardCharsets.UTF_8);
        byte[] mask = deriveBootEnvMask(fingerprintBytes);
        Arrays.fill(fingerprintBytes, (byte) 0);
        byte[] kek = new byte[32];
        for (int i = 0; i < 32; i++) {
            kek[i] = (byte) (maskedKek[i] ^ mask[i]);
        }
        Arrays.fill(mask, (byte) 0);
        return kek;
    }

    private static byte[] deriveBootEnvMask(byte[] fingerprintBytes) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0);
        try {
            mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
            mac.update("javashroud-boot-env-mask-v1".getBytes(StandardCharsets.US_ASCII));
            byte[] digest = mac.doFinal(fingerprintBytes);
            byte[] mask = Arrays.copyOf(digest, 32);
            Arrays.fill(digest, (byte) 0);
            return mask;
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static boolean constantTimeStringEqual(String a, String b) {
        if (a == null || b == null) return a == b;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        boolean equal;
        try {
            if (aBytes.length != bBytes.length) return false;
            int diff = 0;
            for (int i = 0; i < aBytes.length; i++) {
                diff |= (aBytes[i] ^ bBytes[i]) & 0xFF;
            }
            equal = diff == 0;
        } finally {
            Arrays.fill(aBytes, (byte) 0);
            Arrays.fill(bBytes, (byte) 0);
        }
        return equal;
    }

    private static byte[] bootSidecarBinding(byte[] envelope) {
        if (envelope == null || envelope.length < 4 + 2 + 32 + 1 + 12 + 4 + 16) return null;
        if ((envelope[0] & 0xFF) != 0x4A || (envelope[1] & 0xFF) != 0x53 ||
            (envelope[2] & 0xFF) != 0x42 || (envelope[3] & 0xFF) != 0x4D ||
            (envelope[4] & 0xFF) != HARDENED_BOOT_MATERIAL_VERSION || (envelope[5] & 0xFF) != 32) return null;
        return Arrays.copyOfRange(envelope, 6, 38);
    }

    private static boolean isBootKekSidecar(byte[] bytes) {
        if (bytes == null) return false;
        if (bytes.length >= BOOT_SIDECAR_TEXT_PREFIX.length) {
            boolean text = true;
            for (int index = 0; index < BOOT_SIDECAR_TEXT_PREFIX.length; index++) {
                text &= bytes[index] == BOOT_SIDECAR_TEXT_PREFIX[index];
            }
            if (text) return true;
        }
        return bytes.length >= 4 && (bytes[0] & 0xFF) == 0x4A && (bytes[1] & 0xFF) == 0x53 &&
            (bytes[2] & 0xFF) == 0x42 && (bytes[3] & 0xFF) == 0x4B;
    }

    private static byte[] decodeBootKekSidecar(byte[] bytes, byte[] expectedBinding) throws Exception {
        byte[] binary = null;
        byte[] encoded = null;
        byte[] header = null;
        byte[] binding = null;
        byte[] salt = null;
        byte[] nonce = null;
        byte[] keyMaterial = null;
        byte[] wrappingKey = null;
        byte[] aad = null;
        byte[] plaintext = null;
        boolean accepted = false;
        try {
            boolean text = bytes.length >= BOOT_SIDECAR_TEXT_PREFIX.length;
            for (int index = 0; text && index < BOOT_SIDECAR_TEXT_PREFIX.length; index++) {
                text = bytes[index] == BOOT_SIDECAR_TEXT_PREFIX[index];
            }
            if (text) {
                encoded = Arrays.copyOfRange(bytes, BOOT_SIDECAR_TEXT_PREFIX.length, bytes.length);
                if (encoded.length == 0) throw new SecurityException("empty Boot KEK sidecar");
                binary = Base64.getUrlDecoder().decode(encoded);
            } else {
                binary = bytes.clone();
            }
            if (binary.length != 118 || (binary[0] & 0xFF) != 0x4A || (binary[1] & 0xFF) != 0x53 ||
                (binary[2] & 0xFF) != 0x42 || (binary[3] & 0xFF) != 0x4B ||
                (binary[4] & 0xFF) != 1 || (binary[5] & 0xFF) != 0 ||
                (binary[6] & 0xFF) != 16 || (binary[7] & 0xFF) != 12 ||
                readSealedResourceLe16(binary, 8) != 48) {
                throw new SecurityException("unsupported Boot KEK sidecar");
            }
            header = Arrays.copyOfRange(binary, 0, 10);
            binding = Arrays.copyOfRange(binary, 10, 42);
            if (expectedBinding == null || expectedBinding.length != 32 || !MessageDigest.isEqual(binding, expectedBinding)) {
                throw new SecurityException("Boot KEK sidecar artifact binding mismatch");
            }
            salt = Arrays.copyOfRange(binary, 42, 58);
            nonce = Arrays.copyOfRange(binary, 58, 70);
            keyMaterial = concat(BOOT_SIDECAR_KEY_DOMAIN, salt);
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(expectedBinding, "HmacSHA256"));
            wrappingKey = mac.doFinal(keyMaterial);
            aad = concat(header, binding, salt, nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(wrappingKey, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            plaintext = cipher.doFinal(binary, 70, 48);
            if (plaintext.length != 32) throw new SecurityException("Boot KEK sidecar plaintext length mismatch");
            accepted = true;
            return plaintext;
        } catch (IllegalArgumentException error) {
            throw new SecurityException("Boot KEK sidecar encoding is invalid", error);
        } finally {
            if (binary != null) Arrays.fill(binary, (byte) 0);
            if (encoded != null) Arrays.fill(encoded, (byte) 0);
            if (header != null) Arrays.fill(header, (byte) 0);
            if (binding != null) Arrays.fill(binding, (byte) 0);
            if (salt != null) Arrays.fill(salt, (byte) 0);
            if (nonce != null) Arrays.fill(nonce, (byte) 0);
            if (keyMaterial != null) Arrays.fill(keyMaterial, (byte) 0);
            if (wrappingKey != null) Arrays.fill(wrappingKey, (byte) 0);
            if (aad != null) Arrays.fill(aad, (byte) 0);
            if (!accepted && plaintext != null) Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static byte[] decryptBootMaterial(byte[] envelope, byte[] bootSecret) throws Exception {
        if (envelope == null || envelope.length < 4 + 2 + 12 + 4 + 16 || bootSecret.length != 32) {
            throw new SecurityException("malformed boot material envelope");
        }
        int version = envelope[4] & 0xFF;
        if ((envelope[0] & 0xFF) != 0x4A || (envelope[1] & 0xFF) != 0x53 ||
            (envelope[2] & 0xFF) != 0x42 || (envelope[3] & 0xFF) != 0x4D ||
            (version != BOOT_MATERIAL_VERSION && version != HARDENED_BOOT_MATERIAL_VERSION)) {
            throw new SecurityException("unsupported boot material envelope");
        }
        byte[] sidecarBinding = null;
        int nonceLengthOffset = 5;
        if (version == HARDENED_BOOT_MATERIAL_VERSION) {
            int bindingLength = envelope[5] & 0xFF;
            if (bindingLength != 32 || 6 + bindingLength >= envelope.length) {
                throw new SecurityException("malformed hardened boot binding");
            }
            sidecarBinding = Arrays.copyOfRange(envelope, 6, 6 + bindingLength);
            nonceLengthOffset = 6 + bindingLength;
        }
        int nonceLength = envelope[nonceLengthOffset] & 0xFF;
        int nonceOffset = nonceLengthOffset + 1;
        if (nonceLength != 12 || nonceOffset + nonceLength + 4 > envelope.length) throw new SecurityException("malformed boot material nonce");
        int sealedLengthOffset = nonceOffset + nonceLength;
        int sealedLength = readSealedResourceLe32(envelope, sealedLengthOffset);
        int sealedOffset = sealedLengthOffset + 4;
        if (sealedLength < 16 || sealedOffset + sealedLength != envelope.length) throw new SecurityException("malformed boot material payload");
        byte[] nonce = Arrays.copyOfRange(envelope, nonceOffset, nonceOffset + nonceLength);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(bootSecret, "AES"), new GCMParameterSpec(128, nonce));
            if (version == HARDENED_BOOT_MATERIAL_VERSION) {
                cipher.updateAAD(HARDENED_BOOT_MATERIAL_AAD);
                cipher.updateAAD(sidecarBinding);
            } else {
                cipher.updateAAD(BOOT_MATERIAL_AAD);
            }
            return cipher.doFinal(envelope, sealedOffset, sealedLength);
        } catch (Exception error) {
            throw new SecurityException("boot material envelope authentication failed", error);
        } finally {
            Arrays.fill(nonce, (byte) 0);
            if (sidecarBinding != null) Arrays.fill(sidecarBinding, (byte) 0);
        }
    }

    private static void validateAndPublishJavaBootMaterial(byte[] material) {
        validateAndPublishJavaBootMaterial(material, detectPlatform());
    }

    private static synchronized void validateAndPublishJavaBootMaterial(byte[] material, String platformSuffix) {
        if (runtimeResourceKeys != null || expectedShellBindingCommitment != null) {
            throw new SecurityException("boot material is already installed");
        }
        int materialVersion = material == null || material.length == 0 ? -1 : material[0] & 0xFF;
        if (material == null || material.length < 4 + 64 + 64 ||
            (materialVersion != BOOT_MATERIAL_VERSION && materialVersion != HARDENED_BOOT_MATERIAL_VERSION)) {
            throw new SecurityException("malformed boot material");
        }
        int partitionCount = material[1] & 0xFF;
        int slotCount = material[2] & 0xFF;
        int bindingCount = material[3] & 0xFF;
        int expectedLength = 4 + 64 + slotCount * 32 + bindingCount * (1 + SHELL_BINDING_COMMITMENT_SIZE);
        if (partitionCount < 1 || partitionCount > NATIVE_ANCHOR_KEY_SLOT || slotCount != partitionCount + 1 ||
            bindingCount > 4 || material.length != expectedLength) {
            throw new SecurityException("invalid boot material key slots");
        }
        byte[][] keys = new byte[slotCount][];
        byte[] selectedBinding = null;
        boolean published = false;
        int offset = 4 + 64;
        try {
            for (int slot = 0; slot < slotCount; slot++) {
                keys[slot] = Arrays.copyOfRange(material, offset, offset + 32);
                offset += 32;
            }
            boolean[] seenPlatforms = new boolean[5];
            int currentPlatformId = shellBindingPlatformId(platformSuffix);
            for (int binding = 0; binding < bindingCount; binding++) {
                int platformId = material[offset++] & 0xFF;
                if (platformId < 1 || platformId > 4 || seenPlatforms[platformId]) {
                    throw new SecurityException("invalid native shell binding platform");
                }
                seenPlatforms[platformId] = true;
                byte[] commitment = Arrays.copyOfRange(material, offset, offset + SHELL_BINDING_COMMITMENT_SIZE);
                offset += SHELL_BINDING_COMMITMENT_SIZE;
                int nonzero = 0;
                for (byte value : commitment) nonzero |= value & 0xFF;
                if (nonzero == 0) {
                    Arrays.fill(commitment, (byte) 0);
                    throw new SecurityException("invalid native shell binding commitment");
                }
                if (platformId == currentPlatformId) {
                    selectedBinding = commitment;
                } else {
                    Arrays.fill(commitment, (byte) 0);
                }
            }
            if (bindingCount > 0 && selectedBinding == null) {
                throw new SecurityException("missing native shell binding for current platform");
            }
            runtimeResourcePartitionCount = partitionCount;
            anchorResourcePartition = partitionCount;
            runtimeResourceKeys = keys;
            expectedShellBindingCommitment = selectedBinding;
            expectedShellBindingThread = selectedBinding == null ? null : Thread.currentThread();
            shellBindingHandoffState = selectedBinding == null ? 0 : 1;
            published = true;
        } finally {
            if (!published) {
                for (byte[] key : keys) if (key != null) Arrays.fill(key, (byte) 0);
                if (selectedBinding != null) Arrays.fill(selectedBinding, (byte) 0);
            }
        }
    }

    private static synchronized void clearJavaBootMaterial() {
        byte[][] keys = runtimeResourceKeys;
        byte[] shellBinding = expectedShellBindingCommitment;
        runtimeResourceKeys = null;
        runtimeResourcePartitionCount = 0;
        anchorResourcePartition = -1;
        expectedShellBindingCommitment = null;
        expectedShellBindingThread = null;
        shellBindingHandoffState = 0;
        if (keys != null) for (byte[] key : keys) if (key != null) Arrays.fill(key, (byte) 0);
        if (shellBinding != null) Arrays.fill(shellBinding, (byte) 0);
        clearNativeShellBootSecret();
    }

    private static synchronized void publishNativeShellBootSecret(byte[] bootSecret) {
        clearNativeShellBootSecret();
        if (bootSecret == null || bootSecret.length != 32) {
            throw new SecurityException("native shell boot secret must be 32 bytes");
        }
        nativeShellBootSecret = Arrays.copyOf(bootSecret, bootSecret.length);
        nativeShellBootSecretThread = Thread.currentThread();
    }

    private static synchronized void clearNativeShellBootSecret() {
        byte[] secret = nativeShellBootSecret;
        nativeShellBootSecret = null;
        nativeShellBootSecretThread = null;
        if (secret != null) Arrays.fill(secret, (byte) 0);
    }

    /* Fixed JNI_OnLoad bridge. The max shell uses this only when no external
     * Boot KEK environment variable/file was supplied. */
    private static synchronized byte[] takeBootSecretForNativeShell() {
        if (nativeShellBootSecret == null || nativeShellBootSecretThread != Thread.currentThread()) return null;
        byte[] secret = nativeShellBootSecret;
        nativeShellBootSecret = null;
        nativeShellBootSecretThread = null;
        byte[] result = Arrays.copyOf(secret, secret.length);
        Arrays.fill(secret, (byte) 0);
        return result;
    }

    private static synchronized void clearExpectedShellBindingCommitment() {
        byte[] shellBinding = expectedShellBindingCommitment;
        expectedShellBindingCommitment = null;
        expectedShellBindingThread = null;
        shellBindingHandoffState = 0;
        if (shellBinding != null) Arrays.fill(shellBinding, (byte) 0);
    }

    /* Fixed JNI_OnLoad bridge. Runtime sealing must keep this name and descriptor stable. */
    private static synchronized byte[] takeExpectedShellBindingCommitment() {
        if (shellBindingHandoffState != 1 || expectedShellBindingThread != Thread.currentThread()) return null;
        byte[] shellBinding = expectedShellBindingCommitment;
        expectedShellBindingCommitment = null;
        if (shellBinding == null) return null;
        byte[] result = Arrays.copyOf(shellBinding, shellBinding.length);
        Arrays.fill(shellBinding, (byte) 0);
        shellBindingHandoffState = 2;
        return result;
    }

    private static synchronized void verifyShellBindingHandoffAfterLoad() {
        if (shellBindingHandoffState == 0) return;
        if (shellBindingHandoffState != 2 || expectedShellBindingCommitment != null ||
            expectedShellBindingThread != Thread.currentThread()) {
            throw new SecurityException("native shell did not consume the boot binding commitment");
        }
        expectedShellBindingThread = null;
        shellBindingHandoffState = 0;
    }

    private static int shellBindingPlatformId(String platform) {
        if ("windows-x64".equals(platform)) return 1;
        if ("linux-x64".equals(platform)) return 2;
        if ("macos-x64".equals(platform)) return 3;
        if ("macos-arm64".equals(platform)) return 4;
        return 0;
    }

    /* ---- Platform detection ---- */

    private static String detectPlatform() {
        return detectPlatform(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
    }

    private static String detectPlatform(String osName, String osArch) {
        String normalizedOs = osName == null ? "" : osName.trim().toLowerCase(Locale.ROOT);
        String normalizedArch = osArch == null ? "" : osArch.trim().toLowerCase(Locale.ROOT);
        boolean x64 = "amd64".equals(normalizedArch) || "x86_64".equals(normalizedArch) || "x64".equals(normalizedArch);
        boolean arm64 = "aarch64".equals(normalizedArch) || "arm64".equals(normalizedArch);
        boolean windows = "windows".equals(normalizedOs) || normalizedOs.startsWith("windows ");
        boolean linux = "linux".equals(normalizedOs) || normalizedOs.startsWith("linux ");
        boolean macos = "macos".equals(normalizedOs) || "mac os x".equals(normalizedOs) || normalizedOs.startsWith("mac os ");
        if (windows) return x64 ? "windows-x64" : null;
        if (linux) return x64 ? "linux-x64" : null;
        if (macos && x64) return "macos-x64";
        if (macos && arm64) return "macos-arm64";
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

    private static boolean tryLoadBundledNative(String platformSuffix, String components) {
        SealedNativeLibrary[] sealedLibraries = sealedBundledLibraryNames(platformSuffix);
        for (SealedNativeLibrary sealedLibrary : sealedLibraries) {
            if (tryLoadBundledNativeResource(platformSuffix, sealedLibrary.resourcePath, sealedLibrary.fileSuffix)) return true;
        }
        return false;
    }

    private static boolean tryLoadBundledNativeResource(String platformSuffix, String resourcePath, String suffix) {
        byte[] nativeBytes;
        try (InputStream in = resourceStream(resourcePath)) {
            if (in == null) return false;
            nativeBytes = decodeSealedNativeResource(readAll(in));
        } catch (Exception e) {
            loadMessage = debugNativeLoadMessage("native-resource-error:" + resourcePath, e);
            return false;
        }
        if (nativeBytes == null || nativeBytes.length == 0) return false;
        try {
            for (File extractDirectory : nativeExtractDirectories()) {
                if (tryLoadBundledNativeFromDirectory(platformSuffix, resourcePath, suffix, nativeBytes, extractDirectory)) return true;
            }
            return false;
        } finally {
            Arrays.fill(nativeBytes, (byte) 0);
        }
    }

    private static boolean tryLoadBundledNativeFromDirectory(String platformSuffix, String resourcePath, String suffix, byte[] nativeBytes, File extractDirectory) {
        File tempLib = null;
        String previousLoaderOwner = System.getProperty(sealedLoaderPropertyName());
        String previousClassBindings = System.getProperty(sealedBindingPropertyName());
        String previousMethodBindings = System.getProperty(sealedMethodBindingPropertyName());
        String previousFieldBindings = System.getProperty(sealedFieldBindingPropertyName());
        boolean previousBootSecretEnvBindingEnabled = bootSecretEnvBindingEnabled;
        String[] previousBootSecretExpectedFingerprints = bootSecretExpectedFingerprints == null
            ? new String[0]
            : bootSecretExpectedFingerprints.clone();
        boolean ok = false;
        try {
            if (!ensureNativeExtractDirectory(extractDirectory)) return false;
            /* File.createTempFile has a one-time multi-second init path on
             * Java 8 (Windows); build the unique name directly instead. */
            tempLib = createUniqueTempFile(nativeTempPrefix(resourcePath), suffix, extractDirectory);
            tempLib.deleteOnExit();
            try (FileOutputStream out = new FileOutputStream(tempLib)) {
                out.write(nativeBytes);
            }
            tempLib.setReadable(true, true);
            tempLib.setWritable(true, true);
            tempLib.setExecutable(true, true);
            prepareJavaBootMaterialForLoad(platformSuffix);
            publishSealedNativeBindings();
            sealedNativeBindingsPublished = true;
            System.load(tempLib.getAbsolutePath());
            verifyShellBindingHandoffAfterLoad();
            loadMessage = "native:bundled:" + platformSuffix + ":" + initializeNativeKernel(platformSuffix);
            installBootMaterialIntoNative(platformSuffix);
            try {
                preloadRuntimeResourcesIntoNative();
                if (verifyNativeAbiAfterLoad()) {
                    verifyBootTokenAfterLoad(platformSuffix);
                    ok = !nativeSelfCheckFailed;
                }
                return ok;
            } finally {
                clearJavaBootMaterial();
                if (!ok) {
                    sealedNativeBindingsPublished = false;
                }
            }
        } catch (UnsatisfiedLinkError e) {
            loadMessage = debugNativeLoadMessage("native:bundled-load-error", e);
            if (tempLib != null) tempLib.delete();
            return false;
        } catch (Exception e) {
            loadMessage = "native:bundled-init-error:" + e.getClass().getName() + ":" + String.valueOf(e.getMessage());
            if (tempLib != null) tempLib.delete();
            return false;
        } finally {
            if (!ok) {
                clearJavaBootMaterial();
                try {
                    nativeAbortBootMaterial();
                } catch (Throwable ignored) {
                }
                sealedNativeBindingsPublished = false;
                bootSecretEnvBindingEnabled = previousBootSecretEnvBindingEnabled;
                String[] currentBootSecretExpectedFingerprints = bootSecretExpectedFingerprints;
                bootSecretExpectedFingerprints = previousBootSecretExpectedFingerprints;
                if (currentBootSecretExpectedFingerprints != null &&
                    currentBootSecretExpectedFingerprints != previousBootSecretExpectedFingerprints) {
                    Arrays.fill(currentBootSecretExpectedFingerprints, null);
                }
                restoreLoaderProperty(previousLoaderOwner);
                restoreProperty(sealedBindingPropertyName(), previousClassBindings);
                restoreProperty(sealedMethodBindingPropertyName(), previousMethodBindings);
                restoreProperty(sealedFieldBindingPropertyName(), previousFieldBindings);
            }
        }
    }

    private static int initializeNativeKernel(String platformSuffix) {
        int result = nativeInit(platformSuffix);
        return result == 2 ? nativeInit(platformSuffix) : result;
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

    private static void publishSealedNativeBindings() {
        publishSealedNativeBindings(null);
    }

    private static void publishSealedNativeBindings(AkenNativeLibrary locator) {
        if (locator == null) throw new SecurityException("AKEN native bindings require an active locator");
        try {
            publishSealedNativeLoaderOwner();
            String bindingText = sealedNativeBindingText(locator);
            if (bindingText == null || bindingText.length() == 0) {
                throw new SecurityException("AKEN native bindings are unavailable");
            }
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

    private static void ensureSealedNativeBindingsPublished() {
        if (sealedNativeBindingsPublished) return;
        publishSealedNativeBindings();
        sealedNativeBindingsPublished = true;
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

    private static String legacySealedNativeBindingsResource() {
        return new String(new char[]{'M','E','T','A','-','I','N','F','/','.','r','/','b','i','n','d','i','n','g','s','.','d','a','t'});
    }

    private static String sealedNativeIndexText() {
        try (InputStream in = resourceStream(SEALED_NATIVE_INDEX_RESOURCE)) {
            if (in == null) return null;
            byte[] raw = readAll(in);
            byte[] decoded = null;
            try {
                decoded = hasRuntimeResourceHeader(raw)
                    ? decodeRuntimeResource(raw, true)
                    : isAscii(raw) ? raw.clone() : null;
                return decoded == null ? null : new String(decoded, StandardCharsets.UTF_8);
            } finally {
                Arrays.fill(raw, (byte) 0);
                if (decoded != null) Arrays.fill(decoded, (byte) 0);
            }
        } catch (Exception ignored) {
            return null;
        }
    }

    private static String sealedNativeBindingText() {
        return sealedNativeBindingText(null);
    }

    private static String sealedNativeBindingText(AkenNativeLibrary locator) {
        String resourcePath = locator == null ? SEALED_NATIVE_BINDINGS_RESOURCE : locator.bindingResourcePath;
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

    private static SealedNativeLibrary[] sealedBundledLibraryNames(String platformSuffix) {
        try {
            String index = sealedNativeIndexText();
            if (index == null || index.length() == 0) return new SealedNativeLibrary[0];
            LinkedHashSet<SealedNativeLibrary> libraries = new LinkedHashSet<>();
            String[] lines = index.split("\n");
            for (String line : lines) {
                String[] parts = line.trim().split("\\|", -1);
                if (parts.length != 3 || !platformSuffix.equals(parts[0])) continue;
                libraries.add(new SealedNativeLibrary(parts[1], parts[2]));
            }
            return libraries.toArray(new SealedNativeLibrary[0]);
        } catch (Exception ignored) {
            return new SealedNativeLibrary[0];
        }
    }

    private static byte[] decodeSealedNativeResource(byte[] raw) {
        if (raw == null || raw.length == 0 || hasRuntimeResourceHeader(raw)) return null;
        return raw;
    }

    private static byte[] hexToBytes(String hex) {
        if ((hex.length() & 1) != 0) throw new IllegalArgumentException("odd hex");
        byte[] out = new byte[hex.length() / 2];
        for (int index = 0; index < out.length; index++) {
            int hi = Character.digit(hex.charAt(index * 2), 16);
            int lo = Character.digit(hex.charAt(index * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                Arrays.fill(out, (byte) 0);
                throw new IllegalArgumentException("bad hex");
            }
            out[index] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    private static byte[] hexToBytes(byte[] hex) {
        if ((hex.length & 1) != 0) throw new IllegalArgumentException("odd hex");
        byte[] out = new byte[hex.length / 2];
        for (int index = 0; index < out.length; index++) {
            int hi = Character.digit((char) (hex[index * 2] & 0xFF), 16);
            int lo = Character.digit((char) (hex[index * 2 + 1] & 0xFF), 16);
            if (hi < 0 || lo < 0) {
                Arrays.fill(out, (byte) 0);
                throw new IllegalArgumentException("bad hex");
            }
            out[index] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static byte[] decodeRuntimeResourceForNative(byte[] raw) {
        byte[] decoded;
        if (loadState == LOAD_READY && nativeIsBootMaterialReady()) {
            try {
                decoded = nativeDecodeRuntimeResource(raw);
            } catch (LinkageError ignored) {
                decoded = null;
            }
            // Keep manifest discovery self-contained when an older shell or a
            // platform build does not expose the optional native resource
            // decoder. The same authenticated partition keys and hashes are
            // checked by the Java fallback; a tampered envelope still fails
            // closed rather than being accepted by the fallback.
            if (decoded == null) decoded = decodeRuntimeResource(raw);
        } else {
            decoded = decodeRuntimeResource(raw);
        }
        if (decoded == null) throw new IllegalArgumentException("unsupported runtime resource envelope");
        return decoded;
    }

    private static int runtimeResourcePartitionCount() {
        return runtimeResourcePartitionCount;
    }

    private static int anchorResourcePartition() {
        return anchorResourcePartition;
    }

    private static byte[] partitionResourceKey(int partitionId) {
        byte[][] keys = runtimeResourceKeys;
        if (keys == null || partitionId < 0 || partitionId >= keys.length) throw new SecurityException("runtime key slot unavailable");
        return keys[partitionId].clone();
    }

    public static byte[] decodeRuntimeResourceEnvelope(byte[] raw) {
        return loadState == LOAD_READY && nativeIsBootMaterialReady()
            ? nativeDecodeRuntimeResource(raw)
            : decodeRuntimeResource(raw);
    }

    private static byte[] decodeRuntimeResource(byte[] raw) {
        return decodeRuntimeResource(raw, true);
    }

    private static byte[] decodeRuntimeResource(byte[] raw, boolean allowCompressed) {
        if (!hasRuntimeResourceHeader(raw)) return null;
        return decodeRuntimeResourceCurrent(raw, allowCompressed);
    }

    private static boolean hasRuntimeResourceHeader(byte[] raw) {
        return raw != null && raw.length >= 5 &&
            raw[0] == 0x4A && raw[1] == 0x53 && raw[2] == 0x52 && raw[3] == 0x50 &&
            (raw[4] & 0xFF) == RUNTIME_RESOURCE_VERSION;
    }

    private static byte[] decodeRuntimeResourceCurrent(byte[] raw, boolean allowCompressed) {
        if (raw.length < RUNTIME_RESOURCE_HEADER_SIZE + 96 + 32 + 1 || (raw[raw.length - 1] & 0xFF) != 32) return null;
        byte[] nonce = Arrays.copyOfRange(raw, 5, 21);
        int metadataLength = readSealedResourceLe16(raw, 21);
        int macLength = readSealedResourceLe16(raw, 23);
        int partitionId = readSealedResourceLe16(raw, 25);
        if (metadataLength != 96 || macLength != 32) return null;
        if (partitionId < 0 || partitionId > anchorResourcePartition()) return null;
        int metadataOffset = RUNTIME_RESOURCE_HEADER_SIZE;
        int bodyOffset = metadataOffset + metadataLength;
        if (bodyOffset + 33 > raw.length) return null;
        int tagOffset = raw.length - 33;
        byte[] resourceKey = partitionResourceKey(partitionId);
        try {
            byte[] expected = hmacSha256(resourceKey, concat("jsrp-auth-v3".getBytes(StandardCharsets.US_ASCII), nonce, Arrays.copyOfRange(raw, 0, tagOffset)));
            if (!constantTimeEquals(expected, raw, tagOffset)) return null;
            byte[] metadata = runtimeResourceAesCtrWithDomains(
                resourceKey,
                Arrays.copyOfRange(raw, metadataOffset, bodyOffset),
                nonce,
                intBytes(0),
                intBytes(0),
                intBytes(0)
            );
            RuntimeResourceMetadata parsed = parseRuntimeResourceMetadata(metadata);
            if (parsed == null) return null;
            if (parsed.partitionId != partitionId) return null;
            if (parsed.kindId < 1 || parsed.kindId > 4) return null;
            if (parsed.layerCount < 1 || parsed.layerCount > 7 || parsed.variantId > 127) return null;
            if (parsed.plainLength < 0 || parsed.storedLength < 0 || parsed.bodyLength < 0) return null;
            if (bodyOffset + parsed.bodyLength != tagOffset) return null;
            byte[] body = Arrays.copyOfRange(raw, bodyOffset, tagOffset);
            byte[] stored = runtimeResourceAesCtr(resourceKey, body, nonce, parsed.kindId, parsed.variantId, parsed.layerCount);
            if (stored.length != parsed.storedLength) return null;
            if (!Arrays.equals(sha256(stored), parsed.storedHash)) return null;
            byte[] plain = parsed.compressed ? (allowCompressed ? decompressEmbeddedZstd(stored, parsed.plainLength) : null) : stored;
            if (plain == null || plain.length != parsed.plainLength) return null;
            return Arrays.equals(sha256(plain), parsed.plainHash) ? plain : null;
        } finally {
            Arrays.fill(resourceKey, (byte) 0);
        }
    }

    private static byte[] decompressEmbeddedZstd(byte[] bytes, int expectedLength) {
        if (expectedLength < 0 || bytes == null || bytes.length < 7) return null;
        int offset = 0;
        if (readSealedResourceLe32(bytes, offset) != ZSTD_MAGIC) return null;
        offset += 4;
        int descriptor = bytes[offset++] & 0xFF;
        if ((descriptor & 0x08) != 0 || (descriptor & 0x03) != 0) return null;
        int frameContentSizeFlag = descriptor >>> 6;
        boolean singleSegment = (descriptor & 0x20) != 0;
        boolean checksum = (descriptor & 0x04) != 0;
        if (!singleSegment) {
            if (offset >= bytes.length) return null;
            offset++;
        }
        int contentSizeLength;
        if (frameContentSizeFlag == 0) contentSizeLength = singleSegment ? 1 : 0;
        else if (frameContentSizeFlag == 1) contentSizeLength = 2;
        else if (frameContentSizeFlag == 2) contentSizeLength = 4;
        else contentSizeLength = 8;
        long declaredLength = readZstdFrameContentSize(bytes, offset, contentSizeLength);
        if (declaredLength != expectedLength) return null;
        offset += contentSizeLength;
        ByteArrayOutputStream out = new ByteArrayOutputStream(expectedLength);
        boolean sawLast = false;
        while (!sawLast) {
            if (offset + 3 > bytes.length) return null;
            int header = (bytes[offset] & 0xFF) | ((bytes[offset + 1] & 0xFF) << 8) | ((bytes[offset + 2] & 0xFF) << 16);
            offset += 3;
            sawLast = (header & 1) != 0;
            int blockType = (header >>> 1) & 0x03;
            int blockSize = header >>> 3;
            if (blockType == 0) {
                if (offset + blockSize > bytes.length) return null;
                out.write(bytes, offset, blockSize);
                offset += blockSize;
            } else if (blockType == 1) {
                if (offset >= bytes.length) return null;
                for (int i = 0; i < blockSize; i++) out.write(bytes[offset] & 0xFF);
                offset++;
            } else {
                return null;
            }
            if (out.size() > expectedLength) return null;
        }
        if (checksum) {
            if (offset + 4 > bytes.length) return null;
            offset += 4;
        }
        if (offset != bytes.length || out.size() != expectedLength) return null;
        return out.toByteArray();
    }

    private static long readZstdFrameContentSize(byte[] bytes, int offset, int length) {
        if (length < 0 || length > 8 || offset < 0 || offset + length > bytes.length) return -1L;
        long value = 0L;
        for (int i = 0; i < length; i++) value |= (long)(bytes[offset + i] & 0xFF) << (8 * i);
        return length == 2 ? value + 256L : value;
    }

    private static byte[] runtimeResourceAesCtr(byte[] resourceKey, byte[] bytes, byte[] nonce, int kindId, int variantId, int layerCount) {
        return runtimeResourceAesCtrWithDomains(resourceKey, bytes, nonce, intBytes(kindId), intBytes(variantId), intBytes(layerCount));
    }

    private static byte[] runtimeResourceAesCtrWithDomains(byte[] resourceKey, byte[] bytes, byte[] nonce, byte[] kindBytes, byte[] variantBytes, byte[] layerBytes) {
        try {
            byte[] key = Arrays.copyOfRange(hmacSha256(resourceKey, concat(
                "jsrp-aes-key".getBytes(StandardCharsets.US_ASCII),
                nonce,
                kindBytes,
                variantBytes,
                layerBytes
            )), 0, 16);
            byte[] iv = Arrays.copyOfRange(hmacSha256(resourceKey, concat(
                "jsrp-aes-iv".getBytes(StandardCharsets.US_ASCII),
                nonce,
                kindBytes,
                variantBytes,
                layerBytes
            )), 0, 16);
            return aesCtrCrypt(key, iv, bytes);
        } catch (Exception ignored) {
            return new byte[0];
        }
    }

    private static RuntimeResourceMetadata parseRuntimeResourceMetadata(byte[] bytes) {
        if (bytes == null || bytes.length != 96) return null;
        if (bytes[0] != 0x4D || bytes[1] != 0x32 || bytes[2] != 1) return null;
        int flags = bytes[6] & 0xFF;
        if ((flags & 0xFE) != 0) return null;
        int expected = readSealedResourceBe32(sha256(Arrays.copyOfRange(bytes, 0, 92)), 0);
        if (readSealedResourceLe32(bytes, 92) != expected) return null;
        RuntimeResourceMetadata parsed = new RuntimeResourceMetadata();
        parsed.kindId = bytes[3] & 0xFF;
        parsed.layerCount = bytes[4] & 0xFF;
        parsed.variantId = bytes[5] & 0xFF;
        parsed.compressed = (flags & 1) != 0;
        parsed.plainLength = readSealedResourceLe32(bytes, 8);
        parsed.storedLength = readSealedResourceLe32(bytes, 12);
        parsed.bodyLength = readSealedResourceLe32(bytes, 16);
        parsed.partitionId = bytes[7] & 0xFF;
        parsed.keyId = readSealedResourceLe32(bytes, 20);
        parsed.seed = readSealedResourceLe32(bytes, 24);
        parsed.plainHash = Arrays.copyOfRange(bytes, 28, 60);
        parsed.storedHash = Arrays.copyOfRange(bytes, 60, 92);
        return parsed;
    }


    /* Pure-Java AES-128 block cipher (encrypt direction only) plus CTR mode.
     * Byte layout follows FIPS-197: state column c holds bytes in[4c..4c+3]. */
    private static final int[] AES_RCON = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36 };
    private static byte[] aesSboxTable;

    private static int aesXtime(int x) {
        return ((x << 1) ^ ((x & 0x80) != 0 ? 0x1B : 0)) & 0xFF;
    }

    private static byte[] aesSbox() {
        if (aesSboxTable != null) return aesSboxTable;
        byte[] sbox = new byte[256];
        int[] log = new int[256];
        int[] exp = new int[255];
        int x = 1;
        for (int i = 0; i < 255; i++) {
            exp[i] = x;
            log[x] = i;
            x = (x << 1) ^ x ^ ((x & 0x80) != 0 ? 0x1B : 0);
            x &= 0xFF;
        }
        sbox[0] = 0x63;
        for (int i = 1; i < 256; i++) {
            int inv = exp[(255 - log[i]) % 255];
            int s = inv;
            s ^= ((inv << 1) | (inv >>> 7)) & 0xFF;
            s ^= ((inv << 2) | (inv >>> 6)) & 0xFF;
            s ^= ((inv << 3) | (inv >>> 5)) & 0xFF;
            s ^= ((inv << 4) | (inv >>> 4)) & 0xFF;
            sbox[i] = (byte) (s ^ 0x63);
        }
        aesSboxTable = sbox;
        return sbox;
    }

    private static int[] aesExpandKey(byte[] key, byte[] sbox) {
        int[] rk = new int[44];
        for (int i = 0; i < 4; i++) {
            rk[i] = ((key[4 * i] & 0xFF) << 24) | ((key[4 * i + 1] & 0xFF) << 16)
                    | ((key[4 * i + 2] & 0xFF) << 8) | (key[4 * i + 3] & 0xFF);
        }
        for (int i = 4; i < 44; i++) {
            int t = rk[i - 1];
            if (i % 4 == 0) {
                int rot = (t << 8) | (t >>> 24);
                t = ((sbox[(rot >>> 24) & 0xFF] & 0xFF) << 24) | ((sbox[(rot >>> 16) & 0xFF] & 0xFF) << 16)
                        | ((sbox[(rot >>> 8) & 0xFF] & 0xFF) << 8) | (sbox[rot & 0xFF] & 0xFF);
                t ^= AES_RCON[i / 4 - 1] << 24;
            }
            rk[i] = rk[i - 4] ^ t;
        }
        return rk;
    }

    private static int aesMixColumn(int b0, int b1, int b2, int b3, int row) {
        switch (row) {
            case 0: return aesXtime(b0) ^ (aesXtime(b1) ^ b1) ^ b2 ^ b3;
            case 1: return b0 ^ aesXtime(b1) ^ (aesXtime(b2) ^ b2) ^ b3;
            case 2: return b0 ^ b1 ^ aesXtime(b2) ^ (aesXtime(b3) ^ b3);
            default: return (aesXtime(b0) ^ b0) ^ b1 ^ b2 ^ aesXtime(b3);
        }
    }

    private static void aesEncryptBlock(int[] rk, byte[] sbox, byte[] in, int inOff, byte[] out, int outOff) {
        int[] s = new int[4];
        for (int c = 0; c < 4; c++) {
            s[c] = ((in[inOff + 4 * c] & 0xFF) << 24) | ((in[inOff + 4 * c + 1] & 0xFF) << 16)
                    | ((in[inOff + 4 * c + 2] & 0xFF) << 8) | (in[inOff + 4 * c + 3] & 0xFF);
            s[c] ^= rk[c];
        }
        for (int round = 1; round < 10; round++) {
            int[] t = new int[4];
            for (int c = 0; c < 4; c++) {
                int b0 = sbox[(s[c] >>> 24) & 0xFF] & 0xFF;
                int b1 = sbox[(s[(c + 1) & 3] >>> 16) & 0xFF] & 0xFF;
                int b2 = sbox[(s[(c + 2) & 3] >>> 8) & 0xFF] & 0xFF;
                int b3 = sbox[s[(c + 3) & 3] & 0xFF] & 0xFF;
                t[c] = (aesMixColumn(b0, b1, b2, b3, 0) << 24) | (aesMixColumn(b0, b1, b2, b3, 1) << 16)
                        | (aesMixColumn(b0, b1, b2, b3, 2) << 8) | aesMixColumn(b0, b1, b2, b3, 3);
            }
            for (int c = 0; c < 4; c++) s[c] = t[c] ^ rk[round * 4 + c];
        }
        for (int c = 0; c < 4; c++) {
            int b0 = sbox[(s[c] >>> 24) & 0xFF] & 0xFF;
            int b1 = sbox[(s[(c + 1) & 3] >>> 16) & 0xFF] & 0xFF;
            int b2 = sbox[(s[(c + 2) & 3] >>> 8) & 0xFF] & 0xFF;
            int b3 = sbox[s[(c + 3) & 3] & 0xFF] & 0xFF;
            int v = ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) ^ rk[40 + c];
            out[outOff + 4 * c] = (byte) (v >>> 24);
            out[outOff + 4 * c + 1] = (byte) (v >>> 16);
            out[outOff + 4 * c + 2] = (byte) (v >>> 8);
            out[outOff + 4 * c + 3] = (byte) v;
        }
    }

    private static byte[] aesCtrCrypt(byte[] key, byte[] iv, byte[] data) {
        byte[] sbox = aesSbox();
        int[] rk = aesExpandKey(key, sbox);
        byte[] counter = iv.clone();
        byte[] stream = new byte[16];
        byte[] out = new byte[data.length];
        int offset = 0;
        while (offset < data.length) {
            aesEncryptBlock(rk, sbox, counter, 0, stream, 0);
            int take = Math.min(16, data.length - offset);
            for (int i = 0; i < take; i++) out[offset + i] = (byte) (data[offset + i] ^ stream[i]);
            offset += take;
            for (int i = 15; i >= 0; i--) {
                counter[i] = (byte) (counter[i] + 1);
                if (counter[i] != 0) break;
            }
        }
        Arrays.fill(stream, (byte) 0);
        return out;
    }

    private static byte[] hmacSha256(byte[] data) {
        byte[] key = partitionResourceKey(anchorResourcePartition());
        try {
            return hmacSha256(key, data);
        } finally {
            Arrays.fill(key, (byte) 0);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            /* javax.crypto provider jars trigger JarVerifier.getSystemEntropy
             * (network adapter enumeration) on first use under Java 8, which
             * stalls startup badly on hosts with many virtual adapters. HMAC
             * over java.security.MessageDigest stays on the boot-class SUN
             * provider and avoids that path entirely. */
            byte[] k = key.length > 64 ? sha256(key) : key;
            byte[] ipad = new byte[64];
            byte[] opad = new byte[64];
            for (int i = 0; i < 64; i++) {
                byte b = i < k.length ? k[i] : 0;
                ipad[i] = (byte) (b ^ 0x36);
                opad[i] = (byte) (b ^ 0x5c);
            }
            return sha256(concat(opad, sha256(concat(ipad, data))));
        } catch (Exception ignored) {
            return new byte[32];
        }
    }

    /**
     * Derive a per-build class-encryption AES key from the resident per-build
     * runtime resource root key. The derivation (HKDF-SHA256, RFC 5869) runs
     * entirely inside the sealed native kernel, so neither the derivation logic
     * nor the root key ever exists in distributable Java bytecode. Fail-closed:
     * without the native kernel there is no Java fallback.
     */
    public static byte[] deriveClassEncryptionKey(byte[] keyId, byte[] salt, int length) {
        if (!isNativeLoaded()) {
            loadKernel("loader", "auto", "vm-diverse");
        }
        if (!isNativeLoaded()) {
            throw new SecurityException("class-encryption key derivation requires the sealed native kernel; no Java fallback (" + loadMessage + ")");
        }
        return nativeDeriveClassEncryptionKey(keyId, salt, length);
    }

    public static byte[] decryptClassBytes(byte[] keyId, byte[] salt, byte[] nonce, byte[] ciphertext, byte[] aad, int keyLength) {
        if (keyId == null || salt == null || nonce == null || ciphertext == null || aad == null) {
            throw new SecurityException("encrypted class metadata is incomplete");
        }
        if (nonce.length != 12 || ciphertext.length < 16 || (keyLength != 16 && keyLength != 32)) {
            throw new SecurityException("encrypted class metadata is invalid");
        }
        if (!isNativeLoaded()) loadKernel("loader", "auto", "vm-diverse");
        if (!isNativeLoaded()) {
            throw new SecurityException("class-encryption decryption requires the sealed native kernel; no Java fallback (" + loadMessage + ")");
        }
        try {
            byte[] result = nativeDecryptClassBytes(keyId, salt, nonce, ciphertext, aad, keyLength);
            if (result == null) throw new SecurityException("native class decryption returned no plaintext");
            return result;
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("class-encryption native decoder is not registered for the sealed helper", error);
        }
    }

    private static boolean isDecimal(String value) {
        if (value == null || value.length() == 0 || value.length() > 10) return false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    private static int parsePositiveInt(String value, String label) {
        if (!isDecimal(value)) throw new SecurityException("invalid VM catalog " + label);
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 0) throw new SecurityException("invalid VM catalog " + label);
            return parsed;
        } catch (NumberFormatException e) {
            throw new SecurityException("invalid VM catalog " + label, e);
        }
    }

    private static int lastIndexOf(byte[] data, byte[] needle) {
        if (data == null || needle == null || needle.length == 0 || needle.length > data.length) return -1;
        for (int offset = data.length - needle.length; offset >= 0; offset--) {
            boolean match = true;
            for (int index = 0; index < needle.length; index++) {
                if (data[offset + index] != needle[index]) {
                    match = false;
                    break;
                }
            }
            if (match) return offset;
        }
        return -1;
    }

    private static boolean hasPartitionedRuntimeResourceHeader(byte[] raw, int partitionId) {
        return raw != null && raw.length >= RUNTIME_RESOURCE_HEADER_SIZE && hasRuntimeResourceHeader(raw) &&
            readSealedResourceLe16(raw, 25) == partitionId;
    }

    private static byte[] vmCatalogLeaf(
        byte[] catalogId,
        int partitionId,
        String logicalPath,
        String storagePath,
        int rawLength,
        byte[] rawDigest
    ) {
        return sha256(concat(
            "JSL1".getBytes(StandardCharsets.US_ASCII),
            catalogId,
            intBytes(partitionId),
            frame(logicalPath),
            frame(storagePath),
            longBytes(rawLength),
            rawDigest
        ));
    }

    private static byte[] vmCatalogMerkleRoot(List<byte[]> leaves, byte[] catalogId, int partitionId) {
        if (leaves.isEmpty()) {
            return sha256(concat("JSP1".getBytes(StandardCharsets.US_ASCII), catalogId, intBytes(partitionId)));
        }
        List<byte[]> level = new ArrayList<>(leaves);
        sortByteArrays(level);
        while (level.size() > 1) {
            List<byte[]> next = new ArrayList<>((level.size() + 1) / 2);
            for (int index = 0; index < level.size(); index += 2) {
                byte[] left = level.get(index);
                byte[] right = index + 1 < level.size() ? level.get(index + 1) : left;
                next.add(sha256(concat("JSP1".getBytes(StandardCharsets.US_ASCII), left, right)));
            }
            level = next;
        }
        return level.get(0);
    }

    private static byte[] vmCatalogRoot(byte[] catalogId, List<byte[]> partitionRoots) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] domain = "JSC1-root".getBytes(StandardCharsets.US_ASCII);
        out.write(domain, 0, domain.length);
        out.write(catalogId, 0, catalogId.length);
        for (int partitionId = 0; partitionId < partitionRoots.size(); partitionId++) {
            byte[] id = intBytes(partitionId);
            byte[] root = partitionRoots.get(partitionId);
            out.write(id, 0, id.length);
            out.write(root, 0, root.length);
        }
        return sha256(out.toByteArray());
    }

    private static int compareUnsigned(byte[] left, byte[] right) {
        int length = Math.min(left.length, right.length);
        for (int index = 0; index < length; index++) {
            int comparison = Integer.compare(left[index] & 0xFF, right[index] & 0xFF);
            if (comparison != 0) return comparison;
        }
        return Integer.compare(left.length, right.length);
    }

    private static void sortVmCatalogDirectories(List<String[]> directories) {
        for (int index = 1; index < directories.size(); index++) {
            String[] value = directories.get(index);
            int valuePartition = parsePositiveInt(value[1], "partition id");
            int cursor = index - 1;
            while (cursor >= 0 && parsePositiveInt(directories.get(cursor)[1], "partition id") > valuePartition) {
                directories.set(cursor + 1, directories.get(cursor));
                cursor--;
            }
            directories.set(cursor + 1, value);
        }
    }

    private static void sortByteArrays(List<byte[]> values) {
        for (int index = 1; index < values.size(); index++) {
            byte[] value = values.get(index);
            int cursor = index - 1;
            while (cursor >= 0 && compareUnsigned(values.get(cursor), value) > 0) {
                values.set(cursor + 1, values.get(cursor));
                cursor--;
            }
            values.set(cursor + 1, value);
        }
    }

    private static byte[] frame(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return concat(intBytes(bytes.length), bytes);
    }

    private static byte[] longBytes(long value) {
        return new byte[] {
            (byte) (value >>> 56),
            (byte) (value >>> 48),
            (byte) (value >>> 40),
            (byte) (value >>> 32),
            (byte) (value >>> 24),
            (byte) (value >>> 16),
            (byte) (value >>> 8),
            (byte) value,
        };
    }

    private static byte[] concat(byte[]... parts) {
        int length = 0;
        for (byte[] part : parts) length += part.length;
        byte[] out = new byte[length];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, out, offset, part.length);
            offset += part.length;
        }
        return out;
    }

    private static byte[] intBytes(int value) {
        return new byte[] {
            (byte) (value >>> 24),
            (byte) (value >>> 16),
            (byte) (value >>> 8),
            (byte) value,
        };
    }

    private static boolean constantTimeEquals(byte[] expected, byte[] actual, int actualOffset) {
        if (actualOffset < 0 || actualOffset + expected.length > actual.length) return false;
        int diff = 0;
        for (int i = 0; i < expected.length; i++) diff |= (expected[i] ^ actual[actualOffset + i]) & 0xFF;
        return diff == 0;
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception ignored) {
            return new byte[32];
        }
    }

    private static int readSealedResourceLe16(byte[] data, int offset) {
        return (data[offset] & 0xFF) |
            ((data[offset + 1] & 0xFF) << 8);
    }

    private static int readSealedResourceLe32(byte[] data, int offset) {
        return (data[offset] & 0xFF) |
            ((data[offset + 1] & 0xFF) << 8) |
            ((data[offset + 2] & 0xFF) << 16) |
            ((data[offset + 3] & 0xFF) << 24);
    }

    private static int readSealedResourceBe32(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24) |
            ((data[offset + 1] & 0xFF) << 16) |
            ((data[offset + 2] & 0xFF) << 8) |
            (data[offset + 3] & 0xFF);
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

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }

    private static final class SealedNativeLibrary {
        final String resourcePath;
        final String fileSuffix;

        SealedNativeLibrary(String resourcePath, String fileSuffix) {
            this.resourcePath = resourcePath;
            this.fileSuffix = fileSuffix;
        }

        public boolean equals(Object other) {
            if (!(other instanceof SealedNativeLibrary)) return false;
            SealedNativeLibrary that = (SealedNativeLibrary) other;
            return resourcePath.equals(that.resourcePath) && fileSuffix.equals(that.fileSuffix);
        }

        public int hashCode() {
            return resourcePath.hashCode() * 31 + fileSuffix.hashCode();
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

    private static final class RuntimeResourceMetadata {
        int partitionId;
        int kindId;
        int layerCount;
        int variantId;
        boolean compressed;
        int plainLength;
        int storedLength;
        int bodyLength;
        int keyId;
        int seed;
        byte[] plainHash;
        byte[] storedHash;
    }

}
