package io.github.hht0rro.javashroud.transforms.protection;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandleProxies;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.LinkedHashSet;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.function.Function;
import java.util.function.IntUnaryOperator;
import java.util.Arrays;
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
    private static volatile boolean diversifiedVmEnabled = false;
    private static volatile String vmSelfCheck = "";
    private static volatile long nativeBootToken = 0L;
    private static volatile boolean nativeSelfCheckFailed = false;
    private static volatile boolean sealedNativeBindingsPublished = false;
    private static final String SEALED_NATIVE_INDEX_RESOURCE = "META-INF/.r/0.dat";
    private static final String VM_CATALOG_RESOURCE = "META-INF/.r/vm.catalog";
    private static final int RUNTIME_RESOURCE_VERSION = 7;
    private static final int NATIVE_ANCHOR_KEY_SLOT = 16;
    private static final int BOOTSTRAP_NATIVE_INDEX_VERSION = 1;
    private static final int ZSTD_MAGIC = 0xFD2FB528;
    private static final ConcurrentMap<String, Object[]> SAM_LAMBDA_CACHE = new ConcurrentHashMap<>();

    private JniMicrokernelHelper() { }

    /* ---- JNI native methods (implemented in js_kernel.c) ---- */

    static native int nativeInit(String platform);
    static native int nativeVerify(byte[] data, byte[] expectedMac);
    static native int nativeHeartbeat();
    static native String nativeGetVersion();
    static native long nativeGetBootToken();
    static native void nativeInstallRuntimeResourceKey(byte[] key, int slot);
    static native void nativePreloadRuntimeResources(byte[] preloadIndex, byte[] commitments, byte[] startupNonce);
    public static native byte[] nativeDecryptAes(byte[] encrypted, byte[] key, byte[] iv);
    public static native byte[] nativeDeriveClassEncryptionKey(byte[] keyId, byte[] salt, int length);

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
        return (Runnable) createSamLambda("run", "()Ljava/lang/Runnable;", owner, name, descriptor, implTag, captured);
    }

    public static Object createSamLambda(String samName, String factoryDescriptor, String owner, String name, String descriptor, int implTag, Object[] captured) {
        final Object[] capturedArgs = captured == null ? new Object[0] : Arrays.copyOf(captured, captured.length);
        final Object[] linkedTarget = resolveSamLambdaTarget(owner, name, descriptor, implTag);
        String samOwner = descriptorReturnInternalName(factoryDescriptor);
        try {
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            if ("java/lang/Runnable".equals(samOwner) && "run".equals(samName)) {
                MethodHandle handle = lookup.findStatic(JniMicrokernelHelper.class, "runSamLambda", MethodType.methodType(void.class, Object[].class, Object[].class));
                return MethodHandleProxies.asInterfaceInstance(Runnable.class, MethodHandles.insertArguments(handle, 0, linkedTarget, capturedArgs));
            }
            if ("java/util/function/IntUnaryOperator".equals(samOwner) && "applyAsInt".equals(samName)) {
                MethodHandle handle = lookup.findStatic(JniMicrokernelHelper.class, "applyAsIntSamLambda", MethodType.methodType(int.class, Object[].class, Object[].class, int.class));
                return MethodHandleProxies.asInterfaceInstance(IntUnaryOperator.class, MethodHandles.insertArguments(handle, 0, linkedTarget, capturedArgs));
            }
            if ("java/util/function/Function".equals(samOwner) && "apply".equals(samName)) {
                MethodHandle handle = lookup.findStatic(JniMicrokernelHelper.class, "applySamLambda", MethodType.methodType(Object.class, Object[].class, Object[].class, Object.class));
                return MethodHandleProxies.asInterfaceInstance(Function.class, MethodHandles.insertArguments(handle, 0, linkedTarget, capturedArgs));
            }
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot create virtualized SAM lambda", e);
        }
        throw new IllegalArgumentException("unsupported virtualized SAM lambda");
    }

    public static void runSamLambda(Object[] linkedTarget, Object[] captured) {
        invokeSamLambdaTarget(linkedTarget, captured, new Object[0]);
    }

    public static int applyAsIntSamLambda(Object[] linkedTarget, Object[] captured, int operand) {
        Object result = invokeSamLambdaTarget(linkedTarget, captured, new Object[] { Integer.valueOf(operand) });
        return ((Number) result).intValue();
    }

    public static Object applySamLambda(Object[] linkedTarget, Object[] captured, Object value) {
        return invokeSamLambdaTarget(linkedTarget, captured, new Object[] { value });
    }

    private static Object[] resolveSamLambdaTarget(String owner, String name, String descriptor, int implTag) {
        String key = owner + '\u0000' + name + '\u0000' + descriptor + '\u0000' + implTag;
        Object[] cached = SAM_LAMBDA_CACHE.get(key);
        if (cached != null) return cached;
        try {
            ClassLoader loader = JniMicrokernelHelper.class.getClassLoader();
            Class<?> ownerClass = Class.forName(owner.replace('/', '.'), false, loader);
            Class<?>[] parameterTypes = descriptorParameterTypes(descriptor, ownerClass.getClassLoader());
            String resolvedName = resolveBoundMethodName(owner, name, descriptor);
            Method method = ownerClass.getDeclaredMethod(resolvedName, parameterTypes);
            method.setAccessible(true);
            boolean staticTarget = implTag == 6 || Modifier.isStatic(method.getModifiers());
            Object[] linked = new Object[] { method, Integer.valueOf(parameterTypes.length), Boolean.valueOf(staticTarget) };
            Object[] existing = SAM_LAMBDA_CACHE.putIfAbsent(key, linked);
            return existing == null ? linked : existing;
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("cannot link virtualized SAM lambda", e);
        }
    }

    private static Object invokeSamLambdaTarget(Object[] linkedTarget, Object[] captured, Object[] callArgs) {
        Object targetHandle = linkedTarget[0];
        int parameterCount = ((Integer) linkedTarget[1]).intValue();
        boolean staticTarget = ((Boolean) linkedTarget[2]).booleanValue();
        Object receiver = null;
        int capturedOffset = 0;
        if (!staticTarget) {
            if (captured.length == 0) throw new IllegalStateException("missing captured lambda receiver");
            receiver = captured[0];
            capturedOffset = 1;
        }
        int available = captured.length - capturedOffset + callArgs.length;
        if (available != parameterCount) {
            throw new IllegalStateException("lambda argument count mismatch");
        }
        Object[] args = new Object[available];
        System.arraycopy(captured, capturedOffset, args, 0, captured.length - capturedOffset);
        System.arraycopy(callArgs, 0, args, captured.length - capturedOffset, callArgs.length);
        try {
            if (targetHandle instanceof MethodHandle) {
                Object[] methodHandleArgs = staticTarget ? args : prependReceiver(receiver, args);
                return ((MethodHandle) targetHandle).invokeWithArguments(methodHandleArgs);
            }
            return ((Method) targetHandle).invoke(receiver, args);
        } catch (InvocationTargetException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException) throw (RuntimeException) cause;
            if (cause instanceof Error) throw (Error) cause;
            throw new RuntimeException(cause);
        } catch (Throwable e) {
            if (e instanceof RuntimeException) throw (RuntimeException) e;
            if (e instanceof Error) throw (Error) e;
            throw new RuntimeException(e);
        }
    }

    private static Object[] prependReceiver(Object receiver, Object[] args) {
        Object[] withReceiver = new Object[args.length + 1];
        withReceiver[0] = receiver;
        System.arraycopy(args, 0, withReceiver, 1, args.length);
        return withReceiver;
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
            MethodHandles.Lookup lookup = privateLookup(ownerClass);
            switch (tag) {
                case 6: return lookup.findStatic(ownerClass, name, methodType);
                case 5: return lookup.findVirtual(ownerClass, name, methodType);
                case 7: return lookup.findSpecial(ownerClass, name, methodType, ownerClass);
                case 8: return lookup.findStatic(ownerClass, name, methodType);
                default: return null;
            }
        } catch (Throwable ignored) {
            return null;
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
        return loadState == LOAD_READY;
    }

    /* ---- Kernel loading ---- */

    public static void loadKernel(String kernelComponents, String targetPlatform) {
        loadKernel(kernelComponents, targetPlatform, "vm-off");
    }

    public static synchronized void loadKernel(String kernelComponents, String targetPlatform, String vmMode) {
        diversifiedVmEnabled = "vm-diverse".equals(vmMode);
        if (loadState != LOAD_UNTRIED) return;
        loadState = LOAD_LOADING;
        try {
            String platformSuffix = detectPlatform();
            if (platformSuffix == null) {
                loadMessage = "native-unavailable";
                loadState = LOAD_FAILED;
                runDiversifiedVmSelfExercise();
                return;
            }
            if (!"auto".equals(targetPlatform) && !targetPlatform.equals(platformSuffix)) {
                loadState = LOAD_FAILED;
                return;
            }
            // Prefer the bundled library so stale system-path copies cannot shadow the ABI we generated.
            if (tryLoadBundledNative(platformSuffix, kernelComponents)) {
                loadState = LOAD_READY;
                runDiversifiedVmSelfExercise();
                return;
            }
            if (tryLoadNative(platformSuffix, kernelComponents)) {
                loadState = LOAD_READY;
                runDiversifiedVmSelfExercise();
                return;
            }
            if (loadMessage == null || loadMessage.length() == 0) loadMessage = "native-unavailable";
            loadState = LOAD_FAILED;
            runDiversifiedVmSelfExercise();
        } catch (Exception e) {
            loadMessage = debugNativeLoadMessage("native-exception", e);
            loadState = LOAD_FAILED;
        }
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
        return loadState == LOAD_READY && !nativeSelfCheckFailed;
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
        vmSelfCheck = loadState == LOAD_READY ? "native:vm-diverse:ok" : "native:vm-diverse:unavailable";
    }

    /**
     * Multi-point kernel integrity gate.
     * Requires native kernel loaded AND no self-check or boot token failures.
     * Used by distributed call sites so patching a single check is insufficient.
     */
    public static void requireHealthyKernel() {
        if (nativeSelfCheckFailed || (vmSelfCheck != null && vmSelfCheck.contains("mismatch"))) {
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

    private static void verifyBootTokenAfterLoad() {
        try {
            long expected = computeExpectedBootToken();
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

    private static long computeExpectedBootToken() {
        String platformSuffix = detectPlatform();
        if (platformSuffix == null) platformSuffix = "";
        long token = 0xCBF29CE484222325L;
        token ^= 0xAD3B3ED7L; // FNV1a(decoded native key), mirrored from js_kernel.c
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
        long hash = 0xCBF29CE484222325L;
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        for (byte b : bytes) {
            hash ^= b & 0xFFL;
            hash *= 0x100000001B3L;
        }
        String hex = Long.toHexString(hash);
        return hex.length() >= 16 ? hex : "0000000000000000".substring(hex.length()) + hex;
    }

    private static void preloadRuntimeResourcesIntoNative() {
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
        byte[] rootRaw = readRequiredResource(VM_CATALOG_RESOURCE, catalogJar);
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
                if (line.startsWith("M|")) {
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

    private static void installRuntimeResourceKeyIntoNative() {
        int count = runtimeResourcePartitionCount();
        for (int slot = 0; slot < count; slot++) {
            byte[] key = partitionResourceKey(slot);
            try {
                nativeInstallRuntimeResourceKey(key, slot);
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        }
        byte[] anchor = partitionResourceKey(anchorResourcePartition());
        try {
            nativeInstallRuntimeResourceKey(anchor, NATIVE_ANCHOR_KEY_SLOT);
        } finally {
            Arrays.fill(anchor, (byte) 0);
        }
    }

    /* ---- Platform detection ---- */

    private static String detectPlatform() {
        String osName = System.getProperty("os.name", "").toLowerCase();
        String osArch = System.getProperty("os.arch", "").toLowerCase();
        if (osName.contains("win") && (osArch.contains("64") || osArch.contains("amd64"))) return "windows-x64";
        if (osName.contains("linux") && osArch.contains("64")) return "linux-x64";
        if (osName.contains("mac") && osArch.contains("aarch64")) return "macos-arm64";
        if (osName.contains("mac")) return "macos-x64";
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

    private static boolean tryLoadNative(String platformSuffix, String components) {
        String previousLoaderOwner = System.getProperty(sealedLoaderPropertyName());
        boolean ok = false;
        try {
            publishSealedNativeBindings();
            System.loadLibrary(kernelBaseName() + platformSuffix);
            loadMessage = "native:" + platformSuffix + ":" + initializeNativeKernel(platformSuffix);
            installRuntimeResourceKeyIntoNative();
            sealedNativeBindingsPublished = true;
            try {
                preloadRuntimeResourcesIntoNative();
                if (verifyNativeAbiAfterLoad()) {
                    verifyBootTokenAfterLoad();
                    ok = true;
                }
                return ok;
            } finally {
                if (!ok) {
                    sealedNativeBindingsPublished = false;
                }
            }
        } catch (UnsatisfiedLinkError e) {
            return false;
        } finally {
            if (!ok) restoreLoaderProperty(previousLoaderOwner);
        }
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
        for (File extractDirectory : nativeExtractDirectories()) {
            if (tryLoadBundledNativeFromDirectory(platformSuffix, resourcePath, suffix, nativeBytes, extractDirectory)) return true;
        }
        return false;
    }

    private static boolean tryLoadBundledNativeFromDirectory(String platformSuffix, String resourcePath, String suffix, byte[] nativeBytes, File extractDirectory) {
        File tempLib = null;
        String previousLoaderOwner = System.getProperty(sealedLoaderPropertyName());
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
            publishSealedNativeBindings();
            System.load(tempLib.getAbsolutePath());
            loadMessage = "native:bundled:" + platformSuffix + ":" + initializeNativeKernel(platformSuffix);
            installRuntimeResourceKeyIntoNative();
            sealedNativeBindingsPublished = true;
            try {
                preloadRuntimeResourcesIntoNative();
                if (verifyNativeAbiAfterLoad()) {
                    verifyBootTokenAfterLoad();
                    ok = true;
                }
                return ok;
            } finally {
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
            if (!ok) restoreLoaderProperty(previousLoaderOwner);
        }
    }

    private static int initializeNativeKernel(String platformSuffix) {
        int result = nativeInit(platformSuffix);
        return result == 2 ? nativeInit(platformSuffix) : result;
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
        try {
            System.setProperty(sealedLoaderPropertyName(), JniMicrokernelHelper.class.getName().replace('.', '/'));
            String index = sealedNativeIndexText();
            if (index == null || index.length() == 0) return;
            StringBuilder bindings = new StringBuilder();
            StringBuilder methodBindings = new StringBuilder();
            String[] lines = index.split("\n");
            for (String line : lines) {
                String[] parts = line.trim().split("\\|", -1);
                if (parts.length == 3 && "B".equals(parts[0])) {
                    if (bindings.length() > 0) bindings.append('\n');
                    bindings.append(parts[1]).append('=').append(parts[2]);
                } else if (parts.length == 3 && "M".equals(parts[0])) {
                    if (methodBindings.length() > 0) methodBindings.append('\n');
                    methodBindings.append(parts[1]).append('=').append(parts[2]);
                }
            }
            if (bindings.length() > 0) System.setProperty(sealedBindingPropertyName(), mergeBindingProperties(System.getProperty(sealedBindingPropertyName()), bindings.toString()));
            if (methodBindings.length() > 0) System.setProperty(sealedMethodBindingPropertyName(), mergeBindingProperties(System.getProperty(sealedMethodBindingPropertyName()), methodBindings.toString()));
        } catch (Throwable ignored) {
        }
    }

    private static void ensureSealedNativeBindingsPublished() {
        if (sealedNativeBindingsPublished) return;
        publishSealedNativeBindings();
        sealedNativeBindingsPublished = true;
    }

    private static void restoreLoaderProperty(String previous) {
        try {
            if (previous == null) {
                System.clearProperty(sealedLoaderPropertyName());
            } else {
                System.setProperty(sealedLoaderPropertyName(), previous);
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

    private static String sealedNativeIndexText() {
        try (InputStream in = resourceStream(SEALED_NATIVE_INDEX_RESOURCE)) {
            if (in == null) return null;
            byte[] decoded = decodeBootstrapNativeIndex(readAll(in));
            return decoded == null ? null : new String(decoded, StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            return null;
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
            if (hi < 0 || lo < 0) throw new IllegalArgumentException("bad hex");
            out[index] = (byte) ((hi << 4) | lo);
        }
        return out;
    }

    public static byte[] decodeRuntimeResourceForNative(byte[] raw) {
        byte[] decoded = decodeRuntimeResource(raw);
        if (decoded == null) throw new IllegalArgumentException("unsupported runtime resource envelope");
        return decoded;
    }

    private static int runtimeResourcePartitionCount() {
        return 1;
    }

    private static int anchorResourcePartition() {
        return 0;
    }

    private static byte[] partitionResourceKey(int partitionId) {
        if (partitionId < 0) return new byte[32];
        return new byte[32];
    }

    public static byte[] decodeRuntimeResourceEnvelope(byte[] raw) {
        return decodeRuntimeResource(raw);
    }

    private static byte[] decodeBootstrapNativeIndex(byte[] raw) {
        if (raw == null || raw.length < 42) return null;
        if ((raw[0] & 0xFF) != 0x4A || (raw[1] & 0xFF) != 0x53 || (raw[2] & 0xFF) != 0x42 || (raw[3] & 0xFF) != 0x49) return null;
        if ((raw[4] & 0xFF) != BOOTSTRAP_NATIVE_INDEX_VERSION) return null;
        int plainLength = readSealedResourceLe32(raw, 5);
        if (plainLength < 0) return null;
        int plainOffset = 9;
        int tagOffset = plainOffset + plainLength;
        if (tagOffset + 33 != raw.length || (raw[raw.length - 1] & 0xFF) != 32) return null;
        byte[] expected = hmacSha256(concat("jsbi-auth".getBytes(StandardCharsets.US_ASCII), Arrays.copyOfRange(raw, 0, tagOffset)));
        if (!constantTimeEquals(expected, raw, tagOffset)) return null;
        return Arrays.copyOfRange(raw, plainOffset, tagOffset);
    }

    private static byte[] decodeRuntimeResource(byte[] raw) {
        return decodeRuntimeResource(raw, false);
    }

    private static byte[] decodeRuntimeResource(byte[] raw, boolean allowCompressed) {
        if (!hasRuntimeResourceHeader(raw)) return null;
        int version = raw[4] & 0xFF;
        if (version == RUNTIME_RESOURCE_VERSION) return decodeRuntimeResourceCurrent(raw, allowCompressed);
        return null;
    }

    private static boolean hasRuntimeResourceHeader(byte[] raw) {
        return raw != null && raw.length >= 5 &&
            (raw[0] & 0xFF) == 0x4A && (raw[1] & 0xFF) == 0x53 && (raw[2] & 0xFF) == 0x52 && (raw[3] & 0xFF) == 0x50;
    }

    private static byte[] decodeRuntimeResourceCurrent(byte[] raw, boolean allowCompressed) {
        if (raw.length < 156 || (raw[raw.length - 1] & 0xFF) != 32) return null;
        byte[] nonce = Arrays.copyOfRange(raw, 5, 21);
        int metadataLength = readSealedResourceLe16(raw, 21);
        int macLength = readSealedResourceLe16(raw, 23);
        int partitionId = readSealedResourceLe16(raw, 25);
        if (metadataLength != 96 || macLength != 32) return null;
        if (partitionId < 0 || partitionId >= runtimeResourcePartitionCount()) return null;
        int metadataOffset = 27;
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
        return raw != null && raw.length >= 27 && raw[0] == 'J' && raw[1] == 'S' && raw[2] == 'R' && raw[3] == 'P' &&
            (raw[4] & 0xFF) == RUNTIME_RESOURCE_VERSION && readSealedResourceLe16(raw, 25) == partitionId;
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

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }

    private static String kernelBaseName() {
        return new String(new char[]{'j', 's', '_', 'k', 'e', 'r', 'n', 'e', 'l', '_'});
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
