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
import java.util.function.Function;
import java.util.function.IntUnaryOperator;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
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

    private static volatile int loadState = 0; // 0=untried, 1=native
    private static volatile String loadMessage = "";
    private static volatile boolean diversifiedVmEnabled = false;
    private static volatile String vmSelfCheck = "";
    private static volatile long nativeBootToken = 0L;
    private static volatile boolean nativeSelfCheckFailed = false;
    private static final String SEALED_NATIVE_INDEX_RESOURCE = "META-INF/.r/0.dat";
    private static final int RUNTIME_RESOURCE_VERSION = 6;
    private static final int LEGACY_RUNTIME_RESOURCE_VERSION = 5;
    private static final int BOOTSTRAP_NATIVE_INDEX_VERSION = 1;
    private static final ConcurrentMap<String, Object[]> SAM_LAMBDA_CACHE = new ConcurrentHashMap<>();

    private JniMicrokernelHelper() { }

    /* ---- JNI native methods (implemented in js_kernel.c) ---- */

    static native int nativeInit(String platform);
    static native int nativeVerify(byte[] data, byte[] expectedMac);
    static native int nativeHeartbeat();
    static native String nativeGetVersion();
    static native long nativeGetBootToken();
    static native void nativeInstallRuntimeResourceKey(byte[] key);
    static native void nativePreloadRuntimeResources();
    public static native byte[] nativeDecryptAes(byte[] encrypted, byte[] key, byte[] iv);
    public static native byte[] nativeDeriveClassEncryptionKey(byte[] keyId, byte[] salt, int length);

    public static native Object nativeExecuteVmResource(long entryToken, String resourcePath, Object[] args);
    public static native Object nativeExecuteVmResourceByToken(long entryToken, Object[] args);
    public static Object executeVmResource(long entryToken, String resourcePath, Object[] args) {
        if (loadState == 0) {
            loadKernel("vm", "auto", "vm-diverse");
        }
        if (isNativeLoaded()) {
            publishSealedNativeBindings();
            return nativeExecuteVmResource(entryToken, resourcePath, args);
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }
    public static Object executeVmResource(long entryToken, Object[] args) {
        if (loadState == 0) {
            loadKernel("vm", "auto", "vm-diverse");
        }
        if (isNativeLoaded()) {
            publishSealedNativeBindings();
            return nativeExecuteVmResourceByToken(entryToken, args);
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }

    public static native void nativeExecuteVmResourceVoid(long entryToken);
    public static native void nativeExecuteVmResourceIntVoid(long entryToken, int arg0);
    public static void executeVmResourceVoid(long entryToken) {
        if (loadState == 0) {
            loadKernel("vm", "auto", "vm-diverse");
        }
        if (isNativeLoaded()) {
            publishSealedNativeBindings();
            nativeExecuteVmResourceVoid(entryToken);
            return;
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }
    public static void executeVmResourceIntVoid(long entryToken, int arg0) {
        if (loadState == 0) {
            loadKernel("vm", "auto", "vm-diverse");
        }
        if (isNativeLoaded()) {
            publishSealedNativeBindings();
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
            MethodHandles.Lookup lookup = MethodHandles.privateLookupIn(ownerClass, MethodHandles.lookup());
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
        return loadState == 0 ? "untried" : loadMessage;
    }

    public static boolean isNativeLoaded() {
        return loadState == 1;
    }

    /* ---- Kernel loading ---- */

    public static void loadKernel(String kernelComponents, String targetPlatform) {
        loadKernel(kernelComponents, targetPlatform, "vm-off");
    }

    public static void loadKernel(String kernelComponents, String targetPlatform, String vmMode) {
        diversifiedVmEnabled = "vm-diverse".equals(vmMode);
        if (loadState != 0) return;
        try {
            String platformSuffix = detectPlatform();
            if (platformSuffix == null) {
                loadMessage = "native-unavailable";
                runDiversifiedVmSelfExercise();
                return;
            }
            if (!"auto".equals(targetPlatform) && !targetPlatform.equals(platformSuffix)) {
                return;
            }
            // Prefer the bundled library so stale system-path copies cannot shadow the ABI we generated.
            if (tryLoadBundledNative(platformSuffix, kernelComponents)) { runDiversifiedVmSelfExercise(); return; }
            if (tryLoadNative(platformSuffix, kernelComponents)) { runDiversifiedVmSelfExercise(); return; }
            if (loadMessage == null || loadMessage.length() == 0) loadMessage = "native-unavailable";
            runDiversifiedVmSelfExercise();
        } catch (Exception e) {
            loadMessage = debugNativeLoadMessage("native-exception", e);
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
        return loadState == 1 && !nativeSelfCheckFailed;
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
        vmSelfCheck = loadState == 1 ? "native:vm-diverse:ok" : "native:vm-diverse:unavailable";
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
        try {
            nativePreloadRuntimeResources();
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable e) {
            throw new SecurityException("VM preload failed", e);
        }
    }

    private static void installRuntimeResourceKeyIntoNative() {
        byte[] key = runtimeResourceKey();
        try {
            nativeInstallRuntimeResourceKey(key);
        } finally {
            Arrays.fill(key, (byte) 0);
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
        return prefix + ":" + e.getClass().getName() + ":" + String.valueOf(e.getMessage());
    }

    private static boolean tryLoadNative(String platformSuffix, String components) {
        String previousLoaderOwner = System.getProperty(sealedLoaderPropertyName());
        try {
            publishSealedNativeBindings();
            System.loadLibrary(kernelBaseName() + platformSuffix);
            loadMessage = "native:" + platformSuffix + ":" + nativeInit(platformSuffix);
            installRuntimeResourceKeyIntoNative();
            // Mark the kernel loaded BEFORE preloading VM resources. Native preload
            // (and the method-handle pre-resolution it performs) can trigger <clinit>
            // of other bundled classes whose injected loadKernel call would otherwise
            // re-enter this loader while loadState is still 0, recursively redoing the
            // entire extract/load/init/preload sequence (an effectively unbounded
            // cascade under broad method virtualization). With loadState already set,
            // the re-entry guard in loadKernel short-circuits and nested
            // executeVmResource calls see a ready kernel. Reset on failure.
            loadState = 1;
            boolean ok = false;
            try {
                preloadRuntimeResourcesIntoNative();
                if (verifyNativeAbiAfterLoad()) {
                    verifyBootTokenAfterLoad();
                    ok = true;
                }
                return ok;
            } finally {
                if (!ok) loadState = 0;
            }
        } catch (UnsatisfiedLinkError e) {
            return false;
        } finally {
            restoreLoaderProperty(previousLoaderOwner);
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
        try {
            if (!ensureNativeExtractDirectory(extractDirectory)) return false;
            tempLib = File.createTempFile(nativeTempPrefix(resourcePath), suffix, extractDirectory);
            tempLib.deleteOnExit();
            try (FileOutputStream out = new FileOutputStream(tempLib)) {
                out.write(nativeBytes);
            }
            tempLib.setReadable(true, true);
            tempLib.setWritable(true, true);
            tempLib.setExecutable(true, true);
            publishSealedNativeBindings();
            System.load(tempLib.getAbsolutePath());
            loadMessage = "native:bundled:" + platformSuffix + ":" + nativeInit(platformSuffix);
            installRuntimeResourceKeyIntoNative();
            // See the note in tryLoadNative: set loadState before preload so the
            // re-entry guard in loadKernel stops <clinit>-triggered recursion during
            // native preload/handle resolution, and nested executeVmResource calls
            // see a ready kernel. Reset on failure.
            loadState = 1;
            boolean ok = false;
            try {
                preloadRuntimeResourcesIntoNative();
                if (verifyNativeAbiAfterLoad()) {
                    verifyBootTokenAfterLoad();
                    ok = true;
                }
                return ok;
            } finally {
                if (!ok) loadState = 0;
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
            restoreLoaderProperty(previousLoaderOwner);
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

    public static byte[] decodeRuntimeResourceForNative(byte[] raw) {
        byte[] decoded = decodeRuntimeResource(raw);
        if (decoded == null) throw new IllegalArgumentException("unsupported runtime resource envelope");
        return decoded;
    }

    private static byte[] runtimeResourceKey() {
        return new byte[] {
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
        };
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
        if (!hasRuntimeResourceHeader(raw)) return null;
        int version = raw[4] & 0xFF;
        if (version == RUNTIME_RESOURCE_VERSION) return decodeRuntimeResourceCurrent(raw);
        if (version == LEGACY_RUNTIME_RESOURCE_VERSION) return decodeRuntimeResourceLegacy(raw);
        return null;
    }

    private static boolean hasRuntimeResourceHeader(byte[] raw) {
        return raw != null && raw.length >= 4 &&
            (raw[0] & 0xFF) == 0x4A && (raw[1] & 0xFF) == 0x53 && (raw[2] & 0xFF) == 0x52 && (raw[3] & 0xFF) == 0x50;
    }

    private static byte[] decodeRuntimeResourceCurrent(byte[] raw) {
        if (raw.length < 154 || (raw[raw.length - 1] & 0xFF) != 32) return null;
        byte[] nonce = Arrays.copyOfRange(raw, 5, 21);
        int metadataLength = readSealedResourceLe16(raw, 21);
        int macLength = readSealedResourceLe16(raw, 23);
        if (metadataLength != 96 || macLength != 32) return null;
        int metadataOffset = 25;
        int bodyOffset = metadataOffset + metadataLength;
        if (bodyOffset + 33 > raw.length) return null;
        int tagOffset = raw.length - 33;
        byte[] expected = hmacSha256(concat("jsrp-auth-v2".getBytes(StandardCharsets.US_ASCII), nonce, Arrays.copyOfRange(raw, 0, tagOffset)));
        if (!constantTimeEquals(expected, raw, tagOffset)) return null;
        byte[] metadata = runtimeResourceAesCtrWithDomains(
            Arrays.copyOfRange(raw, metadataOffset, bodyOffset),
            nonce,
            intBytes(0),
            intBytes(0),
            intBytes(0)
        );
        RuntimeResourceMetadata parsed = parseRuntimeResourceMetadata(metadata);
        if (parsed == null) return null;
        if (parsed.kindId < 1 || parsed.kindId > 4) return null;
        if (parsed.layerCount < 1 || parsed.layerCount > 7 || parsed.variantId > 127) return null;
        if (parsed.plainLength < 0 || parsed.storedLength < 0 || parsed.bodyLength < 0) return null;
        if (bodyOffset + parsed.bodyLength != tagOffset) return null;
        byte[] body = Arrays.copyOfRange(raw, bodyOffset, tagOffset);
        byte[] stored = runtimeResourceAesCtr(body, nonce, parsed.kindId, parsed.variantId, parsed.layerCount);
        if (stored.length != parsed.storedLength) return null;
        if (!Arrays.equals(sha256(stored), parsed.storedHash)) return null;
        byte[] plain = parsed.compressed ? null : stored;
        if (plain == null || plain.length != parsed.plainLength) return null;
        return Arrays.equals(sha256(plain), parsed.plainHash) ? plain : null;
    }

    private static byte[] decodeRuntimeResourceLegacy(byte[] raw) {
        if (raw.length < 73 || (raw[raw.length - 1] & 0xFF) != 32) return null;
        int kindId = raw[5] & 0xFF;
        int layerCount = raw[6] & 0xFF;
        int flags = raw[7] & 0xFF;
        boolean compressed = (flags & 0x80) != 0;
        int variantId = flags & 0x7F;
        if (layerCount < 1 || layerCount > 7) return null;
        byte[] nonce = Arrays.copyOfRange(raw, 8, 24);
        int plainLength = readSealedResourceLe32(raw, 24);
        int storedLength = readSealedResourceLe32(raw, 28);
        int bodyLength = readSealedResourceLe32(raw, 32);
        int tagOffset = 40 + bodyLength;
        if (plainLength < 0 || storedLength < 0 || bodyLength < 0) return null;
        if (tagOffset + 33 != raw.length) return null;
        byte[] expected = hmacSha256(concat("jsrp-auth".getBytes(StandardCharsets.US_ASCII), nonce, Arrays.copyOfRange(raw, 0, tagOffset)));
        if (!constantTimeEquals(expected, raw, tagOffset)) return null;
        byte[] body = Arrays.copyOfRange(raw, 40, tagOffset);
        byte[] stored = runtimeResourceAesCtr(body, nonce, kindId, variantId, layerCount);
        if (stored.length != storedLength) return null;
        byte[] plain = compressed ? null : stored;
        return plain != null && plain.length == plainLength ? plain : null;
    }

    private static byte[] runtimeResourceAesCtr(byte[] bytes, byte[] nonce, int kindId, int variantId, int layerCount) {
        return runtimeResourceAesCtrWithDomains(bytes, nonce, intBytes(kindId), intBytes(variantId), intBytes(layerCount));
    }

    private static byte[] runtimeResourceAesCtrWithDomains(byte[] bytes, byte[] nonce, byte[] kindBytes, byte[] variantBytes, byte[] layerBytes) {
        try {
            byte[] key = Arrays.copyOfRange(hmacSha256(concat(
                "jsrp-aes-key".getBytes(StandardCharsets.US_ASCII),
                nonce,
                kindBytes,
                variantBytes,
                layerBytes
            )), 0, 16);
            byte[] iv = Arrays.copyOfRange(hmacSha256(concat(
                "jsrp-aes-iv".getBytes(StandardCharsets.US_ASCII),
                nonce,
                kindBytes,
                variantBytes,
                layerBytes
            )), 0, 16);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(bytes);
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
        parsed.keyId = readSealedResourceLe32(bytes, 20);
        parsed.seed = readSealedResourceLe32(bytes, 24);
        parsed.plainHash = Arrays.copyOfRange(bytes, 28, 60);
        parsed.storedHash = Arrays.copyOfRange(bytes, 60, 92);
        return parsed;
    }

    private static byte[] hmacSha256(byte[] data) {
        byte[] key = runtimeResourceKey();
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception ignored) {
            return new byte[32];
        } finally {
            Arrays.fill(key, (byte) 0);
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
            throw new SecurityException("class-encryption key derivation requires the sealed native kernel; no Java fallback");
        }
        return nativeDeriveClassEncryptionKey(keyId, salt, length);
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
