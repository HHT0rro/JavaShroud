package io.github.hht0rro.javashroud.transforms.protection;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
 import java.security.ProtectionDomain; 
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import java.security.MessageDigest;

/**
 * Runtime helper for class encryption loader.
 * Uses a single shared child ClassLoader that decrypt-defines every encrypted
 * class within one namespace. A central manifest (__jse/index.tab) maps each
 * encrypted class to its resource path and key metadata so that sibling and
 * inner classes referenced at runtime are resolved by the SAME loader. This
 * avoids the IllegalAccessError that occurs when mutually-referencing classes
 * are defined by different class loaders.
 * Pure Java - no Kotlin runtime dependency.
 */
public final class ClassEncryptionLoaderHelper {

    private static final ConcurrentHashMap<String, Class<?>> loadedClasses = new ConcurrentHashMap<>();

    private ClassEncryptionLoaderHelper() { }


    /** Manifest resource listing every encrypted class. */
    private static final String MANIFEST_RESOURCE = "__jse/index.tab";
    private static final String[] INNOCUOUS_EXTENSIONS = {
        ".properties", ".xml", ".json", ".yml", ".cfg", ".conf", ".ini", ".txt"
    };
    /** internalName ('a/b/C') -> "resourcePath\tkeyMetadata". Loaded once. */
    private static volatile ConcurrentHashMap<String, String[]> manifest;
    /** The single shared loader that owns all decrypted application classes. */
    private static volatile SharedDecryptingClassLoader sharedLoader;

    /**
     * Load an encrypted class from a resource path and return the Class object.
     * Called from the stub's <clinit> and from method delegation code.
     */
    public static Class<?> loadClass(String resourcePath, String keyMetadata) {
        Class<?> existing = loadedClasses.get(resourcePath);
        if (existing != null) return existing;
        try {
            return doLoadClass(resourcePath, keyMetadata);
        } catch (Exception e) {
            throw new IllegalStateException("Encrypted class not loaded: " + resourcePath, e);
        }
    }

    /**
     *
     */
    private static volatile sun.misc.Unsafe unsafe;
    private static final ConcurrentHashMap<String, Method> methodCache = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Object> instanceCache = new ConcurrentHashMap<>();

    static {
        try {
            java.lang.reflect.Field f = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            f.setAccessible(true);
            unsafe = (sun.misc.Unsafe) f.get(null);
        } catch (Exception e) { unsafe = null; }
    }

    public static Object invokeMethod(Object[] args) throws Exception {
        Class<?> classRef = (Class<?>) args[0];
        String methodName = (String) args[1];
        String descriptor = (String) args[2];
        int isStatic = (Integer) args[3];
        Object thisRef = args[4];

        // Parse parameter types from descriptor
        Class<?>[] paramTypes = parseParamTypes(classRef.getClassLoader(), descriptor);
        Object[] methodArgs = new Object[args.length - 5];
        System.arraycopy(args, 5, methodArgs, 0, methodArgs.length);

        // Build cache key
        String cacheKey = classRef.getName() + "." + methodName + descriptor;
        Method method = methodCache.get(cacheKey);
        if (method == null) {
            method = classRef.getDeclaredMethod(methodName, paramTypes);
            method.setAccessible(true);
            methodCache.put(cacheKey, method);
        }

        if (isStatic != 0) {
            return method.invoke(null, methodArgs);
        } else {
            // Instance method: need a real instance of the loaded class
            // The thisRef is a stub, not a real class instance. Create a real instance.
            String instKey = classRef.getName();
            Object realInstance = instanceCache.get(instKey);
            if (realInstance == null) {
                realInstance = createInstance(classRef);
                if (realInstance != null) {
                    instanceCache.put(instKey, realInstance);
                }
            }
            if (realInstance != null) {
                return method.invoke(realInstance, methodArgs);
            }
            // Last resort: try with original thisRef (may work for some cases)
            return method.invoke(thisRef, methodArgs);
        }
    }

    private static Object createInstance(Class<?> clazz) {
        // Try no-arg constructor first
        try {
            java.lang.reflect.Constructor<?> ctor = clazz.getDeclaredConstructor();
            ctor.setAccessible(true);
            return ctor.newInstance();
        } catch (Exception ignored) { }
        // Use Unsafe.allocateInstance if available (doesn't call any constructor)
        if (unsafe != null) {
            try {
                return unsafe.allocateInstance(clazz);
            } catch (Exception ignored) { }
        }
        return null;
    }

    /**
     * Load and invoke main for the encrypted class.
     * Called from the stub's main method for backward compatibility.
     */
    public static void loadAndInvokeMain(String resourcePath, String keyMetadata, String[] args) throws Exception {
        Class<?> loaded = loadClass(resourcePath, keyMetadata);
        if (loaded == null) {
            throw new ClassNotFoundException("Encrypted class not loaded: " + resourcePath);
        }
        Method main = loaded.getMethod("main", String[].class);
        main.invoke(null, (Object) args);
    }

    /**
     * @deprecated Use loadClass instead.
     */
    public static void initializeClass(String resourcePath, String keyMetadata) {
        loadClass(resourcePath, keyMetadata);
    }

    /**
     * Get a previously loaded class by its resource path.
     */
    public static Class<?> getLoadedClass(String resourcePath) {
        return loadedClasses.get(resourcePath);
    }

    // --- Internal methods ---

    private static Class<?> doLoadClass(String resourcePath, String keyMetadata) throws Exception {
        String className = null;
        for (java.util.Map.Entry<String, String[]> entry : manifest().entrySet()) {
            if (resourcePath.equals(entry.getValue()[0])) {
                className = entry.getKey();
                break;
            }
        }
        if (className == null) {
            // Legacy fallback: extract binary class name from resource path: __jse/e2e/Root.enc -> e2e.Root
            className = resourcePath
                .replace("__jse/", "")
                .replace(".enc", "")
                .replace('/', '.');
        }
        // Resolve through the single shared loader so that this class and every
        // class it references (siblings, inner classes) live in one namespace.
        Class<?> defined = sharedLoader().loadClass(className);
        loadedClasses.put(resourcePath, defined);
        return defined;
    }

    /** Lazily build (once) the shared decrypting class loader. */
    private static SharedDecryptingClassLoader sharedLoader() {
        SharedDecryptingClassLoader local = sharedLoader;
        if (local != null) return local;
        synchronized (ClassEncryptionLoaderHelper.class) {
            if (sharedLoader == null) {
                sharedLoader = new SharedDecryptingClassLoader(
                    ClassEncryptionLoaderHelper.class.getClassLoader());
            }
            return sharedLoader;
        }
    }

    /** Lazily load (once) the central manifest of encrypted classes. */
    private static ConcurrentHashMap<String, String[]> manifest() {
        ConcurrentHashMap<String, String[]> local = manifest;
        if (local != null) return local;
        synchronized (ClassEncryptionLoaderHelper.class) {
            if (manifest == null) {
                ConcurrentHashMap<String, String[]> m = new ConcurrentHashMap<>();
                try {
                    byte[] manifestBytes = readManifestBytes();
                    if (manifestBytes != null) {
                        String text = new String(manifestBytes, java.nio.charset.StandardCharsets.UTF_8);
                        for (String line : text.split("\n")) {
                            if (line.isEmpty()) continue;
                            String[] cols = line.split("\t");
                            if (cols.length >= 3) {
                                // key: binary name a.b.C ; value: [resourcePath, keyMetadata]
                                m.put(cols[0].replace('/', '.'), new String[]{cols[1], cols[2]});
                            }
                        }
                    }
                } catch (Exception ignored) { }
                manifest = m;
            }
            return manifest;
        }
    }

    private static byte[] readManifestBytes() throws Exception {
        InputStream legacy = ClassEncryptionLoaderHelper.class.getClassLoader()
            .getResourceAsStream(MANIFEST_RESOURCE);
        if (legacy != null) {
            byte[] bytes = readAll(legacy);
            byte[] decoded = decodeRuntimeResource(bytes);
            if (decoded != null && looksLikeManifest(new String(decoded, java.nio.charset.StandardCharsets.UTF_8))) return decoded;
            if (looksLikeManifest(new String(bytes, java.nio.charset.StandardCharsets.UTF_8))) return bytes;
            return null;
        }
        java.net.URL root = ClassEncryptionLoaderHelper.class.getProtectionDomain().getCodeSource().getLocation();
        java.util.jar.JarFile jar = new java.util.jar.JarFile(new java.io.File(root.toURI()));
        try {
            java.util.Enumeration<java.util.jar.JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                java.util.jar.JarEntry entry = entries.nextElement();
                if (entry.isDirectory() || !(hasInnocuousExtension(entry.getName()) || entry.getName().endsWith(".dat"))) continue;
                byte[] encoded = readAll(jar.getInputStream(entry));
                byte[] decoded = decodeRuntimeResource(encoded);
                if (decoded == null) continue;
                String candidate = new String(decoded, java.nio.charset.StandardCharsets.UTF_8);
                if (looksLikeManifest(candidate)) return decoded;
            }
        } finally {
            jar.close();
        }
        return null;
    }

    private static byte[] decodeRuntimeResource(byte[] bytes) {
        try {
            return JniMicrokernelHelper.decodeRuntimeResourceForNative(bytes);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean looksLikeManifest(String candidate) {
        boolean sawEntry = false;
        for (String line : candidate.split("\n")) {
            if (line.isEmpty()) continue;
            String[] cols = line.split("\t");
            if (cols.length < 3) return false;
            if (cols[0].isEmpty() || cols[1].isEmpty() || cols[2].isEmpty()) return false;
            if (!(hasInnocuousExtension(cols[1]) || cols[1].endsWith(".dat") || cols[1].endsWith(".bin") || (cols[1].startsWith("__jse/") && cols[1].endsWith(".enc")))) return false;
            if (cols[2].indexOf(':') <= 0) return false;
            sawEntry = true;
        }
        return sawEntry;
    }

    private static boolean hasInnocuousExtension(String name) {
        for (String ext : INNOCUOUS_EXTENSIONS) {
            if (name.endsWith(ext)) return true;
        }
        return false;
    }

    private static byte[] readAll(InputStream is) throws Exception {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
            return bos.toByteArray();
        } finally {
            is.close();
        }
    }

    /** Decrypt the bytes for a manifest-listed class; null if not encrypted. */
    private static byte[] decryptClassBytes(String binaryName) {
        String[] entry = manifest().get(binaryName);
        if (entry == null) return null;
        try {
            String resourcePath = entry[0];
            String keyMetadata = entry[1];
            ParsedMetadata metadata = parseMetadata(binaryName, resourcePath, keyMetadata);
            byte[] key = JniMicrokernelHelper.deriveClassEncryptionKey(metadata.keyId, metadata.salt, metadata.keyLength);
            byte[] encryptedBytes = readResource(resourcePath);
            try {
                return decryptBytes(encryptedBytes, metadata.strategy, key, metadata.nonce, metadata.aad);
            } finally {
                java.util.Arrays.fill(key, (byte) 0);
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt encrypted class: " + binaryName, e);
        }
    }

    private static byte[] readResource(String resourcePath) throws Exception {
        InputStream is = ClassEncryptionLoaderHelper.class.getClassLoader().getResourceAsStream(resourcePath);
        if (is == null) throw new Exception("Resource not found: " + resourcePath);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) {
            bos.write(buf, 0, n);
        }
        byte[] bytes = bos.toByteArray();
        byte[] decoded = decodeRuntimeResource(bytes);
        return decoded != null ? decoded : bytes;
    }

    private static ParsedMetadata parseMetadata(String binaryName, String resourcePath, String keyMetadata) throws Exception {
        String[] parts = keyMetadata.split(":", -1);
        if (parts.length != 6 || !"v2".equals(parts[0])) {
            throw new SecurityException("Unsupported encrypted class metadata format: " + binaryName);
        }
        String strategy = parts[1];
        if (!("aes-128".equals(strategy) || "aes-256".equals(strategy))) {
            throw new IllegalStateException("Unsupported encrypted class resource format");
        }
        byte[] keyId = Base64.getDecoder().decode(parts[2]);
        byte[] salt = Base64.getDecoder().decode(parts[3]);
        byte[] nonce = Base64.getDecoder().decode(parts[4]);
        byte[] expectedHash = Base64.getDecoder().decode(parts[5]);
        if (nonce.length != 12) throw new SecurityException("Invalid AES-GCM nonce length for encrypted class: " + binaryName);
        byte[] aad = matchingAad(binaryName.replace('.', '/'), resourcePath, strategy, expectedHash);
        if (aad == null) {
            throw new SecurityException("Encrypted class metadata AAD mismatch: " + binaryName);
        }
        return new ParsedMetadata(strategy, keyId, salt, nonce, aad, "aes-256".equals(strategy) ? 32 : 16);
    }

    private static byte[] decryptBytes(byte[] data, String strategy, byte[] key, byte[] nonce, byte[] aad) throws Exception {
        if (!("aes-128".equals(strategy) || "aes-256".equals(strategy))) {
            throw new IllegalStateException("Unsupported encrypted class resource format");
        }
        if (nonce == null || nonce.length != 12) throw new SecurityException("Invalid AES-GCM nonce length");
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(key, "AES");
        cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, new javax.crypto.spec.GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(data);
    }

    private static byte[] aad(String className, String resourcePath, String strategy, String keyMode) {
        return ("javashroud:class-encryption:v2:" + className + ":" + resourcePath + ":" + strategy + ":" + keyMode + ":sealed-runtime")
            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    private static byte[] matchingAad(String className, String resourcePath, String strategy, byte[] expectedHash) throws Exception {
        String[] keyModes = new String[] { "per-class", "global" };
        for (String keyMode : keyModes) {
            byte[] candidate = aad(className, resourcePath, strategy, keyMode);
            if (constantTimeEquals(MessageDigest.getInstance("SHA-256").digest(candidate), expectedHash)) return candidate;
        }
        return null;
    }

    private static boolean constantTimeEquals(byte[] left, byte[] right) {
        if (left == null || right == null || left.length != right.length) return false;
        int diff = 0;
        for (int i = 0; i < left.length; i++) diff |= (left[i] ^ right[i]) & 0xFF;
        return diff == 0;
    }

    private static final class ParsedMetadata {
        final String strategy;
        final byte[] keyId;
        final byte[] salt;
        final byte[] nonce;
        final byte[] aad;
        final int keyLength;
        ParsedMetadata(String strategy, byte[] keyId, byte[] salt, byte[] nonce, byte[] aad, int keyLength) {
            this.strategy = strategy;
            this.keyId = keyId;
            this.salt = salt;
            this.nonce = nonce;
            this.aad = aad;
            this.keyLength = keyLength;
        }
    }

    /**
     * Parse method descriptor to get parameter Class[] types.
     * Example: "(ILjava/lang/String;[B)V" -> [int.class, String.class, byte[].class]
     */
    private static Class<?>[] parseParamTypes(ClassLoader loader, String descriptor) throws ClassNotFoundException {
        // Extract parameter section between first '(' and ')'
        int start = descriptor.indexOf('(');
        int end = descriptor.indexOf(')');
        if (start < 0 || end < 0) return new Class<?>[0];

        String params = descriptor.substring(start + 1, end);
        java.util.List<Class<?>> types = new java.util.ArrayList<>();
        int i = 0;
        while (i < params.length()) {
            char c = params.charAt(i);
            switch (c) {
                case 'Z': types.add(boolean.class); i++; break;
                case 'B': types.add(byte.class); i++; break;
                case 'C': types.add(char.class); i++; break;
                case 'S': types.add(short.class); i++; break;
                case 'I': types.add(int.class); i++; break;
                case 'J': types.add(long.class); i++; break;
                case 'F': types.add(float.class); i++; break;
                case 'D': types.add(double.class); i++; break;
                case 'L': {
                    int semi = params.indexOf(';', i);
                    String className = params.substring(i + 1, semi).replace('/', '.');
                    types.add(loader.loadClass(className));
                    i = semi + 1;
                    break;
                }
                case '[': {
                    // Array type: count dimensions, then parse element type
                    int dims = 0;
                    while (i < params.length() && params.charAt(i) == '[') { dims++; i++; }
                    // Parse element type
                    if (i < params.length()) {
                        char elem = params.charAt(i);
                        Class<?> base;
                        switch (elem) {
                            case 'Z': base = boolean.class; i++; break;
                            case 'B': base = byte.class; i++; break;
                            case 'C': base = char.class; i++; break;
                            case 'S': base = short.class; i++; break;
                            case 'I': base = int.class; i++; break;
                            case 'J': base = long.class; i++; break;
                            case 'F': base = float.class; i++; break;
                            case 'D': base = double.class; i++; break;
                            case 'L': {
                                int semi = params.indexOf(';', i);
                                String className = params.substring(i + 1, semi).replace('/', '.');
                                base = loader.loadClass(className);
                                i = semi + 1;
                                break;
                            }
                            default: throw new ClassNotFoundException("Unknown type: " + elem);
                        }
                        // Build array class
                        StringBuilder arrayDesc = new StringBuilder();
                        for (int d = 0; d < dims; d++) arrayDesc.append('[');
                        arrayDesc.append(elem);
                        if (elem == 'L') {
                            int semi = params.indexOf(';', i - 1);
                            // Already advanced i past the element
                        }
                        types.add(java.lang.reflect.Array.newInstance(base, new int[dims]).getClass());
                    }
                    break;
                }
                default: i++; break;
            }
        }
        return types.toArray(new Class<?>[0]);
    }

    /**
     * Single shared ClassLoader that decrypt-defines every encrypted class in one
     * namespace. For a requested class it first checks the central manifest: if the
     * class is encrypted it decrypts and defines it here; otherwise it delegates to
     * the parent loader. Because all mutually-referencing encrypted classes (e.g. an
     * outer class and its inner classes) are defined by THIS loader, they share a
     * runtime package and access each other without IllegalAccessError.
     */
    private static final class SharedDecryptingClassLoader extends ClassLoader {
        SharedDecryptingClassLoader(ClassLoader parent) {
            super(parent);
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] bytes = decryptClassBytes(name);
            if (bytes == null) {
                throw new ClassNotFoundException(name);
            }
 ProtectionDomain domain = ClassEncryptionLoaderHelper.class.getProtectionDomain(); 
 return defineClass(name, bytes, 0, bytes.length, domain); 
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> c = findLoadedClass(name);
                if (c == null) {
                    // Prefer locally decrypting an encrypted application class so it
                    // and its siblings stay in this loader's namespace; only fall
                    // back to the parent (JDK + non-encrypted classes) otherwise.
                    if (manifest().containsKey(name)) {
                        c = findClass(name);
                    } else {
                        c = super.loadClass(name, false);
                    }
                }
                if (resolve) resolveClass(c);
                return c;
            }
        }
    }
}
