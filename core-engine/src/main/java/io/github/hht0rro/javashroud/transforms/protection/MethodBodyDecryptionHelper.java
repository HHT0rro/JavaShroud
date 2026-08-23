package io.github.hht0rro.javashroud.transforms.protection;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Base64;
import java.security.MessageDigest;
import java.util.Arrays;

public final class MethodBodyDecryptionHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }

    private MethodBodyDecryptionHelper() { }
    public static Object invokeEncrypted(String resourcePath, String metadata, String strategy, int isStatic, Class<?> ownerClass, Object thisRef, Object[] args) throws Exception {
        return invokeEncrypted(resourcePath, metadata, strategy, "lazy-decrypt", isStatic, ownerClass, thisRef, args);
    }

    public static Object invokeEncrypted(String resourcePath, String metadata, String strategy, String mode, int isStatic, Class<?> ownerClass, Object thisRef, Object[] args) throws Exception {
        String effectiveMode = mode == null ? "lazy-decrypt" : mode;
        // A decrypted method and its hidden class are per-invocation state.
        // Do not retain Method/class/instance objects in a global cache: that
        // would keep authenticated method material live across calls and
        // across artifact/session generations.
        Method method = defineAndFindMethod(resourcePath, metadata, strategy, effectiveMode, ownerClass);
        Object[] actualArgs = actualArgs(method, isStatic, method.getDeclaringClass(), thisRef, args);
        try {
            return method.invoke(null, actualArgs);
        } catch (InvocationTargetException e) {
            throw sneakyThrow(e.getCause());
        }
    }

    private static Method defineAndFindMethod(String resourcePath, String metadataText, String requestedStrategy, String mode, Class<?> ownerClass) throws Exception {
        byte[] encrypted = null;
        ParsedMetadata metadata = null;
        byte[] key = null;
        byte[] classBytes = null;
        try {
            encrypted = readResource(resourcePath);
            metadata = parseMetadata(ownerClass, resourcePath, metadataText, requestedStrategy, mode);
            key = JniMicrokernelHelper.deriveClassEncryptionKey(metadata.keyId, metadata.salt, metadata.keyLength);
            classBytes = JniMicrokernelHelper.decryptClassBytes(
                metadata.keyId,
                metadata.salt,
                metadata.nonce,
                encrypted,
                metadata.aad,
                metadata.keyLength
            );
            Class<?> wrapperClass = defineClass(ownerClass, classBytes);
            return findEntryMethod(wrapperClass);
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
            if (encrypted != null) Arrays.fill(encrypted, (byte) 0);
            if (classBytes != null) Arrays.fill(classBytes, (byte) 0);
            if (metadata != null) metadata.wipe();
        }
    }

    private static byte[] readResource(String resourcePath) throws Exception {
        InputStream in = MethodBodyDecryptionHelper.class.getClassLoader().getResourceAsStream(resourcePath);
        if (in == null) throw new IllegalStateException("Encrypted method resource not found: " + resourcePath);
        try (InputStream input = in; ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = input.read(buffer)) != -1) out.write(buffer, 0, read);
            return out.toByteArray();
        }
    }

    private static Class<?> defineClass(Class<?> ownerClass, byte[] classBytes) throws Exception {
        MethodHandles.Lookup lookup = MethodHandles.privateLookupIn(ownerClass, MethodHandles.lookup());
        return lookup.defineHiddenClass(classBytes, true, MethodHandles.Lookup.ClassOption.NESTMATE).lookupClass();
    }

    private static Method findEntryMethod(Class<?> wrapperClass) {
        for (Method method : wrapperClass.getDeclaredMethods()) {
            if ((method.getModifiers() & java.lang.reflect.Modifier.STATIC) != 0) {
                method.setAccessible(true);
                return method;
            }
        }
        throw new IllegalStateException("No static entry method in decrypted wrapper: " + wrapperClass.getName());
    }

    private static Object[] actualArgs(Method method, int isStatic, Class<?> wrapperClass, Object thisRef, Object[] args) throws Exception {
        Object[] providedArgs = args == null ? new Object[0] : args;
        if (isStatic != 0) return providedArgs;
        if (method.getParameterCount() == providedArgs.length + 1) {
            return prependReceiver(thisRef, providedArgs);
        }
        if (method.getParameterCount() == providedArgs.length) {
            return providedArgs;
        }
        throw new IllegalStateException(
            "Decrypted wrapper parameter mismatch: expected " + method.getParameterCount() +
                " arguments for " + method.getDeclaringClass().getName() + "." + method.getName() +
                " but received " + providedArgs.length + " original arguments"
        );
    }

    private static Object[] prependReceiver(Object receiver, Object[] args) {
        Object[] actualArgs = new Object[args.length + 1];
        actualArgs[0] = receiver;
        System.arraycopy(args, 0, actualArgs, 1, args.length);
        return actualArgs;
    }

    @SuppressWarnings("unchecked")
    private static <T extends Throwable> RuntimeException sneakyThrow(Throwable throwable) throws T {
        throw (T) throwable;
    }

    private static ParsedMetadata parseMetadata(Class<?> ownerClass, String resourcePath, String metadata, String requestedStrategy, String mode) throws Exception {
        String[] parts = metadata == null ? null : metadata.split(":", -1);
        if (parts == null || parts.length != 6 || !"v2".equals(parts[0])) {
            throw new SecurityException("Unsupported encrypted method metadata format");
        }
        String strategy = parts[1];
        if (!("aes-128".equals(strategy) || "aes-256".equals(strategy)) || !strategy.equals(requestedStrategy)) {
            throw new SecurityException("Encrypted method strategy mismatch");
        }
        byte[] keyId = Base64.getDecoder().decode(parts[2]);
        byte[] salt = Base64.getDecoder().decode(parts[3]);
        byte[] nonce = Base64.getDecoder().decode(parts[4]);
        if (nonce.length != 12) throw new SecurityException("Invalid AES-GCM nonce length for encrypted method resource");
        byte[] aad = aad(strategy, mode);
        byte[] expectedHash = Base64.getDecoder().decode(parts[5]);
        if (!constantTimeEquals(MessageDigest.getInstance("SHA-256").digest(aad), expectedHash)) {
            throw new SecurityException("Encrypted method metadata AAD mismatch");
        }
        return new ParsedMetadata(strategy, keyId, salt, nonce, aad, "aes-256".equals(strategy) ? 32 : 16);
    }

    private static byte[] aad(String strategy, String mode) {
        return ("javashroud:method-body:v2:" + strategy + ":" + mode + ":sealed-runtime")
            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
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

        void wipe() {
            Arrays.fill(keyId, (byte) 0);
            Arrays.fill(salt, (byte) 0);
            Arrays.fill(nonce, (byte) 0);
            Arrays.fill(aad, (byte) 0);
        }
    }
}
