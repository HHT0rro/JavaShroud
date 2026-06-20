package io.github.hht0rro.javashroud.transforms.protection;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Base64;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class MethodBodyDecryptionHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private static final ConcurrentHashMap<String, Method> METHOD_CACHE = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Object> INSTANCE_CACHE = new ConcurrentHashMap<>();

    private MethodBodyDecryptionHelper() { }
    public static Object invokeEncrypted(String resourcePath, String keyBase64, String strategy, int isStatic, Class<?> ownerClass, Object thisRef, Object[] args) throws Exception {
        byte[] encrypted = readResource(resourcePath);
        byte[] key = Base64.getDecoder().decode(keyBase64);
        byte[] classBytes = decryptBytes(encrypted, key, strategy);
        Class<?> wrapperClass = defineClass(ownerClass, classBytes);
        Method method = findEntryMethod(wrapperClass);
        Object[] actualArgs = actualArgs(method, isStatic, wrapperClass, thisRef, args);
        try {
            return method.invoke(null, actualArgs);
        } catch (InvocationTargetException e) {
            throw sneakyThrow(e.getCause());
        }
    }

    public static byte[] decryptBytes(byte[] encrypted, byte[] key, String strategy) throws Exception {
        if (encrypted == null || key == null || key.length == 0) return encrypted;
        if ("aes-128".equals(strategy) || "aes-256".equals(strategy)) return aesDecrypt(encrypted, key);
        throw new IllegalStateException("Unsupported encrypted method resource format");
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
        String cacheKey = wrapperClass.getName();
        Method cached = METHOD_CACHE.get(cacheKey);
        if (cached != null) return cached;
        for (Method method : wrapperClass.getDeclaredMethods()) {
            if ((method.getModifiers() & java.lang.reflect.Modifier.STATIC) != 0) {
                method.setAccessible(true);
                METHOD_CACHE.put(cacheKey, method);
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

    private static Object instanceFor(Class<?> wrapperClass, Object thisRef) throws Exception {
        String cacheKey = wrapperClass.getName();
        Object cached = INSTANCE_CACHE.get(cacheKey);
        if (cached != null) return cached;
        try {
            Object created = wrapperClass.getDeclaredConstructor().newInstance();
            INSTANCE_CACHE.put(cacheKey, created);
            return created;
        } catch (NoSuchMethodException ignored) {
            return thisRef;
        }
    }

    private static byte[] aesDecrypt(byte[] encrypted, byte[] key) throws Exception {
        if (encrypted.length < 16) {
            throw new IllegalStateException("Encrypted method resource is missing AES IV");
        }
        byte[] iv = new byte[16];
        byte[] payload = new byte[encrypted.length - 16];
        System.arraycopy(encrypted, 0, iv, 0, 16);
        System.arraycopy(encrypted, 16, payload, 0, payload.length);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        return cipher.doFinal(payload);
    }
}


