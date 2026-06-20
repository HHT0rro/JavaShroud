package io.github.hht0rro.javashroud.transforms.protection;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.util.concurrent.ConcurrentHashMap;

public final class HiddenClassDeployerHelper {
    private static final ConcurrentHashMap<String, MethodHandle> HANDLES = new ConcurrentHashMap<>();

    private HiddenClassDeployerHelper() { }

    public static MethodHandle getOrCreateHandle(String className, String methodName, String descriptor) {
        String key = className + "." + methodName + descriptor;
        MethodHandle handle = HANDLES.get(key);
        if (handle != null) return handle;
        throw new IllegalStateException("Hidden class handle is not registered: " + key);
    }

    public static Class<?> defineHiddenClass(MethodHandles.Lookup lookup, byte[] classBytes) {
        try {
            return lookup.defineHiddenClass(classBytes, true).lookupClass();
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("Hidden class deployment failed", e);
        }
    }
}
