package io.github.hht0rro.javashroud.transforms.protection;

/**
 * Runtime helper for anti-dump enforcement.
 * Sensitive logic delegated to native js_kernel library.
 */
public final class AntiDumpRuntimeHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private AntiDumpRuntimeHelper() { }

    public static native void nativeInitializeProtection(String protectionLevel);
    public static native void nativeInitializeProtection(String protectionLevel, Class<?> ownerClass);

    public static void initializeProtection(String protectionLevel) {
        initializeProtection(protectionLevel, null);
    }

    public static void initializeProtection(String protectionLevel, Class<?> ownerClass) {
        String level = protectionLevel == null ? "field-scramble" : protectionLevel;
        if (!JniMicrokernelHelper.isNativeLoaded()) {
            if ("field-scramble".equals(level)) return;
            throw new SecurityException("anti-dump protection level " + level + " requires the sealed native kernel");
        }
        try {
            nativeInitializeProtection(level, ownerClass);
        } catch (UnsatisfiedLinkError e) {
            if ("field-scramble".equals(level)) return;
            throw new SecurityException("anti-dump native protection entrypoint unavailable", e);
        } catch (SecurityException e) {
            throw e;
        }
    }

    public static String scrambleString(String value, String owner, String field) {
        if (value == null) return null;
        char[] chars = value.toCharArray();
        xorChars(chars, owner, field);
        return new String(chars);
    }

    public static String unscrambleString(String value, String owner, String field) {
        return scrambleString(value, owner, field);
    }

    public static byte[] scrambleBytes(byte[] value, String owner, String field) {
        if (value == null) return null;
        byte[] copy = value.clone();
        int key = key(owner, field);
        for (int i = 0; i < copy.length; i++) {
            copy[i] = (byte) (copy[i] ^ (key >>> ((i & 3) * 8)));
        }
        return copy;
    }

    public static byte[] unscrambleBytes(byte[] value, String owner, String field) {
        return scrambleBytes(value, owner, field);
    }

    public static char[] scrambleChars(char[] value, String owner, String field) {
        if (value == null) return null;
        char[] copy = value.clone();
        xorChars(copy, owner, field);
        return copy;
    }

    public static char[] unscrambleChars(char[] value, String owner, String field) {
        return scrambleChars(value, owner, field);
    }

    private static void xorChars(char[] chars, String owner, String field) {
        int key = key(owner, field);
        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (chars[i] ^ (key >>> ((i & 1) * 16)));
        }
    }

    private static int key(String owner, String field) {
        int h = 0x811C9DC5;
        String material = String.valueOf(owner) + '#' + String.valueOf(field);
        for (int i = 0; i < material.length(); i++) {
            h ^= material.charAt(i);
            h *= 0x01000193;
        }
        return h == 0 ? 0x5A17B00B : h;
    }
}
