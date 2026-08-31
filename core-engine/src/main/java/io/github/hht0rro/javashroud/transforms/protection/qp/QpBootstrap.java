package io.github.hht0rro.javashroud.transforms.protection.qp;

import java.lang.invoke.CallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Runtime bootstrap for opaque invokedynamic targets.
 *
 * Cryptographic token parsing and key derivation are owned by the Native
 * bridge. This class only validates the authenticated target description and
 * performs the JVM lookup required to link the call site.
 */
public final class QpBootstrap {
    private static final int MAGIC_SIZE = 4;
    private static final int VERSION = 3;
    private static final int MAX_TOKEN_BYTES = 64 * 1024;

    private QpBootstrap() {}

    public static CallSite bootstrap(
        MethodHandles.Lookup lookup,
        String name,
        MethodType type,
        String originalBsmToken,
        Object[] encoded
    ) throws Throwable {
        MethodHandle originalBsm = resolveHandle(lookup, name, type, originalBsmToken);
        Object[] decoded = new Object[encoded == null ? 0 : encoded.length];
        try {
            for (int i = 0; i < decoded.length; i++) {
                Object arg = encoded[i];
                if (arg instanceof String && isToken((String) arg)) {
                    decoded[i] = resolveHandle(lookup, name, type, (String) arg);
                } else {
                    decoded[i] = arg;
                }
            }
            Object[] invokeArgs = new Object[3 + decoded.length];
            invokeArgs[0] = lookup;
            invokeArgs[1] = name;
            invokeArgs[2] = type;
            System.arraycopy(decoded, 0, invokeArgs, 3, decoded.length);
            return (CallSite) originalBsm.invokeWithArguments(invokeArgs);
        } finally {
            Arrays.fill(decoded, null);
        }
    }

    /** Resolve one token through the authenticated Native terminal. */
    public static MethodHandle resolveHandle(
        MethodHandles.Lookup lookup,
        String indyName,
        MethodType type,
        String token
    ) throws Exception {
        byte[] raw = null;
        byte[] plaintext = null;
        try {
            raw = decodeToken(token);
            String callerOwner = lookup.lookupClass().getName().replace('.', '/');
            plaintext = QpBridge.openTargetToken(
                raw,
                callerOwner,
                indyName,
                type.toMethodDescriptorString()
            );
            return resolveAuthenticatedTarget(lookup, plaintext);
        } catch (SecurityException error) {
            throw error;
        } catch (Exception error) {
            throw new SecurityException("indy target token authentication failed", error);
        } finally {
            if (raw != null) Arrays.fill(raw, (byte) 0);
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static MethodHandle resolveAuthenticatedTarget(
        MethodHandles.Lookup lookup,
        byte[] plaintext
    ) throws Exception {
        if (plaintext == null || plaintext.length == 0 || plaintext.length > 512) {
            throw new SecurityException("indy target token payload is invalid");
        }
        String[] parts = new String(plaintext, StandardCharsets.UTF_8).split("\\u0000", -1);
        if (parts.length != 5 || parts[0].length() == 0 || parts[1].length() == 0 || parts[2].length() == 0) {
            throw new SecurityException("indy target token payload is invalid");
        }
        Class<?> owner = Class.forName(parts[0].replace('/', '.'));
        MethodType methodType = MethodType.fromMethodDescriptorString(parts[2], owner.getClassLoader());
        int tag;
        try {
            tag = Integer.parseInt(parts[3]);
        } catch (NumberFormatException error) {
            throw new SecurityException("indy target handle tag is invalid", error);
        }
        if (!("0".equals(parts[4]) || "1".equals(parts[4]))) {
            throw new SecurityException("indy target interface flag is invalid");
        }
        switch (tag) {
            case 6:
                return lookup.findStatic(owner, parts[1], methodType);
            case 5:
                return lookup.findVirtual(owner, parts[1], methodType);
            case 9:
                return lookup.findVirtual(owner, parts[1], methodType);
            case 7:
                return lookup.findSpecial(owner, parts[1], methodType, lookup.lookupClass());
            default:
                throw new SecurityException("indy target handle tag is unsupported");
        }
    }

    private static byte[] decodeToken(String token) {
        if (token == null || token.length() < 8) {
            throw new SecurityException("indy target token is invalid");
        }
        try {
            byte[] raw = Base64.getUrlDecoder().decode(token);
            if (raw.length > MAX_TOKEN_BYTES || raw.length <= MAGIC_SIZE + 1 || raw[MAGIC_SIZE] != VERSION) {
                Arrays.fill(raw, (byte) 0);
                throw new SecurityException("indy target token is invalid");
            }
            return raw;
        } catch (IllegalArgumentException error) {
            throw new SecurityException("indy target token is invalid", error);
        }
    }

    private static boolean isToken(String value) {
        if (value == null || value.length() < 8) return false;
        byte[] raw = null;
        try {
            raw = Base64.getUrlDecoder().decode(value);
            return raw.length > MAGIC_SIZE + 1 && raw.length <= MAX_TOKEN_BYTES && raw[MAGIC_SIZE] == VERSION;
        } catch (RuntimeException ignored) {
            return false;
        } finally {
            if (raw != null) Arrays.fill(raw, (byte) 0);
        }
    }
}
