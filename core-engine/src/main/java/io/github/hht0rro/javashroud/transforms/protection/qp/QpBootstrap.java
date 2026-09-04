package io.github.hht0rro.javashroud.transforms.protection.qp;

import java.lang.invoke.CallSite;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Arrays;
import java.util.Base64;

/**
 * Runtime bootstrap for opaque invokedynamic targets.
 *
 * Cryptographic token parsing, target lookup, and bootstrap invocation are
 * owned by the Native bridge. Java only transports opaque token envelopes and
 * never receives a plaintext target description or business MethodHandle.
 */
public final class QpBootstrap {
    private static final int MAGIC_SIZE = 4;
    private static final int VERSION = 6;
    private static final int MAX_TOKEN_BYTES = 64 * 1024;

    private QpBootstrap() {}

    public static CallSite bootstrap(
        MethodHandles.Lookup lookup,
        String name,
        MethodType type,
        String originalBsmToken,
        Object[] encoded
    ) throws Throwable {
        byte[] originalBsm = decodeToken(originalBsmToken);
        Object[] decoded = new Object[encoded == null ? 0 : encoded.length];
        try {
            for (int i = 0; i < decoded.length; i++) {
                Object arg = encoded[i];
                if (arg instanceof String && isToken((String) arg)) {
                    decoded[i] = decodeToken((String) arg);
                } else {
                    decoded[i] = arg;
                }
            }
            return QpBridge.linkTargetSite(lookup, name, type, originalBsm, decoded);
        } finally {
            Arrays.fill(originalBsm, (byte) 0);
            for (Object arg : decoded) {
                if (arg instanceof byte[]) Arrays.fill((byte[]) arg, (byte) 0);
            }
            Arrays.fill(decoded, null);
        }
    }

    /**
     * Validates and decodes an opaque token envelope for a relocated helper.
     * The method is public because sealing may place QpBootstrap and
     * QpCallsiteBridge in different runtime packages; it returns only the
     * authenticated opaque bytes and never resolves a business target.
     */
    public static byte[] decodeToken(String token) {
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
