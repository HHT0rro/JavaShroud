package io.github.hht0rro.javashroud.transforms.protection;

import java.lang.invoke.CallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Runtime bootstrap that resolves opaque indy target tokens. Java 8 compatible. */
public final class IndyTargetBootstrap {
    private static final int[] LANES = new int[] {0x4A535230, 0x4A535231, 0x4A535232, 0x4A535233};
    private static final byte[] MAGIC = new byte[] {'I', 'T', 'K', '1'};

    private IndyTargetBootstrap() {}

    static void installKey(byte[] key) {
        if (key == null || key.length != 16) {
            throw new SecurityException("indy target key is invalid");
        }
        for (int i = 0; i < 4; i++) {
            int offset = i * 4;
            LANES[i] = ((key[offset] & 0xFF) << 24)
                | ((key[offset + 1] & 0xFF) << 16)
                | ((key[offset + 2] & 0xFF) << 8)
                | (key[offset + 3] & 0xFF);
        }
    }

    public static CallSite bootstrap(
        MethodHandles.Lookup lookup,
        String name,
        MethodType type,
        String originalBsmToken,
        Object[] encoded
    ) throws Throwable {
        MethodHandle originalBsm = resolveHandle(lookup, originalBsmToken);
        Object[] decoded = new Object[encoded == null ? 0 : encoded.length];
        try {
            for (int i = 0; i < decoded.length; i++) {
                Object arg = encoded[i];
                if (arg instanceof String && isToken((String) arg)) {
                    decoded[i] = resolveHandle(lookup, (String) arg);
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

    public static MethodHandle resolveHandle(MethodHandles.Lookup lookup, String token) throws Exception {
        byte[] key = currentKey();
        byte[] raw = null;
        byte[] plaintext = null;
        try {
            raw = Base64.getUrlDecoder().decode(token);
            if (raw.length <= MAGIC.length + 1 + 12 + 16) {
                throw new SecurityException("indy target token is truncated");
            }
            for (int i = 0; i < MAGIC.length; i++) {
                if (raw[i] != MAGIC[i]) throw new SecurityException("indy target token is invalid");
            }
            if (raw[MAGIC.length] != 1) throw new SecurityException("indy target token version is unsupported");
            byte[] nonce = Arrays.copyOfRange(raw, MAGIC.length + 1, MAGIC.length + 1 + 12);
            byte[] sealed = Arrays.copyOfRange(raw, MAGIC.length + 1 + 12, raw.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            plaintext = cipher.doFinal(sealed);
            String[] parts = new String(plaintext, "UTF-8").split("\u0000", -1);
            if (parts.length != 5) throw new SecurityException("indy target token payload is invalid");
            Class<?> owner = Class.forName(parts[0].replace('/', '.'));
            MethodType methodType = MethodType.fromMethodDescriptorString(parts[2], owner.getClassLoader());
            int tag = Integer.parseInt(parts[3]);
            boolean iface = "1".equals(parts[4]);
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
        } catch (SecurityException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new SecurityException("indy target token authentication failed");
        } finally {
            if (key != null) Arrays.fill(key, (byte) 0);
            if (raw != null) Arrays.fill(raw, (byte) 0);
            if (plaintext != null) Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static boolean isToken(String value) {
        if (value == null || value.length() < 24) return false;
        try {
            byte[] raw = Base64.getUrlDecoder().decode(value);
            if (raw.length <= MAGIC.length) return false;
            for (int i = 0; i < MAGIC.length; i++) {
                if (raw[i] != MAGIC[i]) return false;
            }
            return true;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    private static byte[] currentKey() {
        byte[] key = new byte[16];
        for (int i = 0; i < 4; i++) {
            int lane = LANES[i];
            key[i * 4] = (byte) (lane >>> 24);
            key[i * 4 + 1] = (byte) (lane >>> 16);
            key[i * 4 + 2] = (byte) (lane >>> 8);
            key[i * 4 + 3] = (byte) lane;
        }
        return key;
    }
}
