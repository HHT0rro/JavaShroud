package io.github.hht0rro.javashroud.transforms.protection;

import java.lang.invoke.CallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Runtime bootstrap that resolves opaque indy target tokens. Java 8 compatible. */
public final class IndyTargetBootstrap {
    private static final byte[] MAGIC = new byte[] {'I', 'T', 'K', '1'};
    private static final byte VERSION = 3;
    private static final byte[] AAD_DOMAIN = new byte[] {'J', 'S', 'I', 'T', 'K', 'A', 'A', 'D', VERSION};
    private static final byte[] KEY_DOMAIN = new byte[] {'J', 'S', 'I', 'T', 'K', 'K', 'D', 'F', VERSION};

    private IndyTargetBootstrap() {}

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

    public static MethodHandle resolveHandle(
        MethodHandles.Lookup lookup,
        String indyName,
        MethodType type,
        String token
    ) throws Exception {
        byte[] key = null;
        byte[] raw = null;
        byte[] plaintext = null;
        byte[] aad = null;
        try {
            raw = Base64.getUrlDecoder().decode(token);
            if (raw.length <= MAGIC.length + 1 + 4 + 32 + 12 + 16) {
                throw new SecurityException("indy target token is truncated");
            }
            for (int i = 0; i < MAGIC.length; i++) {
                if (raw[i] != MAGIC[i]) throw new SecurityException("indy target token is invalid");
            }
            if (raw[MAGIC.length] != VERSION) {
                throw new SecurityException("indy target token version is unsupported");
            }
            int pos = MAGIC.length + 1;
            int siteIndex = readU32be(raw, pos);
            pos += 4;
            int digestOff = pos;
            pos += 32;
            byte[] nonce = Arrays.copyOfRange(raw, pos, pos + 12);
            pos += 12;
            byte[] sealed = Arrays.copyOfRange(raw, pos, raw.length);
            String callerOwner = lookup.lookupClass().getName().replace('.', '/');
            key = siteKey(raw, digestOff, callerOwner, indyName, type.toMethodDescriptorString(), siteIndex);
            aad = buildAad(callerOwner, indyName, type, siteIndex, raw, digestOff);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            plaintext = cipher.doFinal(sealed);
            String[] parts = new String(plaintext, "UTF-8").split("\u0000", -1);
            if (parts.length != 5) throw new SecurityException("indy target token payload is invalid");
            Class<?> owner = Class.forName(parts[0].replace('/', '.'));
            MethodType methodType = MethodType.fromMethodDescriptorString(parts[2], owner.getClassLoader());
            int tag = Integer.parseInt(parts[3]);
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
            if (aad != null) Arrays.fill(aad, (byte) 0);
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

    private static byte[] siteKey(
        byte[] raw,
        int digestOff,
        String callerOwner,
        String indyName,
        String methodType,
        int siteIndex
    ) throws Exception {
        byte[] callerOwnerUtf8 = callerOwner.getBytes("UTF-8");
        byte[] indyNameUtf8 = indyName.getBytes("UTF-8");
        byte[] methodTypeUtf8 = methodType.getBytes("UTF-8");
        byte[] info = new byte[16 + callerOwnerUtf8.length + indyNameUtf8.length + methodTypeUtf8.length];
        int offset = 0;
        offset = writeLenPrefixed(info, offset, callerOwnerUtf8);
        offset = writeLenPrefixed(info, offset, indyNameUtf8);
        offset = writeLenPrefixed(info, offset, methodTypeUtf8);
        info[offset] = (byte) (siteIndex >>> 24);
        info[offset + 1] = (byte) (siteIndex >>> 16);
        info[offset + 2] = (byte) (siteIndex >>> 8);
        info[offset + 3] = (byte) siteIndex;
        byte[] ikm = Arrays.copyOfRange(raw, digestOff, digestOff + 32);
        try {
            return hkdfSha256(ikm, KEY_DOMAIN, info, 16);
        } finally {
            Arrays.fill(info, (byte) 0);
            Arrays.fill(ikm, (byte) 0);
        }
    }

    private static byte[] hkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length) throws Exception {
        byte[] prk = hmacSha256(salt.length == 0 ? new byte[32] : salt, ikm);
        byte[] output = new byte[length];
        byte[] previous = new byte[0];
        int produced = 0;
        int counter = 1;
        try {
            while (produced < length) {
                byte[] next = hmacSha256Concat(prk, previous, info, (byte) counter);
                Arrays.fill(previous, (byte) 0);
                previous = next;
                int take = Math.min(previous.length, length - produced);
                System.arraycopy(previous, 0, output, produced, take);
                produced += take;
                counter++;
            }
            return output;
        } finally {
            Arrays.fill(prk, (byte) 0);
            Arrays.fill(previous, (byte) 0);
        }
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }

    private static byte[] hmacSha256Concat(byte[] key, byte[] previous, byte[] info, byte counter) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        mac.update(previous);
        mac.update(info);
        mac.update(counter);
        return mac.doFinal();
    }

    private static int writeLenPrefixed(byte[] dest, int offset, byte[] utf8) {
        dest[offset] = (byte) (utf8.length >>> 24);
        dest[offset + 1] = (byte) (utf8.length >>> 16);
        dest[offset + 2] = (byte) (utf8.length >>> 8);
        dest[offset + 3] = (byte) utf8.length;
        System.arraycopy(utf8, 0, dest, offset + 4, utf8.length);
        return offset + 4 + utf8.length;
    }

    private static byte[] buildAad(
        String callerOwner,
        String indyName,
        MethodType type,
        int siteIndex,
        byte[] raw,
        int digestOff
    ) throws Exception {
        byte[] callerOwnerUtf8 = callerOwner.getBytes("UTF-8");
        byte[] indyNameUtf8 = indyName.getBytes("UTF-8");
        byte[] methodTypeUtf8 = type.toMethodDescriptorString().getBytes("UTF-8");
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        digest.update(AAD_DOMAIN);
        updateU32be(digest, callerOwnerUtf8.length);
        digest.update(callerOwnerUtf8);
        updateU32be(digest, indyNameUtf8.length);
        digest.update(indyNameUtf8);
        updateU32be(digest, methodTypeUtf8.length);
        digest.update(methodTypeUtf8);
        updateU32be(digest, siteIndex);
        digest.update(raw, digestOff, 32);
        updateU32be(digest, VERSION & 0xFF);
        return digest.digest();
    }

    private static int readU32be(byte[] src, int offset) {
        return ((src[offset] & 0xFF) << 24)
            | ((src[offset + 1] & 0xFF) << 16)
            | ((src[offset + 2] & 0xFF) << 8)
            | (src[offset + 3] & 0xFF);
    }

    private static void updateU32be(MessageDigest digest, int value) {
        digest.update((byte) (value >>> 24));
        digest.update((byte) (value >>> 16));
        digest.update((byte) (value >>> 8));
        digest.update((byte) value);
    }
}
