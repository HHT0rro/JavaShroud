package io.github.hht0rro.javashroud.transforms.protection;

import java.lang.invoke.CallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class BootstrapEncryptionHelper {
    static { JniMicrokernelHelper.loadKernel("loader", "auto", "vm-diverse"); }
    private BootstrapEncryptionHelper() { }

    public static byte[] decryptBytes(String encryptedBase64, String keyBase64) {
        try {
            byte[] encrypted = Base64.getDecoder().decode(encryptedBase64);
            byte[] key = Base64.getDecoder().decode(keyBase64);
            if (encrypted.length < 16 || (encrypted.length - 16) % 16 != 0) {
                throw new BootstrapMethodError("Invalid encrypted bootstrap payload");
            }
            byte[] iv = new byte[16];
            byte[] payload = new byte[encrypted.length - 16];
            System.arraycopy(encrypted, 0, iv, 0, 16);
            System.arraycopy(encrypted, 16, payload, 0, payload.length);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return cipher.doFinal(payload);
        } catch (BootstrapMethodError error) {
            throw error;
        } catch (Exception error) {
            throw new BootstrapMethodError("Invalid encrypted bootstrap payload", error);
        }
    }

    public static CallSite encryptedBootstrap(MethodHandles.Lookup lookup, String name, MethodType type, Object... args) throws Throwable {
        if (args.length < 2 || !(args[0] instanceof String) || !(args[1] instanceof MethodHandle)) {
            throw new BootstrapMethodError("Invalid encrypted bootstrap arguments");
        }
        String keyBase64 = (String) args[0];
        MethodHandle originalBootstrap = (MethodHandle) args[1];
        Object[] decryptedArgs = new Object[args.length - 2];
        for (int i = 2; i < args.length; i++) {
            Object arg = args[i];
            if (arg instanceof String) {
                decryptedArgs[i - 2] = new String(decryptBytes((String) arg, keyBase64), java.nio.charset.StandardCharsets.UTF_8);
            } else {
                decryptedArgs[i - 2] = arg;
            }
        }
        Object[] bootstrapArgs = new Object[3 + decryptedArgs.length];
        bootstrapArgs[0] = lookup;
        bootstrapArgs[1] = name;
        bootstrapArgs[2] = type;
        System.arraycopy(decryptedArgs, 0, bootstrapArgs, 3, decryptedArgs.length);
        return (CallSite) originalBootstrap.invokeWithArguments(bootstrapArgs);
    }
}
