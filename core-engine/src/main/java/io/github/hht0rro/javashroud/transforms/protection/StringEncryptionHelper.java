package io.github.hht0rro.javashroud.transforms.protection;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodType;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodHandleInfo;

/**
 * Thin AKEN StringPage terminal.
 *
 * <p>The authenticated page is materialized as the returned JVM {@link String}
 * inside the native bridge.  No page plaintext byte array crosses into Java and
 * this helper deliberately retains no soft/strong cache, cache key, or decoded
 * value after the caller consumes the result.</p>
 */
public final class StringEncryptionHelper {
    private StringEncryptionHelper() { }

    /*
     * These are deliberately equivalent bootstrap entry points rather than a
     * second decoder.  Generated call sites select one of them per literal;
     * each entry only binds the already-authenticated native terminal handle
     * supplied as a static indy argument.  No plaintext, page bytes, or cache
     * is retained by the bootstrap.
     */
    public static CallSite q0(MethodHandles.Lookup lookup, String invokedName, MethodType invokedType, MethodHandle target) {
        return bindAkenStringCallSite(lookup, invokedName, invokedType, target);
    }

    public static CallSite m7(MethodHandles.Lookup lookup, String invokedName, MethodType invokedType, MethodHandle target) {
        return bindAkenStringCallSite(lookup, invokedName, invokedType, target);
    }

    public static CallSite x3(MethodHandles.Lookup lookup, String invokedName, MethodType invokedType, MethodHandle target) {
        return bindAkenStringCallSite(lookup, invokedName, invokedType, target);
    }

    public static CallSite v8(MethodHandles.Lookup lookup, String invokedName, MethodType invokedType, MethodHandle target) {
        return bindAkenStringCallSite(lookup, invokedName, invokedType, target);
    }

    public static CallSite u0(MethodHandles.Lookup lookup, String invokedName, MethodType invokedType, String packed) {
        return bindAkenStringToken(lookup, invokedName, invokedType, packed);
    }

    public static CallSite u1(MethodHandles.Lookup lookup, String invokedName, MethodType invokedType, String packed) {
        return bindAkenStringToken(lookup, invokedName, invokedType, packed);
    }

    public static CallSite u2(MethodHandles.Lookup lookup, String invokedName, MethodType invokedType, String packed) {
        return bindAkenStringToken(lookup, invokedName, invokedType, packed);
    }

    public static CallSite u3(MethodHandles.Lookup lookup, String invokedName, MethodType invokedType, String packed) {
        return bindAkenStringToken(lookup, invokedName, invokedType, packed);
    }

    public static byte[] materializeAkenStringToken(String packed) {
        if (packed == null || packed.isEmpty()) {
            throw new SecurityException("AKEN string token is invalid");
        }
        final byte[] token;
        try {
            token = java.util.Base64.getUrlDecoder().decode(packed);
        } catch (RuntimeException error) {
            throw new SecurityException("AKEN string token is invalid", error);
        }
        if (token.length < 24 + 4 + 1 || token.length > 24 + 4 + 4096) {
            java.util.Arrays.fill(token, (byte) 0);
            throw new SecurityException("AKEN string token is invalid");
        }
        return token;
    }

    private static CallSite bindAkenStringToken(
        MethodHandles.Lookup lookup,
        String invokedName,
        MethodType invokedType,
        String packed
    ) {
        if (lookup == null || invokedName == null || invokedName.isEmpty() ||
            invokedType == null || !invokedType.equals(MethodType.methodType(byte[].class))) {
            throw new SecurityException("AKEN string token bootstrap binding is invalid");
        }
        byte[] token = materializeAkenStringToken(packed);
        return new ConstantCallSite(MethodHandles.constant(byte[].class, token));
    }

    private static CallSite bindAkenStringCallSite(
        MethodHandles.Lookup lookup,
        String invokedName,
        MethodType invokedType,
        MethodHandle target
    ) {
        if (lookup == null || invokedName == null || invokedName.isEmpty() || target == null ||
            invokedType == null || !invokedType.equals(akenStringCallSiteType()) ||
            !target.type().equals(invokedType)) {
            throw new SecurityException("AKEN string bootstrap binding is invalid");
        }
        /*
         * Do not trust an arbitrary same-signature MethodHandle supplied by a
         * caller.  Generated indy sites carry a direct static handle to this
         * helper's build-renamed terminal.  Reveal the direct handle and bind
         * only that provenance; adapted handles, instance handles, and foreign
         * owners fail closed before a call site is published.
         */
        final MethodHandleInfo info;
        try {
            info = MethodHandles.lookup().revealDirect(target);
        } catch (IllegalArgumentException | SecurityException error) {
            throw new SecurityException("AKEN string bootstrap target provenance is invalid", error);
        }
        Class<?> helperClass = MethodHandles.lookup().lookupClass();
        if (info.getReferenceKind() != MethodHandleInfo.REF_invokeStatic ||
            info.getDeclaringClass() != helperClass ||
            !info.getMethodType().equals(invokedType) ||
            !isStringTerminalMethodName(helperClass, info.getName())) {
            throw new SecurityException("AKEN string bootstrap target provenance is invalid");
        }
        return new ConstantCallSite(target);
    }

    private static boolean isStringTerminalMethodName(Class<?> helperClass, String name) {
        if (name == null || name.isEmpty()) return false;
        String terminalName = null;
        for (java.lang.reflect.Method method : helperClass.getDeclaredMethods()) {
            if (!java.lang.reflect.Modifier.isStatic(method.getModifiers()) ||
                !method.getReturnType().equals(String.class) ||
                !java.util.Arrays.equals(method.getParameterTypes(), new Class<?>[] {
                    byte[].class,
                })) {
                continue;
            }
            if (terminalName != null && !terminalName.equals(method.getName())) return false;
            terminalName = method.getName();
        }
        return terminalName != null && terminalName.equals(name);
    }

    private static MethodType akenStringCallSiteType() {
        return MethodType.methodType(String.class, byte[].class);
    }

    /*
     * The source helper intentionally has no public repeatable page-open API.
     * RuntimeArtifactSealing promotes only the relocated, build-renamed bridge
     * when an authenticated call site in a sealed application needs to link to
     * it.  Keeping this terminal package-private prevents an unsealed helper
     * class from exposing a stable reflection-friendly whole-page decoder.
     */
    static String invokeAkenStringTerminal(byte[] token) {
        if (token == null || token.length < 24 + 4 + 1) {
            throw new SecurityException("AKEN string page request is invalid");
        }
        byte[] encodedHandle = java.util.Arrays.copyOfRange(token, 0, 24);
        int pageIndex = ((token[24] & 0xFF) << 24)
            | ((token[25] & 0xFF) << 16)
            | ((token[26] & 0xFF) << 8)
            | (token[27] & 0xFF);
        byte[] callSiteProof = java.util.Arrays.copyOfRange(token, 28, token.length);
        try {
            return invokeAkenStringTerminal(encodedHandle, pageIndex, callSiteProof);
        } finally {
            java.util.Arrays.fill(encodedHandle, (byte) 0);
            java.util.Arrays.fill(callSiteProof, (byte) 0);
        }
    }

    static String invokeAkenStringTerminal(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        requireAkenStringPageRequest(encodedHandle, pageIndex, callSiteProof);
        try {
            String decoded = JniMicrokernelHelper.openAkenString(encodedHandle, pageIndex, callSiteProof);
            if (decoded == null) {
                throw new SecurityException("AKEN string page access failed closed");
            }
            return decoded;
        } catch (UnsatisfiedLinkError error) {
            throw new SecurityException("AKEN string page native terminal is not registered for the sealed helper", error);
        }
    }

    private static void requireAkenStringPageRequest(byte[] encodedHandle, int pageIndex, byte[] callSiteProof) {
        if (encodedHandle == null || encodedHandle.length != 24 || pageIndex < 0 ||
            callSiteProof == null || callSiteProof.length == 0 || callSiteProof.length > 4096) {
            throw new SecurityException("AKEN string page request is invalid");
        }
    }
}
