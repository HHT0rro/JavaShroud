package io.github.hht0rro.javashroud;

/**
 * WSL/Linux probe that loads the locked glibc 2.17 cdylib and exercises the
 * source-named R1 JNI surface after {@code j.l} recovery.
 */
public final class LinuxR1LoadProbe {
    private LinuxR1LoadProbe() {}

    static native int nativeInit(String platform);

    static native int nativeHeartbeat();

    static native boolean nativeInstallSessionNonce(byte[] startupNonce);

    static native int nativeInstallCatalog(byte[] directory, byte[] bundle);

    static native Object nativeExecuteVmPage(long entryToken, byte[] packedRequest, Object[] args);

    static native String nativeOpenStringPage(byte[] packedRequest);

    static native byte[] nativeReadClassPage(byte[] packedRequest);

    static native void nativeConsumeNativeSegment(byte[] packedRequest);

    static native int nativeInitializeDefense(String surface, String profile);

    static native int nativeProbeDefense(String surface, String point);

    static native byte[] nativeTransformDefense(byte[] material, String binding);

    public static void main(String[] args) {
        if (args.length < 1 || args.length > 2) {
            System.err.println("usage: LinuxR1LoadProbe <libqp_ffi.so> [catalog-sidecar]");
            System.exit(2);
        }
        System.setProperty("j.l", "io/github/hht0rro/javashroud/LinuxR1LoadProbe");
        System.setProperty("j.m", bindingMap());
        if (args.length == 2) {
            System.setProperty("j.c", args[1]);
        }
        System.load(args[0]);
        System.out.println("INIT=" + nativeInit("linux-x64"));
        System.out.println("BEAT=" + nativeHeartbeat());
        if (args.length == 2) {
            System.out.println("STR=" + nativeOpenStringPage(pack(readAll("page-3.handle"), 3, readAll("page-3.proof"))));
            System.out.println("CLS=" + new String(nativeReadClassPage(pack(readAll("page-4.handle"), 4, readAll("page-4.proof")))));
            nativeConsumeNativeSegment(pack(readAll("page-5.handle"), 5, readAll("page-5.proof")));
            System.out.println("NAT=ok");
            System.out.println("VM=" + nativeExecuteVmPage(0L, pack(readAll("page-6.handle"), 6, readAll("page-6.proof")), null));
        }
    }

    private static String bindingMap() {
        String owner = "io/github/hht0rro/javashroud/transforms/protection/qp/QpBridge";
        String[][] methods = {
                {"nativeInit", "(Ljava/lang/String;)I", "nativeInit"},
                {"nativeHeartbeat", "()I", "nativeHeartbeat"},
                {"nativeInstallSessionNonce", "([B)Z", "nativeInstallSessionNonce"},
                {"nativeInstallCatalog", "([B[B)I", "nativeInstallCatalog"},
                {"nativeExecuteVmPage", "(J[B[Ljava/lang/Object;)Ljava/lang/Object;", "nativeExecuteVmPage"},
                {"nativeOpenStringPage", "([B)Ljava/lang/String;", "nativeOpenStringPage"},
                {"nativeReadClassPage", "([B)[B", "nativeReadClassPage"},
                {"nativeConsumeNativeSegment", "([B)V", "nativeConsumeNativeSegment"},
                {"nativeInitializeDefense", "(Ljava/lang/String;Ljava/lang/String;)I", "nativeInitializeDefense"},
                {"nativeProbeDefense", "(Ljava/lang/String;Ljava/lang/String;)I", "nativeProbeDefense"},
                {"nativeTransformDefense", "([BLjava/lang/String;)[B", "nativeTransformDefense"},
        };
        StringBuilder result = new StringBuilder();
        for (String[] method : methods) {
            try {
                byte[] digest = java.security.MessageDigest.getInstance("SHA-256")
                        .digest(("QP-BINDING-V1|" + owner + "#" + method[0] + "#" + method[1])
                                .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                for (int i = 0; i < 8; i++) result.append(String.format("%02x", digest[i] & 0xff));
            } catch (java.security.NoSuchAlgorithmException error) {
                throw new IllegalStateException(error);
            }
            result.append('=').append(method[2]).append('\n');
        }
        return result.toString();
    }

    private static byte[] readAll(String name) {
        String root = System.getProperty("j.c");
        try {
            return java.nio.file.Files.readAllBytes(java.nio.file.Path.of(root, name));
        } catch (Exception error) {
            throw new IllegalStateException(name, error);
        }
    }

    private static byte[] pack(byte[] handle, int pageIndex, byte[] proof) {
        byte[] packed = new byte[24 + 4 + proof.length];
        System.arraycopy(handle, 0, packed, 0, 24);
        packed[24] = (byte) (pageIndex >>> 24);
        packed[25] = (byte) (pageIndex >>> 16);
        packed[26] = (byte) (pageIndex >>> 8);
        packed[27] = (byte) pageIndex;
        System.arraycopy(proof, 0, packed, 28, proof.length);
        return packed;
    }
}
