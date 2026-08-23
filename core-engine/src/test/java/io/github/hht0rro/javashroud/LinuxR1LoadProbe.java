package io.github.hht0rro.javashroud;

/**
 * WSL/Linux probe that loads the locked glibc 2.17 cdylib and exercises the
 * source-named R1 JNI surface after {@code j.l} recovery.
 */
public final class LinuxR1LoadProbe {
    private LinuxR1LoadProbe() {}

    static native int nativeInit(String platform);

    static native int nativeHeartbeat();

    static native boolean nativeInstallAkenSessionNonce(byte[] startupNonce);

    static native Object nativeExecuteAkenVmPage(
            long entryToken,
            byte[] encodedHandle,
            int pageIndex,
            byte[] callSiteProof,
            Object[] args
    );

    static native String nativeOpenAkenString(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    static native byte[] nativeReadAkenClassPage(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    static native void nativeConsumeAkenNativeChunk(byte[] encodedHandle, int pageIndex, byte[] callSiteProof);

    public static void main(String[] args) {
        if (args.length < 1 || args.length > 2) {
            System.err.println("usage: LinuxR1LoadProbe <libjsrt_ffi.so> [catalog-sidecar]");
            System.exit(2);
        }
        System.setProperty("j.l", "io/github/hht0rro/javashroud/LinuxR1LoadProbe");
        if (args.length == 2) {
            System.setProperty("j.c", args[1]);
        }
        System.load(args[0]);
        System.out.println("INIT=" + nativeInit("linux-x64"));
        System.out.println("BEAT=" + nativeHeartbeat());
        if (args.length == 2) {
            System.out.println("STR=" + nativeOpenAkenString(readAll("page-3.handle"), 3, readAll("page-3.proof")));
            System.out.println("CLS=" + new String(nativeReadAkenClassPage(readAll("page-4.handle"), 4, readAll("page-4.proof"))));
            nativeConsumeAkenNativeChunk(readAll("page-5.handle"), 5, readAll("page-5.proof"));
            System.out.println("NAT=ok");
            System.out.println("VM=" + nativeExecuteAkenVmPage(0L, readAll("page-6.handle"), 6, readAll("page-6.proof"), null));
        }
    }

    private static byte[] readAll(String name) {
        String root = System.getProperty("j.c");
        try {
            return java.nio.file.Files.readAllBytes(java.nio.file.Path.of(root, name));
        } catch (Exception error) {
            throw new IllegalStateException(name, error);
        }
    }
}
