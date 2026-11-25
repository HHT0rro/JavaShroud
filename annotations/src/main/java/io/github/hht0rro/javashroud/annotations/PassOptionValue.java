package io.github.hht0rro.javashroud.annotations;

/** Enum-like option values accepted by JavaShroud pass schemas. */
public final class PassOptionValue {
    private PassOptionValue() {}

    public static final class AlgebraicFamily {
        private AlgebraicFamily() {}
        public static final String QUADRATIC_RESIDUE = "quadratic-residue";
        public static final String BITWISE_IDENTITY = "bitwise-identity";
        public static final String MODULAR_ARITHMETIC = "modular-arithmetic";
        public static final String MIXED = "mixed";
    }

    public static final class BindingSource {
        private BindingSource() {}
        public static final String HARDWARE_ID = "hardware-id";
        public static final String JVM_PARAMS = "jvm-params";
        public static final String CERTIFICATE_FINGERPRINT = "certificate-fingerprint";
        public static final String COMBINED = "combined";
    }

    public static final class CollisionPolicy {
        private CollisionPolicy() {}
        public static final String APPEND_INDEX = "append-index";
        public static final String REHASH = "rehash";
        public static final String FAIL = "fail";
    }

    public static final class DictionaryStyle {
        private DictionaryStyle() {}
        public static final String IILIII = "iiliii";
        public static final String OOO0OO = "ooO0oO";
        public static final String NNMNMNM = "nnmnmnm";
        public static final String SEQUENTIAL = "sequential";
        public static final String UNICODE_CONFUSABLE = "unicode-confusable";
        public static final String CUSTOM_FILE = "custom-file";
    }

    public static final class DispatchMode {
        private DispatchMode() {}
        public static final String LOOKUPSWITCH = "lookupswitch";
        public static final String IF_CHAIN = "if-chain";
        public static final String TABLESWITCH_HYBRID = "tableswitch-hybrid";
    }

    public static final class EncryptionStrategy {
        private EncryptionStrategy() {}
        public static final String AES_128 = "aes-128";
        public static final String AES_256 = "aes-256";
    }

    public static final class HandlerComplexity {
        private HandlerComplexity() {}
        public static final String NOP = "nop";
        public static final String FIELD_WRITE = "field-write";
        public static final String METHOD_CALL = "method-call";
    }

    public static final class MethodSelection {
        private MethodSelection() {}
        public static final String SAFE = "safe";
        public static final String CRITICAL_AUTO = "critical-auto";
        public static final String CRITICAL_PLUS = "critical-plus";
        public static final String ALL_COMPATIBLE = "all-compatible";
    }

    public static final class Scope {
        private Scope() {}
        public static final String ALL_STRINGS = "all-strings";
        public static final String ANNOTATED = "annotated";
        public static final String LENGTH_THRESHOLD = "length-threshold";
    }

    public static final class StandardAggressive {
        private StandardAggressive() {}
        public static final String STANDARD = "standard";
        public static final String AGGRESSIVE = "aggressive";
    }

    public static final class TargetPlatform {
        private TargetPlatform() {}
        public static final String AUTO = "auto";
        public static final String WINDOWS_X64 = "windows-x64";
        public static final String LINUX_X64 = "linux-x64";
        public static final String MACOS_X64 = "macos-x64";
        public static final String MACOS_ARM64 = "macos-arm64";
    }
}