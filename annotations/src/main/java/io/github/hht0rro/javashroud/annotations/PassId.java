package io.github.hht0rro.javashroud.annotations;

/** Stable JavaShroud pass identifiers accepted by {@link JavaShroudPass#id()}. */
public final class PassId {
    private PassId() {}

    public static final String ANTI_DECOMPILER_STRUCTURE = "anti-decompiler-structure";
    public static final String CALLSITE_ROTATION_PROTECTION = "callsite-rotation-protection";
    public static final String CONDY_CONSTANT_INDIRECTION = "condy-constant-indirection";
    public static final String CONTROL_FLOW_FLATTENING = "control-flow-flattening";
    public static final String CONTROL_FLOW_OBFUSCATION = "control-flow-obfuscation";
    public static final String EXCEPTION_SEMANTIC_VIRTUALIZATION = "exception-semantic-virtualization";
    public static final String FIELD_STRING_ENCRYPTION = "field-string-encryption";
    public static final String INTEGER_CONSTANT_OBFUSCATION = "integer-constant-obfuscation";
    public static final String INVOKE_DYNAMIC_INDIRECTION = "invoke-dynamic-indirection";
    public static final String JNI_MICROKERNEL_LOADER = "jni-microkernel-loader";
    public static final String MEMBER_HIDE = "member-hide";
    public static final String METHOD_VIRTUALIZATION = "method-virtualization";
    public static final String OS_ANTI_DEBUG = "os-anti-debug";
    public static final String OS_ANTI_VM = "os-anti-vm";
    public static final String REFERENCE_PROXY = "reference-proxy";
    public static final String RENAME_CLASSES = "rename-classes";
    public static final String RENAME_FIELDS = "rename-fields";
    public static final String RENAME_METHODS = "rename-methods";
    public static final String RENAME_PACKAGES = "rename-packages";
    public static final String STATIC_INIT_PERTURBATION = "static-init-perturbation";
    public static final String STRING_ENCRYPTION = "string-encryption";
    public static final String STRIP_COMPILE_DEBUG_INFO = "strip-compile-debug-info";
}
