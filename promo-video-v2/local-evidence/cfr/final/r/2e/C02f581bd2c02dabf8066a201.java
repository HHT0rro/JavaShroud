/*
 * Decompiled with CFR 0.152.
 */
package r.2e;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.lang.constant.Constable;
import java.lang.invoke.CallSite;
import java.lang.invoke.LambdaConversionException;
import java.lang.invoke.LambdaMetafactory;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.security.CodeSource;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.ProtectionDomain;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class C02f581bd2c02dabf8066a201 {
    private static final /* synthetic */ int LOAD_FAILED = -1;
    private static final /* synthetic */ int LOAD_UNTRIED = 0;
    private static final /* synthetic */ int LOAD_LOADING = 1;
    private static final /* synthetic */ int LOAD_READY = 2;
    private static volatile /* synthetic */ int loadState;
    private static volatile /* synthetic */ String loadMessage;
    private static volatile /* synthetic */ boolean diversifiedVmEnabled;
    private static volatile /* synthetic */ String vmSelfCheck;
    private static volatile /* synthetic */ long nativeBootToken;
    private static volatile /* synthetic */ boolean nativeSelfCheckFailed;
    private static volatile /* synthetic */ boolean sealedNativeBindingsPublished;
    private static volatile /* synthetic */ boolean bootSecretEnvBindingEnabled;
    private static volatile /* synthetic */ String[] bootSecretExpectedFingerprints;
    private static volatile /* synthetic */ byte[][] runtimeResourceKeys;
    private static volatile /* synthetic */ int runtimeResourcePartitionCount;
    private static volatile /* synthetic */ int anchorResourcePartition;
    private static volatile /* synthetic */ byte[] expectedShellBindingCommitment;
    private static volatile /* synthetic */ Thread expectedShellBindingThread;
    private static volatile /* synthetic */ int shellBindingHandoffState;
    private static volatile /* synthetic */ byte[] nativeShellBootSecret;
    private static volatile /* synthetic */ Thread nativeShellBootSecretThread;
    private static final /* synthetic */ String SEALED_NATIVE_INDEX_RESOURCE = "META-INF/c3/9ffd262323f896/ea/3b92aee4fca5b3a29852e53f630315.txt";
    private static final /* synthetic */ String SEALED_NATIVE_BINDINGS_RESOURCE = "META-INF/c3/9ffd262323f896/91/af83ef1c73a2ba030c7792a874cc72.xml";
    private static final /* synthetic */ String BOOT_MATERIAL_RESOURCE = "META-INF/.r/boot.dat";
    private static final /* synthetic */ String EMBEDDED_BOOT_SECRET_RESOURCE = "META-INF/c3/9ffd262323f896/47/bb9978181c950edcf4e33f3a50c1ed.xml";
    private static final /* synthetic */ String BOOT_SECRET_ENV = "JAVASHROUD_BOOT_SECRET_V1";
    private static final /* synthetic */ String BOOT_SECRET_FILE_ENV = "JAVASHROUD_BOOT_SECRET_FILE_V1";
    private static final /* synthetic */ int BOOT_MATERIAL_VERSION = 2;
    private static final /* synthetic */ int HARDENED_BOOT_MATERIAL_VERSION = 3;
    private static final /* synthetic */ int SHELL_BINDING_COMMITMENT_SIZE = 32;
    private static final /* synthetic */ byte[] BOOT_MATERIAL_AAD;
    private static final /* synthetic */ byte[] HARDENED_BOOT_MATERIAL_AAD;
    private static final /* synthetic */ byte[] BOOT_SIDECAR_TEXT_PREFIX;
    private static final /* synthetic */ byte[] BOOT_SIDECAR_KEY_DOMAIN;
    private static final /* synthetic */ String VM_CATALOG_RESOURCE = "META-INF/c3/9ffd262323f896/60/f755fc98d2cf13d04248f904384e83.xml";
    private static final /* synthetic */ int RUNTIME_RESOURCE_VERSION = 7;
    private static final /* synthetic */ int NATIVE_ANCHOR_KEY_SLOT = 16;
    private static final /* synthetic */ int BOOTSTRAP_NATIVE_INDEX_VERSION = 1;
    private static final /* synthetic */ int ZSTD_MAGIC = -47205080;
    private static final /* synthetic */ int LAMBDA_FLAG_SERIALIZABLE = 1;
    private static final /* synthetic */ int LAMBDA_FLAG_MARKERS = 2;
    private static final /* synthetic */ int LAMBDA_FLAG_BRIDGES = 4;
    private static final /* synthetic */ int LAMBDA_SUPPORTED_FLAGS = 7;
    private static final /* synthetic */ ConcurrentMap<String, MethodHandle> SAM_LAMBDA_CACHE;
    private static final /* synthetic */ ConcurrentMap<String, Class<?>> SAM_BRIDGE_INTERFACE_CACHE;
    private static final /* synthetic */ int[] AES_RCON;
    private static /* synthetic */ byte[] aesSboxTable;

    private C02f581bd2c02dabf8066a201() {
    }

    static native /* synthetic */ int nativeInit(String var0);

    static native /* synthetic */ int nativeVerify(byte[] var0, byte[] var1);

    static native /* synthetic */ int nativeHeartbeat();

    static native /* synthetic */ String nativeGetVersion();

    static native /* synthetic */ long nativeGetBootToken();

    static native /* synthetic */ boolean nativeInstallBootMaterial(byte[] var0);

    static native /* synthetic */ boolean nativeInstallBootEnvelope(byte[] var0, byte[] var1);

    static native /* synthetic */ boolean nativeIsBootMaterialReady();

    static native /* synthetic */ void nativeAbortBootMaterial();

    static native /* synthetic */ void nativePreloadRuntimeResources(byte[] var0, byte[] var1, byte[] var2);

    static native /* synthetic */ byte[] nativeDecodeRuntimeResource(byte[] var0);

    public static native /* synthetic */ byte[] nativeDecryptAes(byte[] var0, byte[] var1, byte[] var2);

    public static native /* synthetic */ byte[] nativeDeriveClassEncryptionKey(byte[] var0, byte[] var1, int var2);

    static native /* synthetic */ byte[] nativeDecryptClassBytes(byte[] var0, byte[] var1, byte[] var2, byte[] var3, byte[] var4, int var5);

    static native /* synthetic */ String nativeSealedBindingKey(byte[] var0);

    public static native /* synthetic */ String nativeGetMachineFingerprint();

    public static native /* synthetic */ Object nativeExecuteVmResource(long var0, String var2, Object[] var3);

    public static native /* synthetic */ Object nativeExecuteVmResourceByToken(long var0, Object[] var2);

    public static /* synthetic */ Object m_667d12f93462a65a(long l, String string, Object[] objectArray) {
        if (loadState == 0) {
            C02f581bd2c02dabf8066a201.m_d7c5053f05b22be5("vm", "auto", "vm-diverse");
        }
        if (C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            C02f581bd2c02dabf8066a201.ensureSealedNativeBindingsPublished();
            return C02f581bd2c02dabf8066a201.nativeExecuteVmResource(l, string, objectArray);
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }

    public static /* synthetic */ Object m_8db0405476ff174c(long l, Object[] objectArray) {
        if (loadState == 0) {
            C02f581bd2c02dabf8066a201.m_d7c5053f05b22be5("vm", "auto", "vm-diverse");
        }
        if (C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            C02f581bd2c02dabf8066a201.ensureSealedNativeBindingsPublished();
            return C02f581bd2c02dabf8066a201.nativeExecuteVmResourceByToken(l, objectArray);
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }

    public static native /* synthetic */ void nativeExecuteVmResourceVoid(long var0);

    public static native /* synthetic */ int nativeExecuteVmResourceInt(long var0);

    public static native /* synthetic */ int nativeExecuteVmResourceIntInt(long var0, int var2);

    public static native /* synthetic */ void nativeExecuteVmResourceIntVoid(long var0, int var2);

    public static /* synthetic */ void m_9b3e84d577d85e6a(long l) {
        if (loadState == 0) {
            C02f581bd2c02dabf8066a201.m_d7c5053f05b22be5("vm", "auto", "vm-diverse");
        }
        if (C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            C02f581bd2c02dabf8066a201.ensureSealedNativeBindingsPublished();
            C02f581bd2c02dabf8066a201.nativeExecuteVmResourceVoid(l);
            return;
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }

    public static /* synthetic */ int m_eab8b43ae4cf7c93(long l) {
        if (loadState == 0) {
            C02f581bd2c02dabf8066a201.m_d7c5053f05b22be5("vm", "auto", "vm-diverse");
        }
        if (C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            C02f581bd2c02dabf8066a201.ensureSealedNativeBindingsPublished();
            return C02f581bd2c02dabf8066a201.nativeExecuteVmResourceInt(l);
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }

    public static /* synthetic */ int m_d88a91e78cc13152(long l, int n) {
        if (loadState == 0) {
            C02f581bd2c02dabf8066a201.m_d7c5053f05b22be5("vm", "auto", "vm-diverse");
        }
        if (C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            C02f581bd2c02dabf8066a201.ensureSealedNativeBindingsPublished();
            return C02f581bd2c02dabf8066a201.nativeExecuteVmResourceIntInt(l, n);
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }

    public static /* synthetic */ void m_4aa9011d9a43fd30(long l, int n) {
        if (loadState == 0) {
            C02f581bd2c02dabf8066a201.m_d7c5053f05b22be5("vm", "auto", "vm-diverse");
        }
        if (C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            C02f581bd2c02dabf8066a201.ensureSealedNativeBindingsPublished();
            C02f581bd2c02dabf8066a201.nativeExecuteVmResourceIntVoid(l, n);
            return;
        }
        throw new SecurityException("method-virtualization requires a bundled sealed JNI VM kernel; native kernel not loaded (" + loadMessage + ")");
    }

    public static /* synthetic */ Runnable createRunnableLambda(String string, String string2, String string3, int n, Object[] objectArray) {
        return (Runnable)C02f581bd2c02dabf8066a201.createSamLambda("run", "()Ljava/lang/Runnable;", string, string2, string3, n, "()V", "()V", "0;;", objectArray);
    }

    public static /* synthetic */ Object createSamLambda(String string, String string2, String string3, String string4, String string5, int n, String string6, String string7, String string8, Object[] objectArray) {
        Object[] objectArray2 = objectArray == null ? new Object[]{} : Arrays.copyOf(objectArray, objectArray.length);
        MethodHandle methodHandle = C02f581bd2c02dabf8066a201.resolveSamLambdaTarget(string3, string4, string5, n);
        String string9 = C02f581bd2c02dabf8066a201.descriptorReturnInternalName(string2);
        try {
            ClassLoader classLoader = C02f581bd2c02dabf8066a201.class.getClassLoader();
            Class<?> clazz = Class.forName(string9.replace('/', '.'), false, classLoader);
            MethodType methodType = MethodType.fromMethodDescriptorString(string6, classLoader);
            MethodType methodType2 = MethodType.fromMethodDescriptorString(string7, classLoader);
            I4d804b1d48de1013 i4d804b1d48de1013 = C02f581bd2c02dabf8066a201.parseSamLambdaOptions(string8, classLoader, methodType);
            if (!clazz.isInterface() || string.length() == 0 || methodType.parameterCount() != methodType2.parameterCount()) {
                throw new IllegalArgumentException("invalid virtualized SAM recipe");
            }
            if ((i4d804b1d48de1013.flags & 1) == 0) {
                return C02f581bd2c02dabf8066a201.createNonSerializableSamLambda(string, string2, string3, methodHandle, methodType, methodType2, i4d804b1d48de1013, objectArray2);
            }
            MethodHandle methodHandle2 = C02f581bd2c02dabf8066a201.adaptSamLambdaTarget(methodHandle, objectArray2, methodType2);
            return C02f581bd2c02dabf8066a201.createSamProxy(clazz, string, methodHandle2, i4d804b1d48de1013, string3, string4, string5, n, string7, objectArray2);
        }
        catch (ReflectiveOperationException reflectiveOperationException) {
            throw new IllegalStateException("cannot create virtualized SAM lambda", reflectiveOperationException);
        }
    }

    private static /* synthetic */ Object createNonSerializableSamLambda(String string, String string2, String string3, MethodHandle methodHandle, MethodType methodType, MethodType methodType2, I4d804b1d48de1013 i4d804b1d48de1013, Object[] objectArray) throws ReflectiveOperationException {
        CallSite callSite;
        MethodHandles.Lookup lookup;
        ClassLoader classLoader = C02f581bd2c02dabf8066a201.class.getClassLoader();
        Class<?> clazz = Class.forName(string3.replace('/', '.'), false, classLoader);
        try {
            lookup = C02f581bd2c02dabf8066a201.privateLookup(clazz);
        }
        catch (ReflectiveOperationException | RuntimeException exception) {
            lookup = MethodHandles.lookup();
        }
        MethodType methodType3 = MethodType.fromMethodDescriptorString(string2, classLoader);
        try {
            if (i4d804b1d48de1013.flags == 0) {
                callSite = LambdaMetafactory.metafactory(lookup, string, methodType3, methodType, methodHandle, methodType2);
            } else {
                ArrayList<Constable> arrayList = new ArrayList<Constable>();
                arrayList.add(methodType);
                arrayList.add(methodHandle);
                arrayList.add(methodType2);
                arrayList.add(Integer.valueOf(i4d804b1d48de1013.flags));
                if ((i4d804b1d48de1013.flags & 2) != 0) {
                    arrayList.add(Integer.valueOf(i4d804b1d48de1013.markerInterfaces.length));
                    arrayList.addAll(Arrays.asList(i4d804b1d48de1013.markerInterfaces));
                }
                if ((i4d804b1d48de1013.flags & 4) != 0) {
                    arrayList.add(Integer.valueOf(i4d804b1d48de1013.bridgeDescriptors.length));
                    for (String string4 : i4d804b1d48de1013.bridgeDescriptors) {
                        arrayList.add(MethodType.fromMethodDescriptorString(string4, classLoader));
                    }
                }
                callSite = LambdaMetafactory.altMetafactory(lookup, string, methodType3, arrayList.toArray());
            }
        }
        catch (LambdaConversionException lambdaConversionException) {
            throw new ReflectiveOperationException("cannot link virtualized SAM lambda", lambdaConversionException);
        }
        try {
            return callSite.getTarget().invokeWithArguments(objectArray);
        }
        catch (Error | RuntimeException throwable) {
            throw throwable;
        }
        catch (Throwable throwable) {
            throw new ReflectiveOperationException("cannot instantiate virtualized SAM lambda", throwable);
        }
    }

    private static /* synthetic */ MethodHandle resolveSamLambdaTarget(String string, String string2, String string3, int n) {
        String string4 = string + '\u0000' + string2 + '\u0000' + string3 + '\u0000' + n;
        MethodHandle methodHandle = (MethodHandle)SAM_LAMBDA_CACHE.get(string4);
        if (methodHandle != null) {
            return methodHandle;
        }
        try {
            ClassLoader classLoader = C02f581bd2c02dabf8066a201.class.getClassLoader();
            Class<?> clazz = Class.forName(string.replace('/', '.'), false, classLoader);
            String string5 = C02f581bd2c02dabf8066a201.resolveBoundMethodName(string, string2, string3);
            MethodType methodType = C02f581bd2c02dabf8066a201.descriptorMethodType(string3, clazz.getClassLoader());
            MethodHandle methodHandle2 = C02f581bd2c02dabf8066a201.resolveMethodHandle(clazz, string5, methodType, n);
            if (methodHandle2 == null) {
                throw new IllegalArgumentException("unsupported lambda implementation handle tag: " + n);
            }
            MethodHandle methodHandle3 = SAM_LAMBDA_CACHE.putIfAbsent(string4, methodHandle2);
            return methodHandle3 == null ? methodHandle2 : methodHandle3;
        }
        catch (ReflectiveOperationException reflectiveOperationException) {
            throw new IllegalStateException("cannot link virtualized SAM lambda", reflectiveOperationException);
        }
    }

    private static /* synthetic */ Object invokeSamLambdaTarget(MethodHandle methodHandle, Object[] objectArray, Object[] objectArray2) throws Throwable {
        int n = objectArray.length + objectArray2.length;
        if (n != methodHandle.type().parameterCount()) {
            throw new IllegalStateException("lambda argument count mismatch");
        }
        Object[] objectArray3 = new Object[n];
        System.arraycopy(objectArray, 0, objectArray3, 0, objectArray.length);
        System.arraycopy(objectArray2, 0, objectArray3, objectArray.length, objectArray2.length);
        return methodHandle.invokeWithArguments(objectArray3);
    }

    private static /* synthetic */ MethodHandle adaptSamLambdaTarget(MethodHandle methodHandle, Object[] objectArray, MethodType methodType) throws ReflectiveOperationException {
        MethodHandle methodHandle2 = MethodHandles.lookup().findStatic(C02f581bd2c02dabf8066a201.class, "invokeSamLambdaTarget", MethodType.methodType(Object.class, MethodHandle.class, Object[].class, Object[].class));
        methodHandle2 = MethodHandles.insertArguments(methodHandle2, 0, methodHandle, objectArray);
        return methodHandle2.asCollector(Object[].class, methodType.parameterCount()).asType(methodType);
    }

    private static /* synthetic */ Object createSamProxy(Class<?> clazz, String string, MethodHandle methodHandle, I4d804b1d48de1013 i4d804b1d48de1013, String string2, String string3, String string4, int n, String string5, Object[] objectArray) throws ReflectiveOperationException {
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        linkedHashSet.add(clazz);
        linkedHashSet.addAll(Arrays.asList(i4d804b1d48de1013.markerInterfaces));
        if ((i4d804b1d48de1013.flags & 1) != 0) {
            linkedHashSet.add(Serializable.class);
        }
        if (i4d804b1d48de1013.bridgeDescriptors.length != 0) {
            linkedHashSet.add(C02f581bd2c02dabf8066a201.samBridgeInterface(string, i4d804b1d48de1013.bridgeDescriptors));
        }
        return Proxy.newProxyInstance(C02f581bd2c02dabf8066a201.class.getClassLoader(), linkedHashSet.toArray(new Class[0]), (InvocationHandler)new I8df6ac0025772ff2(clazz.getName(), string, string2, string3, string4, n, string5, objectArray, methodHandle));
    }

    private static /* synthetic */ I4d804b1d48de1013 parseSamLambdaOptions(String string, ClassLoader classLoader, MethodType methodType) throws ClassNotFoundException {
        Object object;
        int n;
        String[] stringArray;
        String[] stringArray2 = stringArray = string == null ? new String[]{} : string.split(";", -1);
        if (stringArray.length != 3) {
            throw new IllegalArgumentException("invalid virtualized SAM options");
        }
        try {
            n = Integer.parseInt(stringArray[0], 16);
        }
        catch (NumberFormatException numberFormatException) {
            throw new IllegalArgumentException("invalid virtualized SAM flags", numberFormatException);
        }
        if (n < 0 || (n & 0xFFFFFFF8) != 0) {
            throw new IllegalArgumentException("unsupported virtualized SAM flags");
        }
        String[] stringArray3 = C02f581bd2c02dabf8066a201.splitSamOptionList(stringArray[1]);
        String[] stringArray4 = C02f581bd2c02dabf8066a201.splitSamOptionList(stringArray[2]);
        if ((n & 2) == 0 && stringArray3.length != 0) {
            throw new IllegalArgumentException("unexpected virtualized SAM markers");
        }
        if ((n & 4) == 0 && stringArray4.length != 0) {
            throw new IllegalArgumentException("unexpected virtualized SAM bridges");
        }
        Class[] classArray = new Class[stringArray3.length];
        for (int i = 0; i < stringArray3.length; ++i) {
            String string2 = C02f581bd2c02dabf8066a201.decodeSamOptionDescriptor(stringArray3[i]);
            object = C02f581bd2c02dabf8066a201.parseDescriptorType(string2, 0, classLoader);
            if (((I4607d6e8f130899c)object).nextIndex != string2.length() || !((I4607d6e8f130899c)object).type.isInterface()) {
                throw new IllegalArgumentException("invalid virtualized SAM marker interface");
            }
            classArray[i] = ((I4607d6e8f130899c)object).type;
        }
        String[] stringArray5 = new String[stringArray4.length];
        for (int i = 0; i < stringArray4.length; ++i) {
            object = C02f581bd2c02dabf8066a201.decodeSamOptionDescriptor(stringArray4[i]);
            MethodType methodType2 = MethodType.fromMethodDescriptorString((String)object, classLoader);
            if (methodType2.parameterCount() != methodType.parameterCount()) {
                throw new IllegalArgumentException("invalid virtualized SAM bridge descriptor");
            }
            stringArray5[i] = object;
        }
        return new I4d804b1d48de1013(n, classArray, stringArray5);
    }

    private static /* synthetic */ String[] splitSamOptionList(String string) {
        return string == null || string.length() == 0 ? new String[]{} : string.split(",", -1);
    }

    private static /* synthetic */ String decodeSamOptionDescriptor(String string) {
        byte[] byArray = Base64.getUrlDecoder().decode(string);
        try {
            String string2 = new String(byArray, StandardCharsets.US_ASCII);
            return string2;
        }
        finally {
            Arrays.fill(byArray, (byte)0);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ Class<?> samBridgeInterface(String string, String[] stringArray) throws ReflectiveOperationException {
        LinkedHashSet<String> linkedHashSet = new LinkedHashSet<String>(Arrays.asList(stringArray));
        StringBuilder stringBuilder = new StringBuilder(string.length() + linkedHashSet.size() * 24);
        stringBuilder.append(string.length()).append(':').append(string);
        for (String object2 : linkedHashSet) {
            stringBuilder.append('|').append(object2.length()).append(':').append(object2);
        }
        String string2 = stringBuilder.toString();
        Class clazz = (Class)SAM_BRIDGE_INTERFACE_CACHE.get(string2);
        if (clazz != null) {
            return clazz;
        }
        ConcurrentMap<String, Class<?>> concurrentMap = SAM_BRIDGE_INTERFACE_CACHE;
        synchronized (concurrentMap) {
            int n;
            Class clazz2 = (Class)SAM_BRIDGE_INTERFACE_CACHE.get(string2);
            if (clazz2 != null) {
                return clazz2;
            }
            byte[] byArray = C02f581bd2c02dabf8066a201.sha256(string2.getBytes(StandardCharsets.UTF_8));
            StringBuilder stringBuilder2 = new StringBuilder("$B$");
            try {
                for (int i = 0; i < 12; ++i) {
                    n = byArray[i] & 0xFF;
                    stringBuilder2.append(Character.forDigit(n >>> 4, 16));
                    stringBuilder2.append(Character.forDigit(n & 0xF, 16));
                }
            }
            finally {
                Arrays.fill(byArray, (byte)0);
            }
            String string3 = C02f581bd2c02dabf8066a201.class.getName();
            n = string3.lastIndexOf(46);
            String string4 = n < 0 ? stringBuilder2.toString() : string3.substring(0, n + 1) + stringBuilder2;
            byte[] byArray2 = C02f581bd2c02dabf8066a201.buildSamBridgeInterfaceBytes(string4.replace('.', '/'), string, linkedHashSet.toArray(new String[0]));
            Class<?> clazz3 = C02f581bd2c02dabf8066a201.defineSamBridgeInterface(string4, byArray2);
            SAM_BRIDGE_INTERFACE_CACHE.put(string2, clazz3);
            return clazz3;
        }
    }

    private static /* synthetic */ byte[] buildSamBridgeInterfaceBytes(String string, String string2, String[] stringArray) {
        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
            dataOutputStream.writeInt(-889275714);
            dataOutputStream.writeShort(0);
            dataOutputStream.writeShort(52);
            dataOutputStream.writeShort(stringArray.length + 9);
            C02f581bd2c02dabf8066a201.writeSamBridgeUtf8(dataOutputStream, string);
            dataOutputStream.writeByte(7);
            dataOutputStream.writeShort(1);
            C02f581bd2c02dabf8066a201.writeSamBridgeUtf8(dataOutputStream, "java/lang/Object");
            dataOutputStream.writeByte(7);
            dataOutputStream.writeShort(3);
            C02f581bd2c02dabf8066a201.writeSamBridgeUtf8(dataOutputStream, string2);
            C02f581bd2c02dabf8066a201.writeSamBridgeUtf8(dataOutputStream, "Exceptions");
            C02f581bd2c02dabf8066a201.writeSamBridgeUtf8(dataOutputStream, "java/lang/Throwable");
            dataOutputStream.writeByte(7);
            dataOutputStream.writeShort(7);
            for (String string3 : stringArray) {
                C02f581bd2c02dabf8066a201.writeSamBridgeUtf8(dataOutputStream, string3);
            }
            dataOutputStream.writeShort(5633);
            dataOutputStream.writeShort(2);
            dataOutputStream.writeShort(4);
            dataOutputStream.writeShort(0);
            dataOutputStream.writeShort(0);
            dataOutputStream.writeShort(stringArray.length);
            for (int i = 0; i < stringArray.length; ++i) {
                dataOutputStream.writeShort(5185);
                dataOutputStream.writeShort(5);
                dataOutputStream.writeShort(9 + i);
                dataOutputStream.writeShort(1);
                dataOutputStream.writeShort(6);
                dataOutputStream.writeInt(4);
                dataOutputStream.writeShort(1);
                dataOutputStream.writeShort(8);
            }
            dataOutputStream.writeShort(0);
            dataOutputStream.flush();
            return byteArrayOutputStream.toByteArray();
        }
        catch (IOException iOException) {
            throw new IllegalStateException("cannot encode virtualized SAM bridge interface", iOException);
        }
    }

    private static /* synthetic */ void writeSamBridgeUtf8(DataOutputStream dataOutputStream, String string) throws IOException {
        dataOutputStream.writeByte(1);
        dataOutputStream.writeUTF(string);
    }

    private static /* synthetic */ Class<?> defineSamBridgeInterface(String string, byte[] byArray) throws ReflectiveOperationException {
        try {
            Method method = MethodHandles.Lookup.class.getMethod("defineClass", byte[].class);
            return (Class)method.invoke((Object)MethodHandles.lookup(), new Object[]{byArray});
        }
        catch (NoSuchMethodException noSuchMethodException) {
            Class<?> clazz = Class.forName("sun.misc.Unsafe");
            Field field = clazz.getDeclaredField("theUnsafe");
            field.setAccessible(true);
            Object object = field.get(null);
            Method method = clazz.getDeclaredMethod("defineClass", String.class, byte[].class, Integer.TYPE, Integer.TYPE, ClassLoader.class, ProtectionDomain.class);
            return (Class)method.invoke(object, string, byArray, 0, byArray.length, C02f581bd2c02dabf8066a201.class.getClassLoader(), C02f581bd2c02dabf8066a201.class.getProtectionDomain());
        }
    }

    public static /* synthetic */ MethodHandle resolveVmMethodHandle(String string) {
        try {
            String[] stringArray;
            String[] stringArray2 = stringArray = string == null ? null : string.split("\\|", -1);
            if (stringArray == null || stringArray.length != 5 || !"handle".equals(stringArray[0])) {
                return null;
            }
            int n = Integer.parseInt(stringArray[1]);
            String string2 = stringArray[2];
            String string3 = C02f581bd2c02dabf8066a201.resolveBoundMethodName(string2, stringArray[3], stringArray[4]);
            String string4 = stringArray[4];
            ClassLoader classLoader = C02f581bd2c02dabf8066a201.class.getClassLoader();
            Class<?> clazz = Class.forName(string2.replace('/', '.'), false, classLoader);
            MethodType methodType = C02f581bd2c02dabf8066a201.descriptorMethodType(string4, clazz.getClassLoader());
            return C02f581bd2c02dabf8066a201.resolveMethodHandle(clazz, string3, methodType, n);
        }
        catch (Throwable throwable) {
            return null;
        }
    }

    private static /* synthetic */ MethodHandle resolveMethodHandle(Class<?> clazz, String string, MethodType methodType, int n) throws ReflectiveOperationException {
        MethodHandles.Lookup lookup;
        try {
            lookup = C02f581bd2c02dabf8066a201.privateLookup(clazz);
        }
        catch (ReflectiveOperationException | RuntimeException exception) {
            lookup = MethodHandles.publicLookup();
        }
        switch (n) {
            case 5: {
                return lookup.findVirtual(clazz, string, methodType);
            }
            case 6: {
                return lookup.findStatic(clazz, string, methodType);
            }
            case 7: {
                return lookup.findSpecial(clazz, string, methodType, clazz);
            }
            case 8: {
                if (!"<init>".equals(string) || methodType.returnType() != Void.TYPE) {
                    return null;
                }
                return lookup.findConstructor(clazz, methodType);
            }
            case 9: {
                return lookup.findVirtual(clazz, string, methodType);
            }
        }
        return null;
    }

    private static /* synthetic */ MethodHandles.Lookup privateLookup(Class<?> clazz) throws ReflectiveOperationException {
        try {
            Method method = MethodHandles.class.getMethod("privateLookupIn", Class.class, MethodHandles.Lookup.class);
            return (MethodHandles.Lookup)method.invoke(null, clazz, MethodHandles.lookup());
        }
        catch (NoSuchMethodException noSuchMethodException) {
            Constructor constructor = MethodHandles.Lookup.class.getDeclaredConstructor(Class.class);
            constructor.setAccessible(true);
            return (MethodHandles.Lookup)constructor.newInstance(clazz);
        }
    }

    private static /* synthetic */ String descriptorReturnInternalName(String string) {
        int n = string.indexOf(41);
        if (string.length() <= n + 2 || string.charAt(n + 1) != 'L') {
            throw new IllegalArgumentException("invalid SAM factory descriptor");
        }
        int n2 = string.indexOf(59, n + 2);
        if (n2 < 0) {
            throw new IllegalArgumentException("invalid SAM factory descriptor");
        }
        return string.substring(n + 2, n2);
    }

    private static /* synthetic */ MethodType descriptorMethodType(String string, ClassLoader classLoader) throws ClassNotFoundException {
        int n = string.indexOf(41);
        if (string.length() <= n + 1) {
            throw new IllegalArgumentException("invalid method descriptor");
        }
        Class<?>[] classArray = C02f581bd2c02dabf8066a201.descriptorParameterTypes(string, classLoader);
        if (string.charAt(n + 1) == 'V') {
            if (string.length() != n + 2) {
                throw new IllegalArgumentException("invalid method descriptor");
            }
            return MethodType.methodType(Void.TYPE, classArray);
        }
        I4607d6e8f130899c i4607d6e8f130899c = C02f581bd2c02dabf8066a201.parseDescriptorType(string, n + 1, classLoader);
        return MethodType.methodType(i4607d6e8f130899c.type, classArray);
    }

    private static /* synthetic */ String resolveBoundMethodName(String string, String string2, String string3) {
        String[] stringArray;
        String string4 = System.getProperty(C02f581bd2c02dabf8066a201.sealedMethodBindingPropertyName());
        if (string4 == null || string4.length() == 0) {
            return string2;
        }
        String string5 = C02f581bd2c02dabf8066a201.sealedBindingKey(string + "#" + string2 + "#" + string3) + "=";
        for (String string6 : stringArray = string4.split("\\n")) {
            String string7;
            String string8 = string6.trim();
            if (!string8.startsWith(string5) || (string7 = string8.substring(string5.length())).length() <= 0) continue;
            return string7;
        }
        return string2;
    }

    private static /* synthetic */ Class<?>[] descriptorParameterTypes(String string, ClassLoader classLoader) throws ClassNotFoundException {
        int n = string.indexOf(40);
        int n2 = string.indexOf(41, n + 1);
        if (n != 0 || n2 < 0) {
            throw new IllegalArgumentException("invalid method descriptor");
        }
        ArrayList arrayList = new ArrayList();
        int n3 = n + 1;
        while (n3 < n2) {
            I4607d6e8f130899c i4607d6e8f130899c = C02f581bd2c02dabf8066a201.parseDescriptorType(string, n3, classLoader);
            arrayList.add(i4607d6e8f130899c.type);
            n3 = i4607d6e8f130899c.nextIndex;
        }
        return arrayList.toArray(new Class[0]);
    }

    private static /* synthetic */ I4607d6e8f130899c parseDescriptorType(String string, int n, ClassLoader classLoader) throws ClassNotFoundException {
        char c = string.charAt(n);
        switch (c) {
            case 'Z': {
                return new I4607d6e8f130899c(Boolean.TYPE, n + 1);
            }
            case 'B': {
                return new I4607d6e8f130899c(Byte.TYPE, n + 1);
            }
            case 'C': {
                return new I4607d6e8f130899c(Character.TYPE, n + 1);
            }
            case 'S': {
                return new I4607d6e8f130899c(Short.TYPE, n + 1);
            }
            case 'I': {
                return new I4607d6e8f130899c(Integer.TYPE, n + 1);
            }
            case 'J': {
                return new I4607d6e8f130899c(Long.TYPE, n + 1);
            }
            case 'F': {
                return new I4607d6e8f130899c(Float.TYPE, n + 1);
            }
            case 'D': {
                return new I4607d6e8f130899c(Double.TYPE, n + 1);
            }
            case 'L': {
                int n2 = string.indexOf(59, n);
                if (n2 < 0) {
                    throw new IllegalArgumentException("invalid object descriptor");
                }
                String string2 = string.substring(n + 1, n2).replace('/', '.');
                return new I4607d6e8f130899c(Class.forName(string2, false, classLoader), n2 + 1);
            }
            case '[': {
                int n3 = n;
                while (string.charAt(n3) == '[') {
                    ++n3;
                }
                if (string.charAt(n3) == 'L' && (n3 = string.indexOf(59, n3)) < 0) {
                    throw new IllegalArgumentException("invalid array descriptor");
                }
                String string3 = string.substring(n, n3 + 1).replace('/', '.');
                return new I4607d6e8f130899c(Class.forName(string3, false, classLoader), n3 + 1);
            }
        }
        throw new IllegalArgumentException("unsupported descriptor tag " + c);
    }

    public static /* synthetic */ String getLoadStatus() {
        return loadState == 0 && (loadMessage == null || loadMessage.length() == 0) ? "untried" : loadMessage;
    }

    public static /* synthetic */ boolean isNativeLoaded() {
        return loadState == 2;
    }

    public static /* synthetic */ void m_6da6c3af7ef7f7b3(String string, String string2) {
        C02f581bd2c02dabf8066a201.m_d7c5053f05b22be5(string, string2, "vm-off");
    }

    public static synchronized /* synthetic */ void m_d7c5053f05b22be5(String string, String string2, String string3) {
        diversifiedVmEnabled = "vm-diverse".equals(string3);
        if (loadState != 0) {
            return;
        }
        loadState = 1;
        try {
            String string4 = C02f581bd2c02dabf8066a201.detectPlatform(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
            if (string4 == null) {
                loadMessage = "native-unavailable";
                loadState = -1;
                C02f581bd2c02dabf8066a201.runDiversifiedVmSelfExercise();
                return;
            }
            if (!C02f581bd2c02dabf8066a201.targetPlatformAllowsCurrent(string2, string4)) {
                loadMessage = "native-platform-not-requested:" + string4;
                loadState = -1;
                return;
            }
            C02f581bd2c02dabf8066a201.prepareJavaBootMaterialForLoad(string4);
            if (C02f581bd2c02dabf8066a201.tryLoadBundledNative(string4, string)) {
                loadState = 2;
                C02f581bd2c02dabf8066a201.runDiversifiedVmSelfExercise();
                return;
            }
            if (loadMessage == null || loadMessage.length() == 0) {
                loadMessage = "bundled-native-unavailable";
            }
            C02f581bd2c02dabf8066a201.clearJavaBootMaterial();
            try {
                C02f581bd2c02dabf8066a201.nativeAbortBootMaterial();
            }
            catch (Throwable throwable) {
                // empty catch block
            }
            loadState = -1;
            C02f581bd2c02dabf8066a201.runDiversifiedVmSelfExercise();
        }
        catch (Exception exception) {
            C02f581bd2c02dabf8066a201.clearJavaBootMaterial();
            loadMessage = C02f581bd2c02dabf8066a201.debugNativeLoadMessage("native-exception", exception);
            loadState = -1;
        }
    }

    private static /* synthetic */ boolean targetPlatformAllowsCurrent(String string, String string2) {
        String[] stringArray;
        if (string == null || string2 == null) {
            return false;
        }
        String string3 = string.trim();
        if ("auto".equals(string3) || "all".equals(string3)) {
            return true;
        }
        for (String string4 : stringArray = string3.split(",", -1)) {
            if (!string2.equals(string4.trim())) continue;
            return true;
        }
        return false;
    }

    public static /* synthetic */ boolean isDiversifiedVmEnabled() {
        return diversifiedVmEnabled;
    }

    public static /* synthetic */ boolean isKernelIntegrityReady() {
        return loadState == 2 && !nativeSelfCheckFailed && C02f581bd2c02dabf8066a201.nativeIsBootMaterialReady();
    }

    public static /* synthetic */ String getVmSelfCheck() {
        return vmSelfCheck;
    }

    private static /* synthetic */ void runDiversifiedVmSelfExercise() {
        if (!diversifiedVmEnabled) {
            return;
        }
        vmSelfCheck = loadState == 2 ? "native:vm-diverse:ok" : "native:vm-diverse:unavailable";
    }

    public static /* synthetic */ void requireHealthyKernel() {
        if (nativeSelfCheckFailed || loadState != 2 || !C02f581bd2c02dabf8066a201.nativeIsBootMaterialReady() || vmSelfCheck != null && vmSelfCheck.contains("mismatch")) {
            throw new SecurityException("Kernel integrity mismatch");
        }
    }

    private static /* synthetic */ boolean verifyNativeAbiAfterLoad() {
        try {
            C02f581bd2c02dabf8066a201.nativeExecuteVmResource(0L, null, null);
            return true;
        }
        catch (UnsatisfiedLinkError unsatisfiedLinkError) {
            loadMessage = "x_a637487cdacf81b9";
            return false;
        }
        catch (Throwable throwable) {
            return true;
        }
    }

    private static /* synthetic */ void verifyBootTokenAfterLoad(String string) {
        try {
            long l;
            long l2 = C02f581bd2c02dabf8066a201.computeExpectedBootToken(string);
            nativeBootToken = l = C02f581bd2c02dabf8066a201.nativeGetBootToken();
            if (l != l2) {
                nativeSelfCheckFailed = true;
                loadMessage = "native:integrity-mismatch";
            }
        }
        catch (UnsatisfiedLinkError unsatisfiedLinkError) {
            nativeSelfCheckFailed = true;
            loadMessage = "native:abi-missing:nativeGetBootToken";
        }
        catch (Throwable throwable) {
            nativeSelfCheckFailed = true;
            loadMessage = "native:integrity-check-failed";
        }
    }

    private static /* synthetic */ long computeExpectedBootToken(String string) {
        if (string == null) {
            string = "";
        }
        long l = -3750763034362895579L;
        l ^= 0xCC4A1511L;
        l *= 1099511628211L;
        l ^= 1L;
        l *= 1099511628211L;
        l ^= C02f581bd2c02dabf8066a201.fnv1a32(string);
        l *= 1099511628211L;
        l ^= 1L;
        return l *= 1099511628211L;
    }

    private static /* synthetic */ long fnv1a32(String string) {
        long l = 2166136261L;
        for (int i = 0; i < string.length(); ++i) {
            l ^= (long)string.charAt(i) & 0xFFL;
            l = l * 16777619L & 0xFFFFFFFFL;
        }
        return l;
    }

    private static /* synthetic */ String sealedBindingKey(String string) {
        byte[] byArray = string.getBytes(StandardCharsets.UTF_8);
        try {
            String string2 = C02f581bd2c02dabf8066a201.nativeSealedBindingKey(byArray);
            if (!C02f581bd2c02dabf8066a201.isHex(string2, 16, 16)) {
                throw new SecurityException("native binding lookup failed");
            }
            String string3 = string2;
            return string3;
        }
        catch (UnsatisfiedLinkError unsatisfiedLinkError) {
            throw new SecurityException("native binding lookup unavailable", unsatisfiedLinkError);
        }
        finally {
            Arrays.fill(byArray, (byte)0);
        }
    }

    private static /* synthetic */ void preloadRuntimeResourcesIntoNative() {
        if (!C02f581bd2c02dabf8066a201.hasVmCatalogResource()) {
            return;
        }
        byte[][] byArray = null;
        byte[] byArray2 = C02f581bd2c02dabf8066a201.createVmStartupNonce();
        try {
            byArray = C02f581bd2c02dabf8066a201.verifiedVmCatalogPayload();
            C02f581bd2c02dabf8066a201.nativePreloadRuntimeResources(byArray[0], byArray[1], byArray2);
        }
        catch (SecurityException securityException) {
            throw securityException;
        }
        catch (Throwable throwable) {
            throw new SecurityException("VM preload failed", throwable);
        }
        finally {
            if (byArray != null) {
                Arrays.fill(byArray[0], (byte)0);
                Arrays.fill(byArray[1], (byte)0);
            }
            Arrays.fill(byArray2, (byte)0);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ boolean hasVmCatalogResource() {
        boolean bl;
        block20: {
            JarFile jarFile = C02f581bd2c02dabf8066a201.openCatalogJar();
            if (jarFile != null) {
                try {
                    JarEntry jarEntry = jarFile.getJarEntry(VM_CATALOG_RESOURCE);
                    boolean bl2 = jarEntry != null && !jarEntry.isDirectory();
                    return bl2;
                }
                catch (Exception exception) {
                    boolean bl3 = false;
                    return bl3;
                }
                finally {
                    try {
                        jarFile.close();
                    }
                    catch (Exception exception) {}
                }
            }
            InputStream inputStream = C02f581bd2c02dabf8066a201.resourceStream(VM_CATALOG_RESOURCE);
            try {
                boolean bl4 = bl = inputStream != null;
                if (inputStream == null) break block20;
            }
            catch (Throwable throwable) {
                try {
                    if (inputStream != null) {
                        try {
                            inputStream.close();
                        }
                        catch (Throwable throwable2) {
                            throwable.addSuppressed(throwable2);
                        }
                    }
                    throw throwable;
                }
                catch (Exception exception) {
                    return false;
                }
            }
            inputStream.close();
        }
        return bl;
    }

    private static /* synthetic */ byte[] createVmStartupNonce() {
        byte[] byArray = new byte[32];
        C02f581bd2c02dabf8066a201.vmStartupSecureRandom().nextBytes(byArray);
        return byArray;
    }

    private static /* synthetic */ SecureRandom vmStartupSecureRandom() {
        if (File.separatorChar == '\\') {
            try {
                return SecureRandom.getInstance("Windows-PRNG");
            }
            catch (NoSuchAlgorithmException noSuchAlgorithmException) {
                // empty catch block
            }
        }
        return new SecureRandom();
    }

    private static /* synthetic */ void verifyVmPreloadIndexBeforeNative(String string, Set<String> set) {
        String[] stringArray;
        if (string == null || string.length() == 0) {
            throw new SecurityException("missing VM preload index");
        }
        HashSet<String> hashSet = new HashSet<String>();
        for (String string2 : stringArray = string.split("\n")) {
            String string3 = string2.trim();
            if (string3.length() == 0 || string3.startsWith("A|")) continue;
            String[] stringArray2 = string3.split("\\|", -1);
            if (!(stringArray2.length >= 7 && C02f581bd2c02dabf8066a201.isHex(stringArray2[0], 1, 16) && C02f581bd2c02dabf8066a201.isHex(stringArray2[4], 64, 64) && C02f581bd2c02dabf8066a201.isHex(stringArray2[5], 1, 8) && C02f581bd2c02dabf8066a201.isHex(stringArray2[6], 16, 16))) {
                throw new SecurityException("malformed VM preload entry");
            }
            if (!(hashSet.add(stringArray2[0]) && set.contains(stringArray2[1]) && set.contains(stringArray2[2]))) {
                throw new SecurityException("invalid VM preload catalog reference");
            }
            String string4 = C02f581bd2c02dabf8066a201.vmPreloadEntryAuthTag(stringArray2[0], stringArray2[1], stringArray2[2], stringArray2[3], stringArray2[4], stringArray2[5]);
            if (C02f581bd2c02dabf8066a201.constantTimeAsciiEquals(string4, stringArray2[6])) continue;
            throw new SecurityException("invalid VM preload profile auth");
        }
        if (hashSet.isEmpty()) {
            throw new SecurityException("empty VM preload index");
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ byte[][] verifiedVmCatalogPayload() throws Exception {
        try (JarFile jarFile = C02f581bd2c02dabf8066a201.openCatalogJar();){
            Object object;
            CharSequence charSequence;
            Object[] objectArray;
            byte[] byArray = C02f581bd2c02dabf8066a201.readRequiredResource(VM_CATALOG_RESOURCE, jarFile);
            byte[] byArray2 = C02f581bd2c02dabf8066a201.decodeRuntimeResource(byArray, true);
            if (byArray2 == null) {
                throw new SecurityException("invalid VM catalog root envelope");
            }
            int n = C02f581bd2c02dabf8066a201.lastIndexOf(byArray2, new byte[]{10, 72, 124});
            if (n < 0) {
                throw new SecurityException("malformed VM catalog root");
            }
            byte[] byArray3 = Arrays.copyOfRange(byArray2, 0, n + 1);
            String string = new String(byArray2, StandardCharsets.UTF_8);
            String string2 = string.substring(n + 3).trim();
            if (!C02f581bd2c02dabf8066a201.isHex(string2, 64, 64)) {
                throw new SecurityException("malformed VM catalog root tag");
            }
            byte[] byArray4 = C02f581bd2c02dabf8066a201.partitionResourceKey(C02f581bd2c02dabf8066a201.anchorResourcePartition);
            try {
                objectArray = C02f581bd2c02dabf8066a201.hmacSha256(byArray4, C02f581bd2c02dabf8066a201.concat("jsc1-root-auth-v1".getBytes(StandardCharsets.US_ASCII), byArray3));
                if (!MessageDigest.isEqual(objectArray, C02f581bd2c02dabf8066a201.hexToBytes(string2))) {
                    throw new SecurityException("invalid VM catalog root tag");
                }
            }
            finally {
                Arrays.fill(byArray4, (byte)0);
            }
            objectArray = new String(byArray3, StandardCharsets.UTF_8).split("\n");
            if (objectArray.length < 2) {
                throw new SecurityException("empty VM catalog root");
            }
            String[] stringArray = objectArray[0].split("\\|", -1);
            if (!(stringArray.length == 6 && "JSC1".equals(stringArray[0]) && C02f581bd2c02dabf8066a201.isHex(stringArray[1], 32, 32) && C02f581bd2c02dabf8066a201.isDecimal(stringArray[2]) && C02f581bd2c02dabf8066a201.isDecimal(stringArray[3]) && C02f581bd2c02dabf8066a201.isDecimal(stringArray[4]) && C02f581bd2c02dabf8066a201.isHex(stringArray[5], 64, 64))) {
                throw new SecurityException("malformed VM catalog header");
            }
            byte[] byArray5 = C02f581bd2c02dabf8066a201.hexToBytes(stringArray[1]);
            int n2 = C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray[2], "partition count");
            int n3 = C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray[3], "method count");
            int n4 = C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray[4], "resource count");
            if (n2 != C02f581bd2c02dabf8066a201.runtimeResourcePartitionCount) {
                throw new SecurityException("VM catalog partition mismatch");
            }
            byte[] byArray6 = C02f581bd2c02dabf8066a201.hexToBytes(stringArray[5]);
            ArrayList<String[]> arrayList = new ArrayList<String[]>();
            for (int i = 1; i < objectArray.length; ++i) {
                charSequence = objectArray[i].trim();
                if (((String)charSequence).length() == 0) continue;
                object = ((String)charSequence).split("\\|", -1);
                if (((String[])object).length != 8 || !"D".equals(object[0])) {
                    throw new SecurityException("malformed VM catalog directory");
                }
                arrayList.add((String[])object);
            }
            if (arrayList.size() != n2) {
                throw new SecurityException("incomplete VM catalog directories");
            }
            C02f581bd2c02dabf8066a201.sortVmCatalogDirectories(arrayList);
            StringBuilder stringBuilder = new StringBuilder();
            charSequence = new StringBuilder();
            object = new HashSet();
            ArrayList<byte[]> arrayList2 = new ArrayList<byte[]>();
            int n5 = 0;
            int n6 = 0;
            for (int i = 0; i < arrayList.size(); ++i) {
                String[] stringArray2 = (String[])arrayList.get(i);
                int n7 = C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray2[1], "partition id");
                if (n7 != i || !C02f581bd2c02dabf8066a201.isHex(stringArray2[4], 64, 64) || !C02f581bd2c02dabf8066a201.isHex(stringArray2[7], 64, 64)) {
                    throw new SecurityException("invalid VM catalog directory ordering");
                }
                String string3 = stringArray2[2];
                int n8 = C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray2[3], "directory length");
                int n9 = C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray2[5], "directory method count");
                int n10 = C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray2[6], "directory resource count");
                byte[] byArray7 = C02f581bd2c02dabf8066a201.hexToBytes(stringArray2[7]);
                byte[] byArray8 = C02f581bd2c02dabf8066a201.readRequiredResource(string3, jarFile);
                if (byArray8.length != n8 || !MessageDigest.isEqual(C02f581bd2c02dabf8066a201.sha256(byArray8), C02f581bd2c02dabf8066a201.hexToBytes(stringArray2[4]))) {
                    throw new SecurityException("invalid VM catalog directory ciphertext");
                }
                if (!C02f581bd2c02dabf8066a201.hasPartitionedRuntimeResourceHeader(byArray8, n7)) {
                    throw new SecurityException("VM catalog directory partition mismatch");
                }
                byte[] byArray9 = C02f581bd2c02dabf8066a201.decodeRuntimeResource(byArray8, true);
                if (byArray9 == null) {
                    throw new SecurityException("invalid VM catalog directory envelope");
                }
                String[] stringArray3 = new String(byArray9, StandardCharsets.UTF_8).split("\n");
                if (stringArray3.length == 0) {
                    throw new SecurityException("empty VM catalog directory");
                }
                String[] stringArray4 = stringArray3[0].split("\\|", -1);
                if (!(stringArray4.length == 6 && "JSD1".equals(stringArray4[0]) && stringArray[1].equals(stringArray4[1]) && n7 == C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray4[2], "directory partition") && n9 == C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray4[3], "directory method count") && n10 == C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray4[4], "directory resource count") && stringArray2[7].equals(stringArray4[5]))) {
                    throw new SecurityException("invalid VM catalog directory header");
                }
                ArrayList<byte[]> arrayList3 = new ArrayList<byte[]>();
                int n11 = 0;
                int n12 = 0;
                for (int j = 1; j < stringArray3.length; ++j) {
                    String string4 = stringArray3[j];
                    if (string4.length() == 0) continue;
                    if (string4.length() >= 2 && string4.charAt(0) == 'M' && string4.charAt(1) == '|') {
                        stringBuilder.append(string4.substring(2)).append('\n');
                        ++n11;
                        continue;
                    }
                    String[] stringArray5 = string4.split("\\|", -1);
                    if (!(stringArray5.length == 5 && "R".equals(stringArray5[0]) && C02f581bd2c02dabf8066a201.isDecimal(stringArray5[3]) && C02f581bd2c02dabf8066a201.isHex(stringArray5[4], 64, 64))) {
                        throw new SecurityException("malformed VM catalog resource");
                    }
                    String string5 = stringArray5[1];
                    String string6 = stringArray5[2];
                    int n13 = C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray5[3], "resource length");
                    byte[] byArray10 = C02f581bd2c02dabf8066a201.hexToBytes(stringArray5[4]);
                    if (!object.add(string6)) {
                        throw new SecurityException("duplicate VM catalog resource");
                    }
                    byte[] byArray11 = C02f581bd2c02dabf8066a201.readRequiredResource(string6, jarFile);
                    if (byArray11.length != n13 || !MessageDigest.isEqual(C02f581bd2c02dabf8066a201.sha256(byArray11), byArray10) || !C02f581bd2c02dabf8066a201.hasPartitionedRuntimeResourceHeader(byArray11, n7)) {
                        throw new SecurityException("invalid VM catalog resource ciphertext");
                    }
                    arrayList3.add(C02f581bd2c02dabf8066a201.sha256(C02f581bd2c02dabf8066a201.concat("JSL1".getBytes(StandardCharsets.US_ASCII), byArray5, C02f581bd2c02dabf8066a201.intBytes(n7), C02f581bd2c02dabf8066a201.frame(string5), C02f581bd2c02dabf8066a201.frame(string6), C02f581bd2c02dabf8066a201.longBytes(n13), byArray10)));
                    ((StringBuilder)charSequence).append("R|").append(string6).append('|').append(n13).append('|').append(stringArray5[4]).append('|').append(n7).append('\n');
                    ++n12;
                }
                if (n11 != n9 || n12 != n10) {
                    throw new SecurityException("VM catalog directory count mismatch");
                }
                byte[] byArray12 = C02f581bd2c02dabf8066a201.vmCatalogMerkleRoot(arrayList3, byArray5, n7);
                if (!MessageDigest.isEqual(byArray12, byArray7)) {
                    throw new SecurityException("VM catalog partition root mismatch");
                }
                arrayList2.add(byArray12);
                n5 += n11;
                n6 += n12;
            }
            if (n5 != n3 || n6 != n4) {
                throw new SecurityException("VM catalog count mismatch");
            }
            if (!MessageDigest.isEqual(C02f581bd2c02dabf8066a201.vmCatalogRoot(byArray5, arrayList2), byArray6)) {
                throw new SecurityException("VM catalog root mismatch");
            }
            C02f581bd2c02dabf8066a201.verifyVmPreloadIndexBeforeNative(stringBuilder.toString(), (Set<String>)object);
            byte[][] byArrayArray = new byte[][]{stringBuilder.toString().getBytes(StandardCharsets.UTF_8), ((StringBuilder)charSequence).toString().getBytes(StandardCharsets.UTF_8)};
            return byArrayArray;
        }
    }

    private static /* synthetic */ JarFile openCatalogJar() {
        try {
            CodeSource codeSource = C02f581bd2c02dabf8066a201.class.getProtectionDomain().getCodeSource();
            if (codeSource == null || codeSource.getLocation() == null || !"file".equalsIgnoreCase(codeSource.getLocation().getProtocol())) {
                return null;
            }
            File file = new File(codeSource.getLocation().toURI());
            return file.isFile() ? new JarFile(file, false) : null;
        }
        catch (Exception exception) {
            return null;
        }
    }

    private static /* synthetic */ byte[] readRequiredResource(String string, JarFile jarFile) throws Exception {
        if (jarFile != null) {
            JarEntry jarEntry = jarFile.getJarEntry(string);
            if (jarEntry == null || jarEntry.isDirectory()) {
                throw new SecurityException("missing VM catalog resource");
            }
            try (InputStream inputStream = jarFile.getInputStream(jarEntry);){
                byte[] byArray = C02f581bd2c02dabf8066a201.readAll(inputStream);
                return byArray;
            }
        }
        try (InputStream inputStream = C02f581bd2c02dabf8066a201.resourceStream(string);){
            if (inputStream == null) {
                throw new SecurityException("missing VM catalog resource");
            }
            byte[] byArray = C02f581bd2c02dabf8066a201.readAll(inputStream);
            return byArray;
        }
    }

    private static /* synthetic */ String vmPreloadEntryAuthTag(String string, String string2, String string3, String string4, String string5, String string6) {
        byte[] byArray = C02f581bd2c02dabf8066a201.sha256(C02f581bd2c02dabf8066a201.concat("jsc1-method-auth-v1".getBytes(StandardCharsets.US_ASCII), {0}, string.getBytes(StandardCharsets.US_ASCII), {0}, string2.getBytes(StandardCharsets.UTF_8), {0}, string3.getBytes(StandardCharsets.UTF_8), {0}, string4.getBytes(StandardCharsets.US_ASCII), {0}, string5.getBytes(StandardCharsets.US_ASCII), {0}, string6.getBytes(StandardCharsets.US_ASCII)));
        return C02f581bd2c02dabf8066a201.hexLower(Arrays.copyOf(byArray, 8));
    }

    private static /* synthetic */ boolean isHex(String string, int n, int n2) {
        if (string == null || string.length() < n || string.length() > n2) {
            return false;
        }
        for (int i = 0; i < string.length(); ++i) {
            if (Character.digit(string.charAt(i), 16) >= 0) continue;
            return false;
        }
        return true;
    }

    private static /* synthetic */ boolean constantTimeAsciiEquals(String string, String string2) {
        if (string == null || string2 == null || string.length() != string2.length()) {
            return false;
        }
        int n = 0;
        for (int i = 0; i < string.length(); ++i) {
            n |= string.charAt(i) ^ string2.charAt(i);
        }
        return n == 0;
    }

    private static /* synthetic */ String hexLower(byte[] byArray) {
        char[] cArray = new char[byArray.length * 2];
        char[] cArray2 = "0123456789abcdef".toCharArray();
        for (int i = 0; i < byArray.length; ++i) {
            int n = byArray[i] & 0xFF;
            cArray[i * 2] = cArray2[n >>> 4];
            cArray[i * 2 + 1] = cArray2[n & 0xF];
        }
        return new String(cArray);
    }

    private static /* synthetic */ void installBootMaterialIntoNative(String string) throws Exception {
        int n;
        byte[] byArray;
        try (InputStream inputStream = C02f581bd2c02dabf8066a201.resourceStream(BOOT_MATERIAL_RESOURCE);){
            if (inputStream == null) {
                throw new SecurityException("missing encrypted boot material envelope");
            }
            byArray = C02f581bd2c02dabf8066a201.readAll(inputStream);
        }
        int n2 = n = byArray.length > 4 ? byArray[4] & 0xFF : -1;
        if (n == 3) {
            byte[] byArray2 = null;
            try {
                if (runtimeResourceKeys == null) {
                    throw new SecurityException("hardened Java boot material was not prepared for native load");
                }
                byArray2 = C02f581bd2c02dabf8066a201.readBootKekSidecarBinary();
                if (!C02f581bd2c02dabf8066a201.nativeInstallBootEnvelope(byArray, byArray2) || !C02f581bd2c02dabf8066a201.nativeIsBootMaterialReady()) {
                    throw new SecurityException("native boot envelope installation failed");
                }
                C02f581bd2c02dabf8066a201.clearExpectedShellBindingCommitment();
            }
            catch (Throwable throwable) {
                C02f581bd2c02dabf8066a201.clearJavaBootMaterial();
                try {
                    C02f581bd2c02dabf8066a201.nativeAbortBootMaterial();
                }
                catch (Throwable throwable2) {
                    // empty catch block
                }
                throw throwable;
            }
            finally {
                if (byArray2 != null) {
                    Arrays.fill(byArray2, (byte)0);
                }
                Arrays.fill(byArray, (byte)0);
            }
            return;
        }
        C02f581bd2c02dabf8066a201.clearJavaBootMaterial();
        byte[] byArray3 = null;
        byte[] byArray4 = null;
        boolean bl = false;
        try {
            byArray3 = C02f581bd2c02dabf8066a201.loadBootSecret(byArray);
            C02f581bd2c02dabf8066a201.publishNativeShellBootSecret(byArray3);
            byArray4 = C02f581bd2c02dabf8066a201.decryptBootMaterial(byArray, byArray3);
            C02f581bd2c02dabf8066a201.validateAndPublishJavaBootMaterial(byArray4, string);
            bl = true;
            if (!C02f581bd2c02dabf8066a201.nativeInstallBootMaterial(byArray4) || !C02f581bd2c02dabf8066a201.nativeIsBootMaterialReady()) {
                throw new SecurityException("native boot material installation failed");
            }
            C02f581bd2c02dabf8066a201.clearExpectedShellBindingCommitment();
            Arrays.fill(byArray4, 4, 68, (byte)0);
        }
        catch (Throwable throwable) {
            if (bl) {
                C02f581bd2c02dabf8066a201.clearJavaBootMaterial();
                try {
                    C02f581bd2c02dabf8066a201.nativeAbortBootMaterial();
                }
                catch (Throwable throwable3) {
                    // empty catch block
                }
            }
            throw throwable;
        }
        finally {
            if (byArray3 != null) {
                Arrays.fill(byArray3, (byte)0);
            }
            if (byArray4 != null) {
                Arrays.fill(byArray4, (byte)0);
            }
            Arrays.fill(byArray, (byte)0);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ byte[] readBootKekSidecarBinary() throws Exception {
        byte[] byArray;
        byte[] byArray2;
        Object object;
        String string = System.getenv(BOOT_SECRET_ENV);
        if (string != null) {
            throw new SecurityException("hardened boot material requires JAVASHROUD_BOOT_SECRET_FILE_V1 or the embedded Boot KEK sidecar");
        }
        String string2 = System.getenv(BOOT_SECRET_FILE_ENV);
        if (string2 != null) {
            if (string2.length() == 0) {
                throw new SecurityException("Boot KEK sidecar file path is empty");
            }
            object = new FileInputStream(string2);
            try {
                byArray2 = C02f581bd2c02dabf8066a201.readAll((InputStream)object);
            }
            finally {
                ((InputStream)object).close();
            }
        }
        object = C02f581bd2c02dabf8066a201.resourceStream(EMBEDDED_BOOT_SECRET_RESOURCE);
        try {
            if (object == null) {
                throw new SecurityException("Boot KEK sidecar is missing");
            }
            byArray2 = C02f581bd2c02dabf8066a201.readAll((InputStream)object);
        }
        finally {
            if (object != null) {
                ((InputStream)object).close();
            }
        }
        object = null;
        byte[] byArray3 = null;
        boolean bl = false;
        try {
            boolean bl2 = byArray2.length >= BOOT_SIDECAR_TEXT_PREFIX.length;
            for (int i = 0; bl2 && i < BOOT_SIDECAR_TEXT_PREFIX.length; ++i) {
                bl2 = byArray2[i] == BOOT_SIDECAR_TEXT_PREFIX[i];
            }
            if (bl2) {
                object = Arrays.copyOfRange(byArray2, BOOT_SIDECAR_TEXT_PREFIX.length, byArray2.length);
                if (((Object)object).length == 0) {
                    throw new SecurityException("empty Boot KEK sidecar");
                }
                try {
                    byArray3 = Base64.getUrlDecoder().decode((byte[])object);
                }
                catch (IllegalArgumentException illegalArgumentException) {
                    throw new SecurityException("Boot KEK sidecar encoding is invalid", illegalArgumentException);
                }
            } else {
                byArray3 = (byte[])byArray2.clone();
            }
            if (byArray3.length != 118 || !C02f581bd2c02dabf8066a201.isBootKekSidecar(byArray3)) {
                throw new SecurityException("unsupported Boot KEK sidecar");
            }
            bl = true;
            byArray = byArray3;
        }
        catch (Throwable throwable) {
            Arrays.fill(byArray2, (byte)0);
            if (object != null) {
                Arrays.fill((byte[])object, (byte)0);
            }
            if (!bl && byArray3 != null) {
                Arrays.fill(byArray3, (byte)0);
            }
            throw throwable;
        }
        Arrays.fill(byArray2, (byte)0);
        if (object != null) {
            Arrays.fill((byte[])object, (byte)0);
        }
        if (!bl && byArray3 != null) {
            Arrays.fill(byArray3, (byte)0);
        }
        return byArray;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ void prepareJavaBootMaterialForLoad(String string) throws Exception {
        byte[] byArray;
        C02f581bd2c02dabf8066a201.clearJavaBootMaterial();
        try (Object object = C02f581bd2c02dabf8066a201.resourceStream(BOOT_MATERIAL_RESOURCE);){
            if (object == null) {
                throw new SecurityException("missing encrypted boot material envelope");
            }
            byArray = C02f581bd2c02dabf8066a201.readAll((InputStream)object);
        }
        object = null;
        byte[] byArray2 = null;
        boolean bl = false;
        try {
            object = C02f581bd2c02dabf8066a201.loadBootSecret(byArray);
            C02f581bd2c02dabf8066a201.publishNativeShellBootSecret((byte[])object);
            byArray2 = C02f581bd2c02dabf8066a201.decryptBootMaterial(byArray, (byte[])object);
            C02f581bd2c02dabf8066a201.validateAndPublishJavaBootMaterial(byArray2, string);
            bl = true;
        }
        finally {
            if (!bl) {
                C02f581bd2c02dabf8066a201.clearJavaBootMaterial();
            }
            if (object != null) {
                Arrays.fill((byte[])object, (byte)0);
            }
            if (byArray2 != null) {
                Arrays.fill(byArray2, (byte)0);
            }
            Arrays.fill(byArray, (byte)0);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ byte[] loadBootSecret(byte[] byArray) throws Exception {
        byte[] byArray2;
        block32: {
            String string = System.getenv(BOOT_SECRET_ENV);
            byte[] byArray3 = C02f581bd2c02dabf8066a201.bootSidecarBinding(byArray);
            try {
                byte[] byArray4;
                InputStream inputStream;
                if (string != null) {
                    if (byArray3 != null) {
                        throw new SecurityException("hardened boot material requires a sealed Boot KEK sidecar file");
                    }
                    if (string.length() != 64) {
                        throw new SecurityException("boot KEK must be 64 hexadecimal characters");
                    }
                    try {
                        byArray2 = C02f581bd2c02dabf8066a201.hexToBytes(string);
                    }
                    catch (IllegalArgumentException illegalArgumentException) {
                        throw new SecurityException("boot KEK must be hexadecimal", illegalArgumentException);
                    }
                    if (byArray2.length != 32) {
                        throw new SecurityException("boot KEK must be 32 bytes");
                    }
                    break block32;
                }
                String string2 = System.getenv(BOOT_SECRET_FILE_ENV);
                if (string2 != null) {
                    if (string2.length() == 0) {
                        throw new SecurityException("boot KEK sidecar file path is empty");
                    }
                    inputStream = new FileInputStream(string2);
                    try {
                        byArray4 = C02f581bd2c02dabf8066a201.readAll(inputStream);
                    }
                    finally {
                        inputStream.close();
                    }
                }
                inputStream = C02f581bd2c02dabf8066a201.resourceStream(EMBEDDED_BOOT_SECRET_RESOURCE);
                try {
                    if (inputStream == null) {
                        throw new SecurityException("boot KEK is missing");
                    }
                    byArray4 = C02f581bd2c02dabf8066a201.readAll(inputStream);
                }
                finally {
                    if (inputStream != null) {
                        inputStream.close();
                    }
                }
                try {
                    byArray2 = C02f581bd2c02dabf8066a201.decodeBootSecretBytes(byArray4, byArray3);
                }
                catch (IllegalArgumentException illegalArgumentException) {
                    throw new SecurityException("boot KEK sidecar or hexadecimal file is invalid", illegalArgumentException);
                }
                finally {
                    Arrays.fill(byArray4, (byte)0);
                }
            }
            finally {
                if (byArray3 != null) {
                    Arrays.fill(byArray3, (byte)0);
                }
            }
        }
        if (bootSecretEnvBindingEnabled) {
            try {
                byArray2 = C02f581bd2c02dabf8066a201.unmaskBootSecret(byArray2);
            }
            catch (SecurityException securityException) {
                Arrays.fill(byArray2, (byte)0);
                throw securityException;
            }
        }
        return byArray2;
    }

    private static /* synthetic */ byte[] decodeBootSecretBytes(byte[] byArray, byte[] byArray2) throws Exception {
        if (C02f581bd2c02dabf8066a201.isBootKekSidecar(byArray)) {
            if (byArray2 == null) {
                throw new SecurityException("sealed Boot KEK sidecar requires a hardened boot envelope");
            }
            return C02f581bd2c02dabf8066a201.decodeBootKekSidecar(byArray, byArray2);
        }
        if (byArray.length == 32) {
            if (byArray2 != null) {
                throw new SecurityException("hardened boot material rejects raw Boot KEK files");
            }
            return (byte[])byArray.clone();
        }
        if (byArray2 != null) {
            throw new SecurityException("hardened boot material rejects hexadecimal Boot KEK files");
        }
        if (byArray.length != 64) {
            throw new SecurityException("boot KEK file must contain 32 raw bytes or 64 hexadecimal characters");
        }
        return C02f581bd2c02dabf8066a201.hexToBytes(byArray);
    }

    private static /* synthetic */ byte[] unmaskBootSecret(byte[] byArray) throws Exception {
        if (byArray == null || byArray.length != 32) {
            throw new SecurityException("masked boot KEK must be 32 bytes");
        }
        String string = C02f581bd2c02dabf8066a201.nativeGetMachineFingerprint();
        if (string == null || string.length() == 0) {
            throw new SecurityException("boot KEK environment binding requires a machine fingerprint");
        }
        String[] stringArray = bootSecretExpectedFingerprints;
        boolean bl = false;
        for (String i : stringArray) {
            if (i == null || !C02f581bd2c02dabf8066a201.constantTimeStringEqual(string, i.trim())) continue;
            bl = true;
            break;
        }
        if (!bl) {
            throw new SecurityException("boot KEK environment binding mismatch");
        }
        byte[] byArray2 = string.getBytes(StandardCharsets.UTF_8);
        byte[] byArray3 = C02f581bd2c02dabf8066a201.deriveBootEnvMask(byArray2);
        Arrays.fill(byArray2, (byte)0);
        byte[] byArray4 = new byte[32];
        for (int i = 0; i < 32; ++i) {
            byArray4[i] = (byte)(byArray[i] ^ byArray3[i]);
        }
        Arrays.fill(byArray3, (byte)0);
        return byArray4;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ byte[] deriveBootEnvMask(byte[] byArray) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        byte[] byArray2 = new byte[32];
        Arrays.fill(byArray2, (byte)0);
        try {
            mac.init(new SecretKeySpec(byArray2, "HmacSHA256"));
            mac.update("javashroud-boot-env-mask-v1".getBytes(StandardCharsets.US_ASCII));
            byte[] byArray3 = mac.doFinal(byArray);
            byte[] byArray4 = Arrays.copyOf(byArray3, 32);
            Arrays.fill(byArray3, (byte)0);
            byte[] byArray5 = byArray4;
            return byArray5;
        }
        finally {
            Arrays.fill(byArray2, (byte)0);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ boolean constantTimeStringEqual(String string, String string2) {
        boolean bl;
        if (string == null || string2 == null) {
            return string == string2;
        }
        byte[] byArray = string.getBytes(StandardCharsets.UTF_8);
        byte[] byArray2 = string2.getBytes(StandardCharsets.UTF_8);
        try {
            if (byArray.length != byArray2.length) {
                boolean bl2 = false;
                return bl2;
            }
            int n = 0;
            for (int i = 0; i < byArray.length; ++i) {
                n |= (byArray[i] ^ byArray2[i]) & 0xFF;
            }
            bl = n == 0;
        }
        finally {
            Arrays.fill(byArray, (byte)0);
            Arrays.fill(byArray2, (byte)0);
        }
        return bl;
    }

    private static /* synthetic */ byte[] bootSidecarBinding(byte[] byArray) {
        if (byArray == null || byArray.length < 71) {
            return null;
        }
        if ((byArray[0] & 0xFF) != 74 || (byArray[1] & 0xFF) != 83 || (byArray[2] & 0xFF) != 66 || (byArray[3] & 0xFF) != 77 || (byArray[4] & 0xFF) != 3 || (byArray[5] & 0xFF) != 32) {
            return null;
        }
        return Arrays.copyOfRange(byArray, 6, 38);
    }

    private static /* synthetic */ boolean isBootKekSidecar(byte[] byArray) {
        if (byArray == null) {
            return false;
        }
        if (byArray.length >= BOOT_SIDECAR_TEXT_PREFIX.length) {
            boolean bl = true;
            for (int i = 0; i < BOOT_SIDECAR_TEXT_PREFIX.length; ++i) {
                bl &= byArray[i] == BOOT_SIDECAR_TEXT_PREFIX[i];
            }
            if (bl) {
                return true;
            }
        }
        return byArray.length >= 4 && (byArray[0] & 0xFF) == 74 && (byArray[1] & 0xFF) == 83 && (byArray[2] & 0xFF) == 66 && (byArray[3] & 0xFF) == 75;
    }

    private static /* synthetic */ byte[] decodeBootKekSidecar(byte[] byArray, byte[] byArray2) throws Exception {
        byte[] byArray3;
        boolean bl;
        byte[] byArray4;
        byte[] byArray5;
        byte[] byArray6;
        byte[] byArray7;
        byte[] byArray8;
        byte[] byArray9;
        byte[] byArray10;
        byte[] byArray11;
        byte[] byArray12;
        block30: {
            byte[] byArray13 = null;
            byArray12 = null;
            byArray11 = null;
            byArray10 = null;
            byArray9 = null;
            byArray8 = null;
            byArray7 = null;
            byArray6 = null;
            byArray5 = null;
            byArray4 = null;
            bl = false;
            try {
                boolean bl2 = byArray.length >= BOOT_SIDECAR_TEXT_PREFIX.length;
                for (int i = 0; bl2 && i < BOOT_SIDECAR_TEXT_PREFIX.length; ++i) {
                    bl2 = byArray[i] == BOOT_SIDECAR_TEXT_PREFIX[i];
                }
                if (bl2) {
                    byArray12 = Arrays.copyOfRange(byArray, BOOT_SIDECAR_TEXT_PREFIX.length, byArray.length);
                    if (byArray12.length == 0) {
                        throw new SecurityException("empty Boot KEK sidecar");
                    }
                    byArray13 = Base64.getUrlDecoder().decode(byArray12);
                } else {
                    byArray13 = (byte[])byArray.clone();
                }
                if (byArray13.length != 118 || (byArray13[0] & 0xFF) != 74 || (byArray13[1] & 0xFF) != 83 || (byArray13[2] & 0xFF) != 66 || (byArray13[3] & 0xFF) != 75 || (byArray13[4] & 0xFF) != 1 || (byArray13[5] & 0xFF) != 0 || (byArray13[6] & 0xFF) != 16 || (byArray13[7] & 0xFF) != 12 || C02f581bd2c02dabf8066a201.readSealedResourceLe16(byArray13, 8) != 48) {
                    throw new SecurityException("unsupported Boot KEK sidecar");
                }
                byArray11 = Arrays.copyOfRange(byArray13, 0, 10);
                byArray10 = Arrays.copyOfRange(byArray13, 10, 42);
                if (byArray2 == null || byArray2.length != 32 || !MessageDigest.isEqual(byArray10, byArray2)) {
                    throw new SecurityException("Boot KEK sidecar artifact binding mismatch");
                }
                byArray9 = Arrays.copyOfRange(byArray13, 42, 58);
                byArray8 = Arrays.copyOfRange(byArray13, 58, 70);
                byArray7 = C02f581bd2c02dabf8066a201.concat(BOOT_SIDECAR_KEY_DOMAIN, byArray9);
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(byArray2, "HmacSHA256"));
                byArray6 = mac.doFinal(byArray7);
                byArray5 = C02f581bd2c02dabf8066a201.concat(byArray11, byArray10, byArray9, byArray8);
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(2, (Key)new SecretKeySpec(byArray6, "AES"), new GCMParameterSpec(128, byArray8));
                cipher.updateAAD(byArray5);
                byArray4 = cipher.doFinal(byArray13, 70, 48);
                if (byArray4.length != 32) {
                    throw new SecurityException("Boot KEK sidecar plaintext length mismatch");
                }
                bl = true;
                byArray3 = byArray4;
                if (byArray13 == null) break block30;
            }
            catch (IllegalArgumentException illegalArgumentException) {
                try {
                    throw new SecurityException("Boot KEK sidecar encoding is invalid", illegalArgumentException);
                }
                catch (Throwable throwable) {
                    if (byArray13 != null) {
                        Arrays.fill(byArray13, (byte)0);
                    }
                    if (byArray12 != null) {
                        Arrays.fill(byArray12, (byte)0);
                    }
                    if (byArray11 != null) {
                        Arrays.fill(byArray11, (byte)0);
                    }
                    if (byArray10 != null) {
                        Arrays.fill(byArray10, (byte)0);
                    }
                    if (byArray9 != null) {
                        Arrays.fill(byArray9, (byte)0);
                    }
                    if (byArray8 != null) {
                        Arrays.fill(byArray8, (byte)0);
                    }
                    if (byArray7 != null) {
                        Arrays.fill(byArray7, (byte)0);
                    }
                    if (byArray6 != null) {
                        Arrays.fill(byArray6, (byte)0);
                    }
                    if (byArray5 != null) {
                        Arrays.fill(byArray5, (byte)0);
                    }
                    if (!bl && byArray4 != null) {
                        Arrays.fill(byArray4, (byte)0);
                    }
                    throw throwable;
                }
            }
            Arrays.fill(byArray13, (byte)0);
        }
        if (byArray12 != null) {
            Arrays.fill(byArray12, (byte)0);
        }
        if (byArray11 != null) {
            Arrays.fill(byArray11, (byte)0);
        }
        if (byArray10 != null) {
            Arrays.fill(byArray10, (byte)0);
        }
        if (byArray9 != null) {
            Arrays.fill(byArray9, (byte)0);
        }
        if (byArray8 != null) {
            Arrays.fill(byArray8, (byte)0);
        }
        if (byArray7 != null) {
            Arrays.fill(byArray7, (byte)0);
        }
        if (byArray6 != null) {
            Arrays.fill(byArray6, (byte)0);
        }
        if (byArray5 != null) {
            Arrays.fill(byArray5, (byte)0);
        }
        if (!bl && byArray4 != null) {
            Arrays.fill(byArray4, (byte)0);
        }
        return byArray3;
    }

    private static /* synthetic */ byte[] decryptBootMaterial(byte[] byArray, byte[] byArray2) throws Exception {
        int n;
        if (byArray == null || byArray.length < 38 || byArray2.length != 32) {
            throw new SecurityException("malformed boot material envelope");
        }
        int n2 = byArray[4] & 0xFF;
        if ((byArray[0] & 0xFF) != 74 || (byArray[1] & 0xFF) != 83 || (byArray[2] & 0xFF) != 66 || (byArray[3] & 0xFF) != 77 || n2 != 2 && n2 != 3) {
            throw new SecurityException("unsupported boot material envelope");
        }
        byte[] byArray3 = null;
        int n3 = 5;
        if (n2 == 3) {
            n = byArray[5] & 0xFF;
            if (n != 32 || 6 + n >= byArray.length) {
                throw new SecurityException("malformed hardened boot binding");
            }
            byArray3 = Arrays.copyOfRange(byArray, 6, 6 + n);
            n3 = 6 + n;
        }
        n = byArray[n3] & 0xFF;
        int n4 = n3 + 1;
        if (n != 12 || n4 + n + 4 > byArray.length) {
            throw new SecurityException("malformed boot material nonce");
        }
        int n5 = n4 + n;
        int n6 = C02f581bd2c02dabf8066a201.readSealedResourceLe32(byArray, n5);
        int n7 = n5 + 4;
        if (n6 < 16 || n7 + n6 != byArray.length) {
            throw new SecurityException("malformed boot material payload");
        }
        byte[] byArray4 = Arrays.copyOfRange(byArray, n4, n4 + n);
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(2, (Key)new SecretKeySpec(byArray2, "AES"), new GCMParameterSpec(128, byArray4));
            if (n2 == 3) {
                cipher.updateAAD(HARDENED_BOOT_MATERIAL_AAD);
                cipher.updateAAD(byArray3);
            } else {
                cipher.updateAAD(BOOT_MATERIAL_AAD);
            }
            byte[] byArray5 = cipher.doFinal(byArray, n7, n6);
            return byArray5;
        }
        catch (Exception exception) {
            throw new SecurityException("boot material envelope authentication failed", exception);
        }
        finally {
            Arrays.fill(byArray4, (byte)0);
            if (byArray3 != null) {
                Arrays.fill(byArray3, (byte)0);
            }
        }
    }

    private static /* synthetic */ void validateAndPublishJavaBootMaterial(byte[] byArray) {
        C02f581bd2c02dabf8066a201.validateAndPublishJavaBootMaterial(byArray, C02f581bd2c02dabf8066a201.detectPlatform(System.getProperty("os.name", ""), System.getProperty("os.arch", "")));
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     * WARNING - void declaration
     */
    private static synchronized /* synthetic */ void validateAndPublishJavaBootMaterial(byte[] byArray, String string) {
        int n;
        if (runtimeResourceKeys != null || expectedShellBindingCommitment != null) {
            throw new SecurityException("boot material is already installed");
        }
        int n2 = n = byArray == null || byArray.length == 0 ? -1 : byArray[0] & 0xFF;
        if (byArray == null || byArray.length < 132 || n != 2 && n != 3) {
            throw new SecurityException("malformed boot material");
        }
        int n3 = byArray[1] & 0xFF;
        int n4 = byArray[2] & 0xFF;
        int n5 = byArray[3] & 0xFF;
        int n6 = 68 + n4 * 32 + n5 * 33;
        if (n3 < 1 || n3 > 16 || n4 != n3 + 1 || n5 > 4 || byArray.length != n6) {
            throw new SecurityException("invalid boot material key slots");
        }
        byte[][] byArrayArray = new byte[n4][];
        byte[] byArray2 = null;
        boolean bl = false;
        int n7 = 68;
        try {
            void var11_12;
            boolean bl2 = false;
            while (var11_12 < n4) {
                byArrayArray[var11_12] = Arrays.copyOfRange(byArray, n7, n7 + 32);
                n7 += 32;
                ++var11_12;
            }
            boolean[] blArray = new boolean[5];
            int n8 = C02f581bd2c02dabf8066a201.shellBindingPlatformId(string);
            for (int i = 0; i < n5; ++i) {
                int n9;
                if ((n9 = byArray[n7++] & 0xFF) < 1 || n9 > 4 || blArray[n9]) {
                    throw new SecurityException("invalid native shell binding platform");
                }
                blArray[n9] = true;
                byte[] byArray3 = Arrays.copyOfRange(byArray, n7, n7 + 32);
                n7 += 32;
                int n10 = 0;
                for (byte by : byArray3) {
                    n10 |= by & 0xFF;
                }
                if (n10 == 0) {
                    Arrays.fill(byArray3, (byte)0);
                    throw new SecurityException("invalid native shell binding commitment");
                }
                if (n9 == n8) {
                    byArray2 = byArray3;
                    continue;
                }
                Arrays.fill(byArray3, (byte)0);
            }
            if (n5 > 0 && byArray2 == null) {
                throw new SecurityException("missing native shell binding for current platform");
            }
            runtimeResourcePartitionCount = n3;
            anchorResourcePartition = n3;
            runtimeResourceKeys = byArrayArray;
            expectedShellBindingCommitment = byArray2;
            expectedShellBindingThread = byArray2 == null ? null : Thread.currentThread();
            shellBindingHandoffState = byArray2 == null ? 0 : 1;
            bl = true;
        }
        finally {
            if (!bl) {
                for (byte[] byArray4 : byArrayArray) {
                    if (byArray4 == null) continue;
                    Arrays.fill(byArray4, (byte)0);
                }
                if (byArray2 != null) {
                    Arrays.fill(byArray2, (byte)0);
                }
            }
        }
    }

    private static synchronized /* synthetic */ void clearJavaBootMaterial() {
        byte[][] byArray = runtimeResourceKeys;
        byte[] byArray2 = expectedShellBindingCommitment;
        runtimeResourceKeys = null;
        runtimeResourcePartitionCount = 0;
        anchorResourcePartition = -1;
        expectedShellBindingCommitment = null;
        expectedShellBindingThread = null;
        shellBindingHandoffState = 0;
        if (byArray != null) {
            for (byte[] byArray3 : byArray) {
                if (byArray3 == null) continue;
                Arrays.fill(byArray3, (byte)0);
            }
        }
        if (byArray2 != null) {
            Arrays.fill(byArray2, (byte)0);
        }
        C02f581bd2c02dabf8066a201.clearNativeShellBootSecret();
    }

    private static synchronized /* synthetic */ void publishNativeShellBootSecret(byte[] byArray) {
        C02f581bd2c02dabf8066a201.clearNativeShellBootSecret();
        if (byArray == null || byArray.length != 32) {
            throw new SecurityException("native shell boot secret must be 32 bytes");
        }
        nativeShellBootSecret = Arrays.copyOf(byArray, byArray.length);
        nativeShellBootSecretThread = Thread.currentThread();
    }

    private static synchronized /* synthetic */ void clearNativeShellBootSecret() {
        byte[] byArray = nativeShellBootSecret;
        nativeShellBootSecret = null;
        nativeShellBootSecretThread = null;
        if (byArray != null) {
            Arrays.fill(byArray, (byte)0);
        }
    }

    private static synchronized /* synthetic */ byte[] takeBootSecretForNativeShell() {
        if (nativeShellBootSecret == null || nativeShellBootSecretThread != Thread.currentThread()) {
            return null;
        }
        byte[] byArray = nativeShellBootSecret;
        nativeShellBootSecret = null;
        nativeShellBootSecretThread = null;
        byte[] byArray2 = Arrays.copyOf(byArray, byArray.length);
        Arrays.fill(byArray, (byte)0);
        return byArray2;
    }

    private static synchronized /* synthetic */ void clearExpectedShellBindingCommitment() {
        byte[] byArray = expectedShellBindingCommitment;
        expectedShellBindingCommitment = null;
        expectedShellBindingThread = null;
        shellBindingHandoffState = 0;
        if (byArray != null) {
            Arrays.fill(byArray, (byte)0);
        }
    }

    private static synchronized /* synthetic */ byte[] takeExpectedShellBindingCommitment() {
        if (shellBindingHandoffState != 1 || expectedShellBindingThread != Thread.currentThread()) {
            return null;
        }
        byte[] byArray = expectedShellBindingCommitment;
        expectedShellBindingCommitment = null;
        if (byArray == null) {
            return null;
        }
        byte[] byArray2 = Arrays.copyOf(byArray, byArray.length);
        Arrays.fill(byArray, (byte)0);
        shellBindingHandoffState = 2;
        return byArray2;
    }

    private static synchronized /* synthetic */ void verifyShellBindingHandoffAfterLoad() {
        if (shellBindingHandoffState == 0) {
            return;
        }
        if (shellBindingHandoffState != 2 || expectedShellBindingCommitment != null || expectedShellBindingThread != Thread.currentThread()) {
            throw new SecurityException("native shell did not consume the boot binding commitment");
        }
        expectedShellBindingThread = null;
        shellBindingHandoffState = 0;
    }

    private static /* synthetic */ int shellBindingPlatformId(String string) {
        if ("windows-x64".equals(string)) {
            return 1;
        }
        if ("linux-x64".equals(string)) {
            return 2;
        }
        if ("macos-x64".equals(string)) {
            return 3;
        }
        if ("macos-arm64".equals(string)) {
            return 4;
        }
        return 0;
    }

    private static /* synthetic */ String detectPlatform(String string, String string2) {
        boolean bl;
        String string3 = string == null ? "" : string.trim().toLowerCase(Locale.ROOT);
        String string4 = string2 == null ? "" : string2.trim().toLowerCase(Locale.ROOT);
        boolean bl2 = "amd64".equals(string4) || "x86_64".equals(string4) || "x64".equals(string4);
        boolean bl3 = "aarch64".equals(string4) || "arm64".equals(string4);
        boolean bl4 = "windows".equals(string3) || string3.startsWith("windows ");
        boolean bl5 = "linux".equals(string3) || string3.startsWith("linux ");
        boolean bl6 = bl = "macos".equals(string3) || "mac os x".equals(string3) || string3.startsWith("mac os ");
        if (bl4) {
            return bl2 ? "windows-x64" : null;
        }
        if (bl5) {
            return bl2 ? "linux-x64" : null;
        }
        if (bl && bl2) {
            return "macos-x64";
        }
        if (bl && bl3) {
            return "macos-arm64";
        }
        return null;
    }

    private static /* synthetic */ String debugNativeLoadMessage(String string, Throwable throwable) {
        Throwable throwable2;
        if (!Boolean.getBoolean("javashroud.debugNativeLoad")) {
            return "native-unavailable";
        }
        for (throwable2 = throwable; throwable2.getCause() != null && throwable2.getCause() != throwable2; throwable2 = throwable2.getCause()) {
        }
        String string2 = string + ":" + throwable.getClass().getName() + ":" + String.valueOf(throwable.getMessage());
        if (throwable2 != throwable) {
            string2 = string2 + ":cause=" + throwable2.getClass().getName() + ":" + String.valueOf(throwable2.getMessage());
        }
        return string2;
    }

    private static /* synthetic */ boolean tryLoadBundledNative(String string, String string2) {
        I10c099465bbeb4b4[] i10c099465bbeb4b4Array;
        for (I10c099465bbeb4b4 i10c099465bbeb4b4 : i10c099465bbeb4b4Array = C02f581bd2c02dabf8066a201.sealedBundledLibraryNames(string)) {
            if (!C02f581bd2c02dabf8066a201.tryLoadBundledNativeResource(string, i10c099465bbeb4b4.resourcePath, i10c099465bbeb4b4.fileSuffix)) continue;
            return true;
        }
        return false;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     * Enabled aggressive block sorting
     * Enabled unnecessary exception pruning
     * Enabled aggressive exception aggregation
     */
    private static /* synthetic */ boolean tryLoadBundledNativeResource(String string, String string2, String string3) {
        byte[] byArray;
        try (File[] fileArray = C02f581bd2c02dabf8066a201.resourceStream(string2);){
            if (fileArray == null) {
                boolean bl = false;
                return bl;
            }
            byArray = C02f581bd2c02dabf8066a201.decodeSealedNativeResource(C02f581bd2c02dabf8066a201.readAll((InputStream)fileArray));
        }
        catch (Exception exception) {
            loadMessage = C02f581bd2c02dabf8066a201.debugNativeLoadMessage("native-resource-error:" + string2, exception);
            return false;
        }
        if (byArray == null) return false;
        if (byArray.length == 0) {
            return false;
        }
        try {
            for (File file : C02f581bd2c02dabf8066a201.nativeExtractDirectories()) {
                if (!C02f581bd2c02dabf8066a201.tryLoadBundledNativeFromDirectory(string, string2, string3, byArray, file)) continue;
                boolean bl = true;
                return bl;
            }
            boolean bl = false;
            return bl;
        }
        finally {
            Arrays.fill(byArray, (byte)0);
        }
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ boolean tryLoadBundledNativeFromDirectory(String string, String string2, String string3, byte[] byArray, File file) {
        File file2 = null;
        String string4 = System.getProperty(C02f581bd2c02dabf8066a201.sealedLoaderPropertyName());
        String string5 = System.getProperty(C02f581bd2c02dabf8066a201.sealedBindingPropertyName());
        String string6 = System.getProperty(C02f581bd2c02dabf8066a201.sealedMethodBindingPropertyName());
        String string7 = System.getProperty(C02f581bd2c02dabf8066a201.sealedFieldBindingPropertyName());
        boolean bl = bootSecretEnvBindingEnabled;
        String[] stringArray = bootSecretExpectedFingerprints == null ? new String[]{} : (String[])bootSecretExpectedFingerprints.clone();
        boolean bl2 = false;
        try {
            boolean bl3;
            if (!C02f581bd2c02dabf8066a201.ensureNativeExtractDirectory(file)) {
                boolean bl4 = false;
                return bl4;
            }
            file2 = C02f581bd2c02dabf8066a201.createUniqueTempFile(C02f581bd2c02dabf8066a201.nativeTempPrefix(string2), string3, file);
            file2.deleteOnExit();
            try (FileOutputStream fileOutputStream = new FileOutputStream(file2);){
                fileOutputStream.write(byArray);
            }
            file2.setReadable(true, true);
            file2.setWritable(true, true);
            file2.setExecutable(true, true);
            C02f581bd2c02dabf8066a201.prepareJavaBootMaterialForLoad(string);
            C02f581bd2c02dabf8066a201.publishSealedNativeBindings();
            sealedNativeBindingsPublished = true;
            System.load(file2.getAbsolutePath());
            C02f581bd2c02dabf8066a201.verifyShellBindingHandoffAfterLoad();
            loadMessage = "native:bundled:" + string + ":" + C02f581bd2c02dabf8066a201.initializeNativeKernel(string);
            C02f581bd2c02dabf8066a201.installBootMaterialIntoNative(string);
            try {
                C02f581bd2c02dabf8066a201.preloadRuntimeResourcesIntoNative();
                if (C02f581bd2c02dabf8066a201.verifyNativeAbiAfterLoad()) {
                    C02f581bd2c02dabf8066a201.verifyBootTokenAfterLoad(string);
                    bl2 = !nativeSelfCheckFailed;
                }
                bl3 = bl2;
            }
            catch (Throwable throwable) {
                try {
                    C02f581bd2c02dabf8066a201.clearJavaBootMaterial();
                    if (!bl2) {
                        sealedNativeBindingsPublished = false;
                    }
                    throw throwable;
                }
                catch (UnsatisfiedLinkError unsatisfiedLinkError) {
                    loadMessage = C02f581bd2c02dabf8066a201.debugNativeLoadMessage("native:bundled-load-error", unsatisfiedLinkError);
                    if (file2 != null) {
                        file2.delete();
                    }
                    boolean bl5 = false;
                    return bl5;
                }
                catch (Exception exception) {
                    loadMessage = "native:bundled-init-error:" + exception.getClass().getName() + ":" + String.valueOf(exception.getMessage());
                    if (file2 != null) {
                        file2.delete();
                    }
                    boolean bl6 = false;
                    return bl6;
                }
            }
            C02f581bd2c02dabf8066a201.clearJavaBootMaterial();
            if (!bl2) {
                sealedNativeBindingsPublished = false;
            }
            return bl3;
        }
        finally {
            if (!bl2) {
                C02f581bd2c02dabf8066a201.clearJavaBootMaterial();
                try {
                    C02f581bd2c02dabf8066a201.nativeAbortBootMaterial();
                }
                catch (Throwable throwable) {}
                sealedNativeBindingsPublished = false;
                bootSecretEnvBindingEnabled = bl;
                Object[] objectArray = bootSecretExpectedFingerprints;
                bootSecretExpectedFingerprints = stringArray;
                if (objectArray != null && objectArray != stringArray) {
                    Arrays.fill(objectArray, null);
                }
                C02f581bd2c02dabf8066a201.restoreProperty(C02f581bd2c02dabf8066a201.sealedLoaderPropertyName(), string4);
                C02f581bd2c02dabf8066a201.restoreProperty(C02f581bd2c02dabf8066a201.sealedBindingPropertyName(), string5);
                C02f581bd2c02dabf8066a201.restoreProperty(C02f581bd2c02dabf8066a201.sealedMethodBindingPropertyName(), string6);
                C02f581bd2c02dabf8066a201.restoreProperty(C02f581bd2c02dabf8066a201.sealedFieldBindingPropertyName(), string7);
            }
        }
    }

    private static /* synthetic */ int initializeNativeKernel(String string) {
        int n = C02f581bd2c02dabf8066a201.nativeInit(string);
        return n == 2 ? C02f581bd2c02dabf8066a201.nativeInit(string) : n;
    }

    private static /* synthetic */ File[] nativeExtractDirectories() {
        String string;
        LinkedHashSet<String> linkedHashSet = new LinkedHashSet<String>();
        C02f581bd2c02dabf8066a201.addNativeExtractDirectory(linkedHashSet, System.getProperty("javashroud.native.extract.dir", ""));
        String string2 = System.getProperty("user.home", "");
        if (string2 != null && string2.length() > 0) {
            C02f581bd2c02dabf8066a201.addNativeExtractDirectory(linkedHashSet, new File(new File(string2, ".javashroud"), "native"));
        }
        if ((string = System.getProperty("user.dir", "")) != null && string.length() > 0) {
            C02f581bd2c02dabf8066a201.addNativeExtractDirectory(linkedHashSet, new File(new File(string, ".javashroud-native"), "native"));
        }
        C02f581bd2c02dabf8066a201.addNativeExtractDirectory(linkedHashSet, System.getProperty("java.io.tmpdir", ""));
        File[] fileArray = new File[linkedHashSet.size()];
        int n = 0;
        for (String string3 : linkedHashSet) {
            fileArray[n++] = new File(string3);
        }
        return fileArray;
    }

    private static /* synthetic */ void addNativeExtractDirectory(LinkedHashSet<String> linkedHashSet, String string) {
        if (string == null) {
            return;
        }
        String string2 = string.trim();
        if (string2.length() == 0) {
            return;
        }
        C02f581bd2c02dabf8066a201.addNativeExtractDirectory(linkedHashSet, new File(string2));
    }

    private static /* synthetic */ void addNativeExtractDirectory(LinkedHashSet<String> linkedHashSet, File file) {
        if (file == null) {
            return;
        }
        try {
            linkedHashSet.add(file.getAbsoluteFile().getPath());
        }
        catch (SecurityException securityException) {
            // empty catch block
        }
    }

    private static /* synthetic */ boolean ensureNativeExtractDirectory(File file) {
        try {
            if (file == null) {
                return false;
            }
            if (file.exists()) {
                return file.isDirectory() && file.canWrite();
            }
            return file.mkdirs() && file.isDirectory() && file.canWrite();
        }
        catch (SecurityException securityException) {
            return false;
        }
    }

    private static /* synthetic */ String nativeTempPrefix(String string) {
        int n = -2128831035;
        for (int i = 0; i < string.length(); ++i) {
            n ^= string.charAt(i) & 0xFF;
            n *= 16777619;
        }
        String string2 = Integer.toUnsignedString(n, 36);
        return ("n" + string2 + "xxxx").substring(0, 8);
    }

    private static /* synthetic */ InputStream resourceStream(String string) {
        InputStream inputStream = C02f581bd2c02dabf8066a201.class.getResourceAsStream("/" + string);
        if (inputStream != null) {
            return inputStream;
        }
        ClassLoader classLoader = C02f581bd2c02dabf8066a201.class.getClassLoader();
        return classLoader == null ? null : classLoader.getResourceAsStream(string);
    }

    private static /* synthetic */ void publishSealedNativeBindings() {
        try {
            String[] stringArray;
            C02f581bd2c02dabf8066a201.publishSealedNativeLoaderOwner();
            String string = C02f581bd2c02dabf8066a201.sealedNativeBindingText();
            if (string == null || string.length() == 0) {
                if (!SEALED_NATIVE_BINDINGS_RESOURCE.equals(C02f581bd2c02dabf8066a201.legacySealedNativeBindingsResource())) {
                    throw new SecurityException("sealed native bindings unavailable");
                }
                return;
            }
            StringBuilder stringBuilder = new StringBuilder();
            StringBuilder stringBuilder2 = new StringBuilder();
            StringBuilder stringBuilder3 = new StringBuilder();
            for (String string2 : stringArray = string.split("\n")) {
                String[] stringArray2 = string2.trim().split("\\|", -1);
                if (stringArray2.length == 3 && "B".equals(stringArray2[0])) {
                    if (stringBuilder.length() > 0) {
                        stringBuilder.append('\n');
                    }
                    stringBuilder.append(stringArray2[1]).append('=').append(stringArray2[2]);
                    continue;
                }
                if (stringArray2.length == 3 && "M".equals(stringArray2[0])) {
                    if (stringBuilder2.length() > 0) {
                        stringBuilder2.append('\n');
                    }
                    stringBuilder2.append(stringArray2[1]).append('=').append(stringArray2[2]);
                    continue;
                }
                if (stringArray2.length == 3 && "F".equals(stringArray2[0])) {
                    if (stringBuilder3.length() > 0) {
                        stringBuilder3.append('\n');
                    }
                    stringBuilder3.append(stringArray2[1]).append('=').append(stringArray2[2]);
                    continue;
                }
                if (stringArray2.length != 3 || !"E".equals(stringArray2[0])) continue;
                bootSecretEnvBindingEnabled = "true".equalsIgnoreCase(stringArray2[1]);
                bootSecretExpectedFingerprints = stringArray2[2].isEmpty() ? new String[]{} : stringArray2[2].split(",");
            }
            if (stringBuilder.length() > 0) {
                System.setProperty(C02f581bd2c02dabf8066a201.sealedBindingPropertyName(), C02f581bd2c02dabf8066a201.mergeBindingProperties(System.getProperty(C02f581bd2c02dabf8066a201.sealedBindingPropertyName()), stringBuilder.toString()));
            }
            if (stringBuilder2.length() > 0) {
                System.setProperty(C02f581bd2c02dabf8066a201.sealedMethodBindingPropertyName(), C02f581bd2c02dabf8066a201.mergeBindingProperties(System.getProperty(C02f581bd2c02dabf8066a201.sealedMethodBindingPropertyName()), stringBuilder2.toString()));
            }
            if (stringBuilder3.length() > 0) {
                System.setProperty(C02f581bd2c02dabf8066a201.sealedFieldBindingPropertyName(), C02f581bd2c02dabf8066a201.mergeBindingProperties(System.getProperty(C02f581bd2c02dabf8066a201.sealedFieldBindingPropertyName()), stringBuilder3.toString()));
            }
        }
        catch (SecurityException securityException) {
            throw securityException;
        }
        catch (Throwable throwable) {
            throw new SecurityException("sealed native bindings unavailable", throwable);
        }
    }

    private static /* synthetic */ void publishSealedNativeLoaderOwner() {
        System.setProperty(C02f581bd2c02dabf8066a201.sealedLoaderPropertyName(), C02f581bd2c02dabf8066a201.class.getName().replace('.', '/'));
    }

    private static /* synthetic */ void ensureSealedNativeBindingsPublished() {
        if (sealedNativeBindingsPublished) {
            return;
        }
        C02f581bd2c02dabf8066a201.publishSealedNativeBindings();
        sealedNativeBindingsPublished = true;
    }

    private static /* synthetic */ void restoreProperty(String string, String string2) {
        try {
            if (string2 == null) {
                System.clearProperty(string);
            } else {
                System.setProperty(string, string2);
            }
        }
        catch (Throwable throwable) {
            // empty catch block
        }
    }

    private static /* synthetic */ String mergeBindingProperties(String string, String string2) {
        if (string == null || string.length() == 0) {
            return string2;
        }
        if (string2 == null || string2.length() == 0) {
            return string;
        }
        LinkedHashMap<String, String> linkedHashMap = new LinkedHashMap<String, String>();
        C02f581bd2c02dabf8066a201.appendBindingProperties(linkedHashMap, string);
        C02f581bd2c02dabf8066a201.appendBindingProperties(linkedHashMap, string2);
        StringBuilder stringBuilder = new StringBuilder();
        for (Map.Entry<String, String> entry : linkedHashMap.entrySet()) {
            if (stringBuilder.length() > 0) {
                stringBuilder.append('\n');
            }
            stringBuilder.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return stringBuilder.toString();
    }

    private static /* synthetic */ void appendBindingProperties(LinkedHashMap<String, String> linkedHashMap, String string) {
        String[] stringArray;
        for (String string2 : stringArray = string.split("\n")) {
            int n = string2.indexOf(61);
            if (n <= 0) continue;
            linkedHashMap.put(string2.substring(0, n), string2.substring(n + 1));
        }
    }

    private static /* synthetic */ String sealedLoaderPropertyName() {
        return new String(new char[]{'j', '.', 'l'});
    }

    private static /* synthetic */ String sealedBindingPropertyName() {
        return new String(new char[]{'j', '.', 'b'});
    }

    private static /* synthetic */ String sealedMethodBindingPropertyName() {
        return new String(new char[]{'j', '.', 'm'});
    }

    private static /* synthetic */ String sealedFieldBindingPropertyName() {
        return new String(new char[]{'j', '.', 'f'});
    }

    private static /* synthetic */ String legacySealedNativeBindingsResource() {
        return new String(new char[]{'M', 'E', 'T', 'A', '-', 'I', 'N', 'F', '/', '.', 'r', '/', 'b', 'i', 'n', 'd', 'i', 'n', 'g', 's', '.', 'd', 'a', 't'});
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     * Enabled aggressive exception aggregation
     */
    private static /* synthetic */ String sealedNativeIndexText() {
        try (InputStream inputStream = C02f581bd2c02dabf8066a201.resourceStream(SEALED_NATIVE_INDEX_RESOURCE);){
            String string;
            if (inputStream == null) {
                String string2 = null;
                return string2;
            }
            byte[] byArray = C02f581bd2c02dabf8066a201.readAll(inputStream);
            byte[] byArray2 = null;
            try {
                byArray2 = C02f581bd2c02dabf8066a201.hasRuntimeResourceHeader(byArray) ? C02f581bd2c02dabf8066a201.decodeRuntimeResource(byArray, true) : C02f581bd2c02dabf8066a201.decodeBootstrapNativeIndex(byArray);
                string = byArray2 == null ? null : new String(byArray2, StandardCharsets.UTF_8);
            }
            catch (Throwable throwable) {
                Arrays.fill(byArray, (byte)0);
                if (byArray2 != null) {
                    Arrays.fill(byArray2, (byte)0);
                }
                throw throwable;
            }
            Arrays.fill(byArray, (byte)0);
            if (byArray2 != null) {
                Arrays.fill(byArray2, (byte)0);
            }
            return string;
        }
        catch (Exception exception) {
            return null;
        }
    }

    /*
     * Enabled aggressive block sorting
     * Enabled unnecessary exception pruning
     * Enabled aggressive exception aggregation
     */
    private static /* synthetic */ String sealedNativeBindingText() {
        try (InputStream inputStream = C02f581bd2c02dabf8066a201.resourceStream(SEALED_NATIVE_BINDINGS_RESOURCE);){
            if (inputStream == null) {
                String string2 = null;
                return string2;
            }
            byte[] byArray = C02f581bd2c02dabf8066a201.decodeRuntimeResource(C02f581bd2c02dabf8066a201.readAll(inputStream), true);
            String string = byArray == null ? null : new String(byArray, StandardCharsets.UTF_8);
            return string;
        }
        catch (Exception exception) {
            return null;
        }
    }

    private static /* synthetic */ I10c099465bbeb4b4[] sealedBundledLibraryNames(String string) {
        try {
            String[] stringArray;
            String string2 = C02f581bd2c02dabf8066a201.sealedNativeIndexText();
            if (string2 == null || string2.length() == 0) {
                return new I10c099465bbeb4b4[0];
            }
            LinkedHashSet<I10c099465bbeb4b4> linkedHashSet = new LinkedHashSet<I10c099465bbeb4b4>();
            for (String string3 : stringArray = string2.split("\n")) {
                String[] stringArray2 = string3.trim().split("\\|", -1);
                if (stringArray2.length != 3 || !string.equals(stringArray2[0])) continue;
                linkedHashSet.add(new I10c099465bbeb4b4(stringArray2[1], stringArray2[2]));
            }
            return linkedHashSet.toArray(new I10c099465bbeb4b4[0]);
        }
        catch (Exception exception) {
            return new I10c099465bbeb4b4[0];
        }
    }

    private static /* synthetic */ byte[] decodeSealedNativeResource(byte[] byArray) {
        if (byArray == null || byArray.length == 0 || C02f581bd2c02dabf8066a201.hasRuntimeResourceHeader(byArray)) {
            return null;
        }
        return byArray;
    }

    private static /* synthetic */ byte[] hexToBytes(String string) {
        if ((string.length() & 1) != 0) {
            throw new IllegalArgumentException("odd hex");
        }
        byte[] byArray = new byte[string.length() / 2];
        for (int i = 0; i < byArray.length; ++i) {
            int n = Character.digit(string.charAt(i * 2), 16);
            int n2 = Character.digit(string.charAt(i * 2 + 1), 16);
            if (n < 0 || n2 < 0) {
                Arrays.fill(byArray, (byte)0);
                throw new IllegalArgumentException("bad hex");
            }
            byArray[i] = (byte)(n << 4 | n2);
        }
        return byArray;
    }

    private static /* synthetic */ byte[] hexToBytes(byte[] byArray) {
        if ((byArray.length & 1) != 0) {
            throw new IllegalArgumentException("odd hex");
        }
        byte[] byArray2 = new byte[byArray.length / 2];
        for (int i = 0; i < byArray2.length; ++i) {
            int n = Character.digit((char)(byArray[i * 2] & 0xFF), 16);
            int n2 = Character.digit((char)(byArray[i * 2 + 1] & 0xFF), 16);
            if (n < 0 || n2 < 0) {
                Arrays.fill(byArray2, (byte)0);
                throw new IllegalArgumentException("bad hex");
            }
            byArray2[i] = (byte)(n << 4 | n2);
        }
        return byArray2;
    }

    public static /* synthetic */ byte[] decodeRuntimeResourceForNative(byte[] byArray) {
        byte[] byArray2;
        if (loadState == 2 && C02f581bd2c02dabf8066a201.nativeIsBootMaterialReady()) {
            try {
                byArray2 = C02f581bd2c02dabf8066a201.nativeDecodeRuntimeResource(byArray);
            }
            catch (LinkageError linkageError) {
                byArray2 = null;
            }
            if (byArray2 == null) {
                byArray2 = C02f581bd2c02dabf8066a201.decodeRuntimeResource(byArray, true);
            }
        } else {
            byArray2 = C02f581bd2c02dabf8066a201.decodeRuntimeResource(byArray, true);
        }
        if (byArray2 == null) {
            throw new IllegalArgumentException("unsupported runtime resource envelope");
        }
        return byArray2;
    }

    private static /* synthetic */ byte[] partitionResourceKey(int n) {
        byte[][] byArray = runtimeResourceKeys;
        if (byArray == null || n < 0 || n >= byArray.length) {
            throw new SecurityException("runtime key slot unavailable");
        }
        return (byte[])byArray[n].clone();
    }

    public static /* synthetic */ byte[] decodeRuntimeResourceEnvelope(byte[] byArray) {
        return loadState == 2 && C02f581bd2c02dabf8066a201.nativeIsBootMaterialReady() ? C02f581bd2c02dabf8066a201.nativeDecodeRuntimeResource(byArray) : C02f581bd2c02dabf8066a201.decodeRuntimeResource(byArray, true);
    }

    private static /* synthetic */ byte[] decodeBootstrapNativeIndex(byte[] byArray) {
        if (byArray == null || byArray.length < 42) {
            return null;
        }
        if ((byArray[0] & 0xFF) != 74 || (byArray[1] & 0xFF) != 83 || (byArray[2] & 0xFF) != 66 || (byArray[3] & 0xFF) != 73) {
            return null;
        }
        if ((byArray[4] & 0xFF) != 1) {
            return null;
        }
        int n = C02f581bd2c02dabf8066a201.readSealedResourceLe32(byArray, 5);
        if (n < 0) {
            return null;
        }
        int n2 = 9;
        int n3 = n2 + n;
        if (n3 + 33 != byArray.length || (byArray[byArray.length - 1] & 0xFF) != 32) {
            return null;
        }
        byte[] byArray2 = C02f581bd2c02dabf8066a201.hmacSha256(C02f581bd2c02dabf8066a201.concat("jsbi-auth".getBytes(StandardCharsets.US_ASCII), Arrays.copyOfRange(byArray, 0, n3)));
        if (!C02f581bd2c02dabf8066a201.constantTimeEquals(byArray2, byArray, n3)) {
            return null;
        }
        return Arrays.copyOfRange(byArray, n2, n3);
    }

    private static /* synthetic */ byte[] decodeRuntimeResource(byte[] byArray, boolean bl) {
        if (!C02f581bd2c02dabf8066a201.hasRuntimeResourceHeader(byArray)) {
            return null;
        }
        int n = byArray[4] & 0xFF;
        if (n == 7) {
            return C02f581bd2c02dabf8066a201.decodeRuntimeResourceCurrent(byArray, bl);
        }
        return null;
    }

    private static /* synthetic */ boolean hasRuntimeResourceHeader(byte[] byArray) {
        return byArray != null && byArray.length >= 5 && (byArray[0] & 0xFF) == 74 && (byArray[1] & 0xFF) == 83 && (byArray[2] & 0xFF) == 82 && (byArray[3] & 0xFF) == 80;
    }

    /*
     * WARNING - Removed try catching itself - possible behaviour change.
     */
    private static /* synthetic */ byte[] decodeRuntimeResourceCurrent(byte[] byArray, boolean bl) {
        if (byArray.length < 156 || (byArray[byArray.length - 1] & 0xFF) != 32) {
            return null;
        }
        byte[] byArray2 = Arrays.copyOfRange(byArray, 5, 21);
        int n = C02f581bd2c02dabf8066a201.readSealedResourceLe16(byArray, 21);
        int n2 = C02f581bd2c02dabf8066a201.readSealedResourceLe16(byArray, 23);
        int n3 = C02f581bd2c02dabf8066a201.readSealedResourceLe16(byArray, 25);
        if (n != 96 || n2 != 32) {
            return null;
        }
        if (n3 < 0 || n3 > C02f581bd2c02dabf8066a201.anchorResourcePartition) {
            return null;
        }
        int n4 = 27;
        int n5 = n4 + n;
        if (n5 + 33 > byArray.length) {
            return null;
        }
        int n6 = byArray.length - 33;
        byte[] byArray3 = C02f581bd2c02dabf8066a201.partitionResourceKey(n3);
        try {
            byte[] byArray4;
            byte[] byArray5 = C02f581bd2c02dabf8066a201.hmacSha256(byArray3, C02f581bd2c02dabf8066a201.concat("jsrp-auth-v3".getBytes(StandardCharsets.US_ASCII), byArray2, Arrays.copyOfRange(byArray, 0, n6)));
            if (!C02f581bd2c02dabf8066a201.constantTimeEquals(byArray5, byArray, n6)) {
                byte[] byArray6 = null;
                return byArray6;
            }
            byte[] byArray7 = C02f581bd2c02dabf8066a201.runtimeResourceAesCtrWithDomains(byArray3, Arrays.copyOfRange(byArray, n4, n5), byArray2, C02f581bd2c02dabf8066a201.intBytes(0), C02f581bd2c02dabf8066a201.intBytes(0), C02f581bd2c02dabf8066a201.intBytes(0));
            I1d6a307162aea03b i1d6a307162aea03b = C02f581bd2c02dabf8066a201.parseRuntimeResourceMetadata(byArray7);
            if (i1d6a307162aea03b == null) {
                byte[] byArray8 = null;
                return byArray8;
            }
            if (i1d6a307162aea03b.partitionId != n3) {
                byte[] byArray9 = null;
                return byArray9;
            }
            if (i1d6a307162aea03b.kindId < 1 || i1d6a307162aea03b.kindId > 4) {
                byte[] byArray10 = null;
                return byArray10;
            }
            if (i1d6a307162aea03b.layerCount < 1 || i1d6a307162aea03b.layerCount > 7 || i1d6a307162aea03b.variantId > 127) {
                byte[] byArray11 = null;
                return byArray11;
            }
            if (i1d6a307162aea03b.plainLength < 0 || i1d6a307162aea03b.storedLength < 0 || i1d6a307162aea03b.bodyLength < 0) {
                byte[] byArray12 = null;
                return byArray12;
            }
            if (n5 + i1d6a307162aea03b.bodyLength != n6) {
                byte[] byArray13 = null;
                return byArray13;
            }
            byte[] byArray14 = Arrays.copyOfRange(byArray, n5, n6);
            byte[] byArray15 = C02f581bd2c02dabf8066a201.runtimeResourceAesCtrWithDomains(byArray3, byArray14, byArray2, C02f581bd2c02dabf8066a201.intBytes(i1d6a307162aea03b.kindId), C02f581bd2c02dabf8066a201.intBytes(i1d6a307162aea03b.variantId), C02f581bd2c02dabf8066a201.intBytes(i1d6a307162aea03b.layerCount));
            if (byArray15.length != i1d6a307162aea03b.storedLength) {
                byte[] byArray16 = null;
                return byArray16;
            }
            if (!Arrays.equals(C02f581bd2c02dabf8066a201.sha256(byArray15), i1d6a307162aea03b.storedHash)) {
                byte[] byArray17 = null;
                return byArray17;
            }
            Object object = i1d6a307162aea03b.compressed ? (Object)(bl ? C02f581bd2c02dabf8066a201.decompressEmbeddedZstd(byArray15, i1d6a307162aea03b.plainLength) : null) : (byArray4 = byArray15);
            if (byArray4 == null || byArray4.length != i1d6a307162aea03b.plainLength) {
                byte[] byArray18 = null;
                return byArray18;
            }
            byte[] byArray19 = (byte[])(Arrays.equals(C02f581bd2c02dabf8066a201.sha256(byArray4), i1d6a307162aea03b.plainHash) ? byArray4 : null);
            return byArray19;
        }
        finally {
            Arrays.fill(byArray3, (byte)0);
        }
    }

    private static /* synthetic */ byte[] decompressEmbeddedZstd(byte[] byArray, int n) {
        int n2;
        long l;
        boolean bl;
        int n3;
        if (n < 0 || byArray == null || byArray.length < 7) {
            return null;
        }
        int n4 = 0;
        if (C02f581bd2c02dabf8066a201.readSealedResourceLe32(byArray, n4) != -47205080) {
            return null;
        }
        n4 += 4;
        if (((n3 = byArray[n4++] & 0xFF) & 8) != 0 || (n3 & 3) != 0) {
            return null;
        }
        int n5 = n3 >>> 6;
        boolean bl2 = (n3 & 0x20) != 0;
        boolean bl3 = bl = (n3 & 4) != 0;
        if (!bl2) {
            if (n4 >= byArray.length) {
                return null;
            }
            ++n4;
        }
        if ((l = C02f581bd2c02dabf8066a201.readZstdFrameContentSize(byArray, n4, n2 = n5 == 0 ? (bl2 ? 1 : 0) : (n5 == 1 ? 2 : (n5 == 2 ? 4 : 8)))) != (long)n) {
            return null;
        }
        n4 += n2;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(n);
        boolean bl4 = false;
        while (!bl4) {
            if (n4 + 3 > byArray.length) {
                return null;
            }
            int n6 = byArray[n4] & 0xFF | (byArray[n4 + 1] & 0xFF) << 8 | (byArray[n4 + 2] & 0xFF) << 16;
            n4 += 3;
            bl4 = (n6 & 1) != 0;
            int n7 = n6 >>> 1 & 3;
            int n8 = n6 >>> 3;
            if (n7 == 0) {
                if (n4 + n8 > byArray.length) {
                    return null;
                }
                byteArrayOutputStream.write(byArray, n4, n8);
                n4 += n8;
            } else if (n7 == 1) {
                if (n4 >= byArray.length) {
                    return null;
                }
                for (int i = 0; i < n8; ++i) {
                    byteArrayOutputStream.write(byArray[n4] & 0xFF);
                }
                ++n4;
            } else {
                return null;
            }
            if (byteArrayOutputStream.size() <= n) continue;
            return null;
        }
        if (bl) {
            if (n4 + 4 > byArray.length) {
                return null;
            }
            n4 += 4;
        }
        if (n4 != byArray.length || byteArrayOutputStream.size() != n) {
            return null;
        }
        return byteArrayOutputStream.toByteArray();
    }

    private static /* synthetic */ long readZstdFrameContentSize(byte[] byArray, int n, int n2) {
        if (n2 < 0 || n2 > 8 || n < 0 || n + n2 > byArray.length) {
            return -1L;
        }
        long l = 0L;
        for (int i = 0; i < n2; ++i) {
            l |= (long)(byArray[n + i] & 0xFF) << 8 * i;
        }
        return n2 == 2 ? l + 256L : l;
    }

    private static /* synthetic */ byte[] runtimeResourceAesCtrWithDomains(byte[] byArray, byte[] byArray2, byte[] byArray3, byte[] byArray4, byte[] byArray5, byte[] byArray6) {
        try {
            byte[] byArray7 = Arrays.copyOfRange(C02f581bd2c02dabf8066a201.hmacSha256(byArray, C02f581bd2c02dabf8066a201.concat("jsrp-aes-key".getBytes(StandardCharsets.US_ASCII), byArray3, byArray4, byArray5, byArray6)), 0, 16);
            byte[] byArray8 = Arrays.copyOfRange(C02f581bd2c02dabf8066a201.hmacSha256(byArray, C02f581bd2c02dabf8066a201.concat("jsrp-aes-iv".getBytes(StandardCharsets.US_ASCII), byArray3, byArray4, byArray5, byArray6)), 0, 16);
            return C02f581bd2c02dabf8066a201.aesCtrCrypt(byArray7, byArray8, byArray2);
        }
        catch (Exception exception) {
            return new byte[0];
        }
    }

    private static /* synthetic */ I1d6a307162aea03b parseRuntimeResourceMetadata(byte[] byArray) {
        if (byArray == null || byArray.length != 96) {
            return null;
        }
        if (byArray[0] != 77 || byArray[1] != 50 || byArray[2] != 1) {
            return null;
        }
        int n = byArray[6] & 0xFF;
        if ((n & 0xFE) != 0) {
            return null;
        }
        int n2 = C02f581bd2c02dabf8066a201.readSealedResourceBe32(C02f581bd2c02dabf8066a201.sha256(Arrays.copyOfRange(byArray, 0, 92)), 0);
        if (C02f581bd2c02dabf8066a201.readSealedResourceLe32(byArray, 92) != n2) {
            return null;
        }
        I1d6a307162aea03b i1d6a307162aea03b = new I1d6a307162aea03b();
        i1d6a307162aea03b.kindId = byArray[3] & 0xFF;
        i1d6a307162aea03b.layerCount = byArray[4] & 0xFF;
        i1d6a307162aea03b.variantId = byArray[5] & 0xFF;
        i1d6a307162aea03b.compressed = (n & 1) != 0;
        i1d6a307162aea03b.plainLength = C02f581bd2c02dabf8066a201.readSealedResourceLe32(byArray, 8);
        i1d6a307162aea03b.storedLength = C02f581bd2c02dabf8066a201.readSealedResourceLe32(byArray, 12);
        i1d6a307162aea03b.bodyLength = C02f581bd2c02dabf8066a201.readSealedResourceLe32(byArray, 16);
        i1d6a307162aea03b.partitionId = byArray[7] & 0xFF;
        i1d6a307162aea03b.keyId = C02f581bd2c02dabf8066a201.readSealedResourceLe32(byArray, 20);
        i1d6a307162aea03b.seed = C02f581bd2c02dabf8066a201.readSealedResourceLe32(byArray, 24);
        i1d6a307162aea03b.plainHash = Arrays.copyOfRange(byArray, 28, 60);
        i1d6a307162aea03b.storedHash = Arrays.copyOfRange(byArray, 60, 92);
        return i1d6a307162aea03b;
    }

    private static /* synthetic */ int aesXtime(int n) {
        return (n << 1 ^ ((n & 0x80) != 0 ? 27 : 0)) & 0xFF;
    }

    private static /* synthetic */ byte[] aesSbox() {
        int n;
        if (aesSboxTable != null) {
            return aesSboxTable;
        }
        byte[] byArray = new byte[256];
        int[] nArray = new int[256];
        int[] nArray2 = new int[255];
        int n2 = 1;
        for (n = 0; n < 255; ++n) {
            nArray2[n] = n2;
            nArray[n2] = n;
            n2 = n2 << 1 ^ n2 ^ ((n2 & 0x80) != 0 ? 27 : 0);
            n2 &= 0xFF;
        }
        byArray[0] = 99;
        for (n = 1; n < 256; ++n) {
            int n3;
            int n4 = n3 = nArray2[(255 - nArray[n]) % 255];
            n4 ^= (n3 << 1 | n3 >>> 7) & 0xFF;
            n4 ^= (n3 << 2 | n3 >>> 6) & 0xFF;
            n4 ^= (n3 << 3 | n3 >>> 5) & 0xFF;
            byArray[n] = (byte)((n4 ^= (n3 << 4 | n3 >>> 4) & 0xFF) ^ 0x63);
        }
        aesSboxTable = byArray;
        return byArray;
    }

    private static /* synthetic */ int[] aesExpandKey(byte[] byArray, byte[] byArray2) {
        int n;
        int[] nArray = new int[44];
        for (n = 0; n < 4; ++n) {
            nArray[n] = (byArray[4 * n] & 0xFF) << 24 | (byArray[4 * n + 1] & 0xFF) << 16 | (byArray[4 * n + 2] & 0xFF) << 8 | byArray[4 * n + 3] & 0xFF;
        }
        for (n = 4; n < 44; ++n) {
            int n2 = nArray[n - 1];
            if (n % 4 == 0) {
                int n3 = n2 << 8 | n2 >>> 24;
                n2 = (byArray2[n3 >>> 24 & 0xFF] & 0xFF) << 24 | (byArray2[n3 >>> 16 & 0xFF] & 0xFF) << 16 | (byArray2[n3 >>> 8 & 0xFF] & 0xFF) << 8 | byArray2[n3 & 0xFF] & 0xFF;
                n2 ^= AES_RCON[n / 4 - 1] << 24;
            }
            nArray[n] = nArray[n - 4] ^ n2;
        }
        return nArray;
    }

    private static /* synthetic */ int aesMixColumn(int n, int n2, int n3, int n4, int n5) {
        switch (n5) {
            case 0: {
                return C02f581bd2c02dabf8066a201.aesXtime(n) ^ (C02f581bd2c02dabf8066a201.aesXtime(n2) ^ n2) ^ n3 ^ n4;
            }
            case 1: {
                return n ^ C02f581bd2c02dabf8066a201.aesXtime(n2) ^ (C02f581bd2c02dabf8066a201.aesXtime(n3) ^ n3) ^ n4;
            }
            case 2: {
                return n ^ n2 ^ C02f581bd2c02dabf8066a201.aesXtime(n3) ^ (C02f581bd2c02dabf8066a201.aesXtime(n4) ^ n4);
            }
        }
        return C02f581bd2c02dabf8066a201.aesXtime(n) ^ n ^ n2 ^ n3 ^ C02f581bd2c02dabf8066a201.aesXtime(n4);
    }

    private static /* synthetic */ void aesEncryptBlock(int[] nArray, byte[] byArray, byte[] byArray2, int n, byte[] byArray3, int n2) {
        int n3;
        int n4;
        int n5;
        int n6;
        int n7;
        int[] nArray2 = new int[4];
        for (n7 = 0; n7 < 4; ++n7) {
            nArray2[n7] = (byArray2[n + 4 * n7] & 0xFF) << 24 | (byArray2[n + 4 * n7 + 1] & 0xFF) << 16 | (byArray2[n + 4 * n7 + 2] & 0xFF) << 8 | byArray2[n + 4 * n7 + 3] & 0xFF;
            int n8 = n7;
            nArray2[n8] = nArray2[n8] ^ nArray[n7];
        }
        for (n7 = 1; n7 < 10; ++n7) {
            int[] nArray3 = new int[4];
            for (n6 = 0; n6 < 4; ++n6) {
                n5 = byArray[nArray2[n6] >>> 24 & 0xFF] & 0xFF;
                n4 = byArray[nArray2[n6 + 1 & 3] >>> 16 & 0xFF] & 0xFF;
                n3 = byArray[nArray2[n6 + 2 & 3] >>> 8 & 0xFF] & 0xFF;
                int n9 = byArray[nArray2[n6 + 3 & 3] & 0xFF] & 0xFF;
                nArray3[n6] = C02f581bd2c02dabf8066a201.aesMixColumn(n5, n4, n3, n9, 0) << 24 | C02f581bd2c02dabf8066a201.aesMixColumn(n5, n4, n3, n9, 1) << 16 | C02f581bd2c02dabf8066a201.aesMixColumn(n5, n4, n3, n9, 2) << 8 | C02f581bd2c02dabf8066a201.aesMixColumn(n5, n4, n3, n9, 3);
            }
            for (n6 = 0; n6 < 4; ++n6) {
                nArray2[n6] = nArray3[n6] ^ nArray[n7 * 4 + n6];
            }
        }
        for (n7 = 0; n7 < 4; ++n7) {
            int n10 = byArray[nArray2[n7] >>> 24 & 0xFF] & 0xFF;
            n6 = byArray[nArray2[n7 + 1 & 3] >>> 16 & 0xFF] & 0xFF;
            n5 = byArray[nArray2[n7 + 2 & 3] >>> 8 & 0xFF] & 0xFF;
            n4 = byArray[nArray2[n7 + 3 & 3] & 0xFF] & 0xFF;
            n3 = (n10 << 24 | n6 << 16 | n5 << 8 | n4) ^ nArray[40 + n7];
            byArray3[n2 + 4 * n7] = (byte)(n3 >>> 24);
            byArray3[n2 + 4 * n7 + 1] = (byte)(n3 >>> 16);
            byArray3[n2 + 4 * n7 + 2] = (byte)(n3 >>> 8);
            byArray3[n2 + 4 * n7 + 3] = (byte)n3;
        }
    }

    private static /* synthetic */ byte[] aesCtrCrypt(byte[] byArray, byte[] byArray2, byte[] byArray3) {
        byte[] byArray4 = C02f581bd2c02dabf8066a201.aesSbox();
        int[] nArray = C02f581bd2c02dabf8066a201.aesExpandKey(byArray, byArray4);
        byte[] byArray5 = (byte[])byArray2.clone();
        byte[] byArray6 = new byte[16];
        byte[] byArray7 = new byte[byArray3.length];
        int n = 0;
        block0: while (n < byArray3.length) {
            int n2;
            C02f581bd2c02dabf8066a201.aesEncryptBlock(nArray, byArray4, byArray5, 0, byArray6, 0);
            int n3 = Math.min(16, byArray3.length - n);
            for (n2 = 0; n2 < n3; ++n2) {
                byArray7[n + n2] = (byte)(byArray3[n + n2] ^ byArray6[n2]);
            }
            n += n3;
            for (n2 = 15; n2 >= 0; --n2) {
                byArray5[n2] = (byte)(byArray5[n2] + 1);
                if (byArray5[n2] != 0) continue block0;
            }
        }
        Arrays.fill(byArray6, (byte)0);
        return byArray7;
    }

    private static /* synthetic */ byte[] hmacSha256(byte[] byArray) {
        byte[] byArray2 = C02f581bd2c02dabf8066a201.partitionResourceKey(C02f581bd2c02dabf8066a201.anchorResourcePartition);
        try {
            byte[] byArray3 = C02f581bd2c02dabf8066a201.hmacSha256(byArray2, byArray);
            return byArray3;
        }
        finally {
            Arrays.fill(byArray2, (byte)0);
        }
    }

    private static /* synthetic */ byte[] hmacSha256(byte[] byArray, byte[] byArray2) {
        try {
            byte[] byArray3 = byArray.length > 64 ? C02f581bd2c02dabf8066a201.sha256(byArray) : byArray;
            byte[] byArray4 = new byte[64];
            byte[] byArray5 = new byte[64];
            for (int i = 0; i < 64; ++i) {
                byte by = i < byArray3.length ? byArray3[i] : (byte)0;
                byArray4[i] = (byte)(by ^ 0x36);
                byArray5[i] = (byte)(by ^ 0x5C);
            }
            return C02f581bd2c02dabf8066a201.sha256(C02f581bd2c02dabf8066a201.concat(byArray5, C02f581bd2c02dabf8066a201.sha256(C02f581bd2c02dabf8066a201.concat(byArray4, byArray2))));
        }
        catch (Exception exception) {
            return new byte[32];
        }
    }

    public static /* synthetic */ byte[] deriveClassEncryptionKey(byte[] byArray, byte[] byArray2, int n) {
        if (!C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            C02f581bd2c02dabf8066a201.m_d7c5053f05b22be5("loader", "auto", "vm-diverse");
        }
        if (!C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            throw new SecurityException("class-encryption key derivation requires the sealed native kernel; no Java fallback (" + loadMessage + ")");
        }
        return C02f581bd2c02dabf8066a201.nativeDeriveClassEncryptionKey(byArray, byArray2, n);
    }

    public static /* synthetic */ byte[] decryptClassBytes(byte[] byArray, byte[] byArray2, byte[] byArray3, byte[] byArray4, byte[] byArray5, int n) {
        if (byArray == null || byArray2 == null || byArray3 == null || byArray4 == null || byArray5 == null) {
            throw new SecurityException("encrypted class metadata is incomplete");
        }
        if (byArray3.length != 12 || byArray4.length < 16 || n != 16 && n != 32) {
            throw new SecurityException("encrypted class metadata is invalid");
        }
        if (!C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            C02f581bd2c02dabf8066a201.m_d7c5053f05b22be5("loader", "auto", "vm-diverse");
        }
        if (!C02f581bd2c02dabf8066a201.isNativeLoaded()) {
            throw new SecurityException("class-encryption decryption requires the sealed native kernel; no Java fallback (" + loadMessage + ")");
        }
        try {
            byte[] byArray6 = C02f581bd2c02dabf8066a201.nativeDecryptClassBytes(byArray, byArray2, byArray3, byArray4, byArray5, n);
            if (byArray6 == null) {
                throw new SecurityException("native class decryption returned no plaintext");
            }
            return byArray6;
        }
        catch (UnsatisfiedLinkError unsatisfiedLinkError) {
            throw new SecurityException("class-encryption native decoder is not registered for the sealed helper", unsatisfiedLinkError);
        }
    }

    private static /* synthetic */ boolean isDecimal(String string) {
        if (string == null || string.length() == 0 || string.length() > 10) {
            return false;
        }
        for (int i = 0; i < string.length(); ++i) {
            char c = string.charAt(i);
            if (c >= '0' && c <= '9') continue;
            return false;
        }
        return true;
    }

    private static /* synthetic */ int parsePositiveInt(String string, String string2) {
        if (!C02f581bd2c02dabf8066a201.isDecimal(string)) {
            throw new SecurityException("invalid VM catalog " + string2);
        }
        try {
            int n = Integer.parseInt(string);
            if (n < 0) {
                throw new SecurityException("invalid VM catalog " + string2);
            }
            return n;
        }
        catch (NumberFormatException numberFormatException) {
            throw new SecurityException("invalid VM catalog " + string2, numberFormatException);
        }
    }

    private static /* synthetic */ int lastIndexOf(byte[] byArray, byte[] byArray2) {
        if (byArray == null || byArray2 == null || byArray2.length == 0 || byArray2.length > byArray.length) {
            return -1;
        }
        for (int i = byArray.length - byArray2.length; i >= 0; --i) {
            boolean bl = true;
            for (int j = 0; j < byArray2.length; ++j) {
                if (byArray[i + j] == byArray2[j]) continue;
                bl = false;
                break;
            }
            if (!bl) continue;
            return i;
        }
        return -1;
    }

    private static /* synthetic */ boolean hasPartitionedRuntimeResourceHeader(byte[] byArray, int n) {
        return byArray != null && byArray.length >= 27 && byArray[0] == 74 && byArray[1] == 83 && byArray[2] == 82 && byArray[3] == 80 && (byArray[4] & 0xFF) == 7 && C02f581bd2c02dabf8066a201.readSealedResourceLe16(byArray, 25) == n;
    }

    private static /* synthetic */ byte[] vmCatalogMerkleRoot(List<byte[]> list, byte[] byArray, int n) {
        if (list.isEmpty()) {
            return C02f581bd2c02dabf8066a201.sha256(C02f581bd2c02dabf8066a201.concat("JSP1".getBytes(StandardCharsets.US_ASCII), byArray, C02f581bd2c02dabf8066a201.intBytes(n)));
        }
        ArrayList<Object> arrayList = new ArrayList<byte[]>(list);
        C02f581bd2c02dabf8066a201.sortByteArrays(arrayList);
        while (arrayList.size() > 1) {
            ArrayList<byte[]> arrayList2 = new ArrayList<byte[]>((arrayList.size() + 1) / 2);
            for (int i = 0; i < arrayList.size(); i += 2) {
                byte[] byArray2 = (byte[])arrayList.get(i);
                byte[] byArray3 = i + 1 < arrayList.size() ? (byte[])arrayList.get(i + 1) : byArray2;
                arrayList2.add(C02f581bd2c02dabf8066a201.sha256(C02f581bd2c02dabf8066a201.concat("JSP1".getBytes(StandardCharsets.US_ASCII), byArray2, byArray3)));
            }
            arrayList = arrayList2;
        }
        return (byte[])arrayList.get(0);
    }

    private static /* synthetic */ byte[] vmCatalogRoot(byte[] byArray, List<byte[]> list) {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] byArray2 = "JSC1-root".getBytes(StandardCharsets.US_ASCII);
        byteArrayOutputStream.write(byArray2, 0, byArray2.length);
        byteArrayOutputStream.write(byArray, 0, byArray.length);
        for (int i = 0; i < list.size(); ++i) {
            byte[] byArray3 = C02f581bd2c02dabf8066a201.intBytes(i);
            byte[] byArray4 = list.get(i);
            byteArrayOutputStream.write(byArray3, 0, byArray3.length);
            byteArrayOutputStream.write(byArray4, 0, byArray4.length);
        }
        return C02f581bd2c02dabf8066a201.sha256(byteArrayOutputStream.toByteArray());
    }

    private static /* synthetic */ int compareUnsigned(byte[] byArray, byte[] byArray2) {
        int n = Math.min(byArray.length, byArray2.length);
        for (int i = 0; i < n; ++i) {
            int n2 = Integer.compare(byArray[i] & 0xFF, byArray2[i] & 0xFF);
            if (n2 == 0) continue;
            return n2;
        }
        return Integer.compare(byArray.length, byArray2.length);
    }

    private static /* synthetic */ void sortVmCatalogDirectories(List<String[]> list) {
        for (int i = 1; i < list.size(); ++i) {
            int n;
            String[] stringArray = list.get(i);
            int n2 = C02f581bd2c02dabf8066a201.parsePositiveInt(stringArray[1], "partition id");
            for (n = i - 1; n >= 0 && C02f581bd2c02dabf8066a201.parsePositiveInt(list.get(n)[1], "partition id") > n2; --n) {
                list.set(n + 1, list.get(n));
            }
            list.set(n + 1, stringArray);
        }
    }

    private static /* synthetic */ void sortByteArrays(List<byte[]> list) {
        for (int i = 1; i < list.size(); ++i) {
            int n;
            byte[] byArray = list.get(i);
            for (n = i - 1; n >= 0 && C02f581bd2c02dabf8066a201.compareUnsigned(list.get(n), byArray) > 0; --n) {
                list.set(n + 1, list.get(n));
            }
            list.set(n + 1, byArray);
        }
    }

    private static /* synthetic */ byte[] frame(String string) {
        byte[] byArray = string.getBytes(StandardCharsets.UTF_8);
        return C02f581bd2c02dabf8066a201.concat(C02f581bd2c02dabf8066a201.intBytes(byArray.length), byArray);
    }

    private static /* synthetic */ byte[] longBytes(long l) {
        return new byte[]{(byte)(l >>> 56), (byte)(l >>> 48), (byte)(l >>> 40), (byte)(l >>> 32), (byte)(l >>> 24), (byte)(l >>> 16), (byte)(l >>> 8), (byte)l};
    }

    private static /* synthetic */ byte[] concat(byte[] ... byArray) {
        int n = 0;
        for (byte[] byArray2 : byArray) {
            n += byArray2.length;
        }
        byte[] byArray3 = new byte[n];
        int n2 = 0;
        for (byte[] byArray4 : byArray) {
            System.arraycopy(byArray4, 0, byArray3, n2, byArray4.length);
            n2 += byArray4.length;
        }
        return byArray3;
    }

    private static /* synthetic */ byte[] intBytes(int n) {
        return new byte[]{(byte)(n >>> 24), (byte)(n >>> 16), (byte)(n >>> 8), (byte)n};
    }

    private static /* synthetic */ boolean constantTimeEquals(byte[] byArray, byte[] byArray2, int n) {
        if (n < 0 || n + byArray.length > byArray2.length) {
            return false;
        }
        int n2 = 0;
        for (int i = 0; i < byArray.length; ++i) {
            n2 |= (byArray[i] ^ byArray2[n + i]) & 0xFF;
        }
        return n2 == 0;
    }

    private static /* synthetic */ byte[] sha256(byte[] byArray) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(byArray);
        }
        catch (Exception exception) {
            return new byte[32];
        }
    }

    private static /* synthetic */ int readSealedResourceLe16(byte[] byArray, int n) {
        return byArray[n] & 0xFF | (byArray[n + 1] & 0xFF) << 8;
    }

    private static /* synthetic */ int readSealedResourceLe32(byte[] byArray, int n) {
        return byArray[n] & 0xFF | (byArray[n + 1] & 0xFF) << 8 | (byArray[n + 2] & 0xFF) << 16 | (byArray[n + 3] & 0xFF) << 24;
    }

    private static /* synthetic */ int readSealedResourceBe32(byte[] byArray, int n) {
        return (byArray[n] & 0xFF) << 24 | (byArray[n + 1] & 0xFF) << 16 | (byArray[n + 2] & 0xFF) << 8 | byArray[n + 3] & 0xFF;
    }

    private static /* synthetic */ File createUniqueTempFile(String string, String string2, File file) throws IOException {
        long l = System.nanoTime();
        for (int i = 0; i < 100; ++i) {
            File file2 = new File(file, string + (l + (long)i) + string2);
            if (!file2.createNewFile()) continue;
            return file2;
        }
        throw new IOException("cannot create unique temp file in " + file);
    }

    private static /* synthetic */ byte[] readAll(InputStream inputStream) throws Exception {
        int n;
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byte[] byArray = new byte[1024];
        while ((n = inputStream.read(byArray)) > 0) {
            byteArrayOutputStream.write(byArray, 0, n);
        }
        return byteArrayOutputStream.toByteArray();
    }

    static {
        loadState = 0;
        loadMessage = "";
        diversifiedVmEnabled = false;
        vmSelfCheck = "";
        nativeBootToken = 0L;
        nativeSelfCheckFailed = false;
        sealedNativeBindingsPublished = false;
        bootSecretEnvBindingEnabled = false;
        bootSecretExpectedFingerprints = new String[0];
        anchorResourcePartition = -1;
        BOOT_MATERIAL_AAD = "javashroud-boot-material-v2".getBytes(StandardCharsets.US_ASCII);
        HARDENED_BOOT_MATERIAL_AAD = "javashroud-boot-material-v3".getBytes(StandardCharsets.US_ASCII);
        BOOT_SIDECAR_TEXT_PREFIX = "JSBK1.".getBytes(StandardCharsets.US_ASCII);
        BOOT_SIDECAR_KEY_DOMAIN = "JavaShroud/BootKekSidecar/v1/key".getBytes(StandardCharsets.US_ASCII);
        SAM_LAMBDA_CACHE = new ConcurrentHashMap<String, MethodHandle>();
        SAM_BRIDGE_INTERFACE_CACHE = new ConcurrentHashMap();
        AES_RCON = new int[]{1, 2, 4, 8, 16, 32, 64, 128, 27, 54};
    }

    private static final class I4d804b1d48de1013 {
        final /* synthetic */ int flags;
        final /* synthetic */ Class<?>[] markerInterfaces;
        final /* synthetic */ String[] bridgeDescriptors;

        I4d804b1d48de1013(int n, Class<?>[] classArray, String[] stringArray) {
            this.flags = n;
            this.markerInterfaces = Arrays.copyOf(classArray, classArray.length);
            this.bridgeDescriptors = Arrays.copyOf(stringArray, stringArray.length);
        }
    }

    private static final class I8df6ac0025772ff2
    implements InvocationHandler,
    Serializable {
        private static final /* synthetic */ long serialVersionUID = 1L;
        private final /* synthetic */ String samInterfaceName;
        private final /* synthetic */ String samName;
        private final /* synthetic */ String owner;
        private final /* synthetic */ String name;
        private final /* synthetic */ String descriptor;
        private final /* synthetic */ int implTag;
        private final /* synthetic */ String instantiatedDescriptor;
        private final /* synthetic */ Object[] captured;
        private transient /* synthetic */ MethodHandle target;

        I8df6ac0025772ff2(String string, String string2, String string3, String string4, String string5, int n, String string6, Object[] objectArray, MethodHandle methodHandle) {
            this.samInterfaceName = string;
            this.samName = string2;
            this.owner = string3;
            this.name = string4;
            this.descriptor = string5;
            this.implTag = n;
            this.instantiatedDescriptor = string6;
            this.captured = Arrays.copyOf(objectArray, objectArray.length);
            this.target = methodHandle;
        }

        @Override
        public /* synthetic */ Object invoke(Object object, Method method, Object[] objectArray) throws Throwable {
            Object[] objectArray2;
            Object[] objectArray3 = objectArray2 = objectArray == null ? new Object[]{} : objectArray;
            if (method.getDeclaringClass() == Object.class) {
                if ("equals".equals(method.getName())) {
                    return objectArray2.length == 1 && object == objectArray2[0];
                }
                if ("hashCode".equals(method.getName())) {
                    return System.identityHashCode(object);
                }
                if ("toString".equals(method.getName())) {
                    return this.samInterfaceName + "@" + Integer.toHexString(System.identityHashCode(object));
                }
            }
            if (method.isDefault()) {
                MethodHandle methodHandle = C02f581bd2c02dabf8066a201.privateLookup(method.getDeclaringClass()).unreflectSpecial(method, method.getDeclaringClass()).bindTo(object);
                return methodHandle.invokeWithArguments(objectArray2);
            }
            if (!this.samName.equals(method.getName())) {
                throw new AbstractMethodError(method.toString());
            }
            MethodType methodType = MethodType.methodType(method.getReturnType(), method.getParameterTypes());
            return this.target().asType(methodType).invokeWithArguments(objectArray2);
        }

        private /* synthetic */ MethodHandle target() throws ReflectiveOperationException {
            if (this.target != null) {
                return this.target;
            }
            ClassLoader classLoader = C02f581bd2c02dabf8066a201.class.getClassLoader();
            MethodHandle methodHandle = C02f581bd2c02dabf8066a201.resolveSamLambdaTarget(this.owner, this.name, this.descriptor, this.implTag);
            MethodType methodType = MethodType.fromMethodDescriptorString(this.instantiatedDescriptor, classLoader);
            this.target = C02f581bd2c02dabf8066a201.adaptSamLambdaTarget(methodHandle, this.captured, methodType);
            return this.target;
        }

        private /* synthetic */ void readObject(ObjectInputStream objectInputStream) throws IOException, ClassNotFoundException {
            objectInputStream.defaultReadObject();
            try {
                this.target = this.target();
            }
            catch (ReflectiveOperationException | RuntimeException exception) {
                InvalidObjectException invalidObjectException = new InvalidObjectException("cannot relink virtualized SAM lambda");
                invalidObjectException.initCause(exception);
                throw invalidObjectException;
            }
        }
    }

    private static final class I4607d6e8f130899c {
        final /* synthetic */ Class<?> type;
        final /* synthetic */ int nextIndex;

        I4607d6e8f130899c(Class<?> clazz, int n) {
            this.type = clazz;
            this.nextIndex = n;
        }
    }

    private static final class I10c099465bbeb4b4 {
        final /* synthetic */ String resourcePath;
        final /* synthetic */ String fileSuffix;

        I10c099465bbeb4b4(String string, String string2) {
            this.resourcePath = string;
            this.fileSuffix = string2;
        }

        public /* synthetic */ boolean equals(Object object) {
            if (!(object instanceof I10c099465bbeb4b4)) {
                return false;
            }
            I10c099465bbeb4b4 i10c099465bbeb4b4 = (I10c099465bbeb4b4)object;
            return this.resourcePath.equals(i10c099465bbeb4b4.resourcePath) && this.fileSuffix.equals(i10c099465bbeb4b4.fileSuffix);
        }

        public /* synthetic */ int hashCode() {
            return this.resourcePath.hashCode() * 31 + this.fileSuffix.hashCode();
        }
    }

    private static final class I1d6a307162aea03b {
        /* synthetic */ int partitionId;
        /* synthetic */ int kindId;
        /* synthetic */ int layerCount;
        /* synthetic */ int variantId;
        /* synthetic */ boolean compressed;
        /* synthetic */ int plainLength;
        /* synthetic */ int storedLength;
        /* synthetic */ int bodyLength;
        /* synthetic */ int keyId;
        /* synthetic */ int seed;
        /* synthetic */ byte[] plainHash;
        /* synthetic */ byte[] storedHash;

        private I1d6a307162aea03b() {
        }
    }
}

