package io.github.hht0rro.javashroud.transforms.protection;

import java.lang.invoke.CallSite;
import java.lang.invoke.ConstantCallSite;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;
import java.lang.invoke.MutableCallSite;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Runtime helper for callsite rotation. Each site binds one of five dispatch
 * shapes so a single template cannot normalize every rotating indy.
 */
public final class CallsiteRotationHelper {
    private static final ConcurrentHashMap<Integer, Object[]> SITES = new ConcurrentHashMap<Integer, Object[]>();
    private static final AtomicInteger NEXT_ID = new AtomicInteger();
    private static final ThreadLocal<Integer> THREAD_SLOT = new ThreadLocal<Integer>();
    private static final MethodHandle ALWAYS_TRUE;
    private static final MethodHandle TABLE_DISPATCH;
    private static final MethodHandle THREAD_DISPATCH;
    private static final MethodHandle ONESHOT_DISPATCH;
    private static final MethodHandle TICK_MUTABLE;

    static {
        try {
            MethodHandles.Lookup lookup = MethodHandles.lookup();
            ALWAYS_TRUE = MethodHandles.constant(boolean.class, true);
            TABLE_DISPATCH = lookup.findStatic(
                CallsiteRotationHelper.class,
                "tableDispatch",
                MethodType.methodType(Object.class, int.class, Object[].class)
            );
            THREAD_DISPATCH = lookup.findStatic(
                CallsiteRotationHelper.class,
                "threadDispatch",
                MethodType.methodType(Object.class, int.class, Object[].class)
            );
            ONESHOT_DISPATCH = lookup.findStatic(
                CallsiteRotationHelper.class,
                "oneShotDispatch",
                MethodType.methodType(Object.class, int.class, Object[].class)
            );
            TICK_MUTABLE = lookup.findStatic(
                CallsiteRotationHelper.class,
                "tickMutable",
                MethodType.methodType(void.class, int.class)
            );
        } catch (Exception ex) {
            throw new ExceptionInInitializerError(ex);
        }
    }

    private CallsiteRotationHelper() {}

    public static CallSite createRotatingCallSite(
        MethodHandles.Lookup lookup,
        String name,
        MethodType type,
        String owner,
        String strategy
    ) throws Exception {
        MethodHandle target = resolveTarget(lookup, name, type, owner);
        String kind = canonicalStrategy(strategy);
        if ("mutable".equals(kind)) {
            return bindMutable(target, type);
        }
        if ("guarded".equals(kind)) {
            return bindGuarded(target, type);
        }
        if ("table".equals(kind)) {
            return bindTable(target, type);
        }
        if ("thread-slot".equals(kind)) {
            return bindThreadSlot(target, type);
        }
        if ("oneshot".equals(kind)) {
            return bindOneShot(target, type);
        }
        throw new SecurityException("unsupported rotation strategy");
    }

    public static Object tableDispatch(int id, Object[] args) throws Throwable {
        Object[] state = requireState(id);
        MethodHandle[] wrappers = (MethodHandle[]) state[1];
        AtomicLong counter = (AtomicLong) state[2];
        int slot = (int) ((counter.incrementAndGet() / 8L) % wrappers.length);
        return wrappers[slot].invokeWithArguments(args);
    }

    public static Object threadDispatch(int id, Object[] args) throws Throwable {
        Object[] state = requireState(id);
        MethodHandle[] wrappers = (MethodHandle[]) state[1];
        Integer current = THREAD_SLOT.get();
        int next = ((current == null ? 0 : current.intValue()) + 1) % wrappers.length;
        THREAD_SLOT.set(Integer.valueOf(next));
        return wrappers[next].invokeWithArguments(args);
    }

    public static Object oneShotDispatch(int id, Object[] args) throws Throwable {
        Object[] state = requireState(id);
        MutableCallSite site = (MutableCallSite) state[0];
        MethodHandle target = ((MethodHandle[]) state[1])[0];
        try {
            return target.invokeWithArguments(args);
        } finally {
            MethodHandle guarded = MethodHandles.guardWithTest(ALWAYS_TRUE, target, target);
            site.setTarget(guarded.asType(site.type()));
            MutableCallSite.syncAll(new MutableCallSite[] {site});
        }
    }

    public static void tickMutable(int id) {
        Object[] state = SITES.get(Integer.valueOf(id));
        if (state == null) {
            return;
        }
        AtomicLong counter = (AtomicLong) state[2];
        if ((counter.incrementAndGet() & 31L) != 0L) {
            return;
        }
        MutableCallSite site = (MutableCallSite) state[0];
        MethodHandle[] wrappers = (MethodHandle[]) state[1];
        int slot = (int) ((counter.get() / 32L) % wrappers.length);
        site.setTarget(folded(wrappers[slot], id).asType(site.type()));
        MutableCallSite.syncAll(new MutableCallSite[] {site});
    }

    private static CallSite bindMutable(MethodHandle target, MethodType type) {
        int id = NEXT_ID.incrementAndGet();
        MutableCallSite site = new MutableCallSite(type);
        MethodHandle[] wrappers = distinctWrappers(target, type);
        SITES.put(Integer.valueOf(id), new Object[] {site, wrappers, new AtomicLong()});
        site.setTarget(folded(wrappers[0], id).asType(type));
        return site;
    }

    private static CallSite bindGuarded(MethodHandle target, MethodType type) {
        MethodHandle[] wrappers = distinctWrappers(target, type);
        MethodHandle guarded = MethodHandles.guardWithTest(ALWAYS_TRUE, wrappers[0], wrappers[1]);
        return new ConstantCallSite(guarded.asType(type));
    }

    private static CallSite bindTable(MethodHandle target, MethodType type) {
        int id = NEXT_ID.incrementAndGet();
        MethodHandle[] wrappers = distinctWrappers(target, type);
        Object[] state = new Object[] {null, wrappers, new AtomicLong()};
        SITES.put(Integer.valueOf(id), state);
        MethodHandle bound = MethodHandles.insertArguments(TABLE_DISPATCH, 0, Integer.valueOf(id));
        return new ConstantCallSite(asInvoker(bound, type));
    }

    private static CallSite bindThreadSlot(MethodHandle target, MethodType type) {
        int id = NEXT_ID.incrementAndGet();
        MethodHandle[] wrappers = distinctWrappers(target, type);
        SITES.put(Integer.valueOf(id), new Object[] {null, wrappers, new AtomicLong()});
        MethodHandle bound = MethodHandles.insertArguments(THREAD_DISPATCH, 0, Integer.valueOf(id));
        return new ConstantCallSite(asInvoker(bound, type));
    }

    private static CallSite bindOneShot(MethodHandle target, MethodType type) {
        int id = NEXT_ID.incrementAndGet();
        MutableCallSite site = new MutableCallSite(type);
        MethodHandle[] wrappers = distinctWrappers(target, type);
        SITES.put(Integer.valueOf(id), new Object[] {site, wrappers, new AtomicLong()});
        MethodHandle bound = MethodHandles.insertArguments(ONESHOT_DISPATCH, 0, Integer.valueOf(id));
        site.setTarget(asInvoker(bound, type));
        return site;
    }

    private static MethodHandle folded(MethodHandle target, int id) {
        MethodHandle tick = MethodHandles.insertArguments(TICK_MUTABLE, 0, Integer.valueOf(id));
        return MethodHandles.foldArguments(target, tick);
    }

    private static MethodHandle asInvoker(MethodHandle dispatch, MethodType type) {
        return dispatch.asCollector(Object[].class, type.parameterCount()).asType(type);
    }

    private static MethodHandle[] distinctWrappers(MethodHandle target, MethodType type) {
        MethodHandle direct = target.asType(type);
        MethodHandle noop = MethodHandles.empty(MethodType.methodType(void.class));
        MethodHandle folded = MethodHandles.foldArguments(direct, noop);
        MethodHandle rethrow = MethodHandles.throwException(type.returnType(), RuntimeException.class);
        MethodHandle handler = MethodHandles.dropArguments(rethrow, 1, type.parameterArray());
        MethodHandle caught = MethodHandles.catchException(direct, RuntimeException.class, handler);
        return new MethodHandle[] {direct, folded, caught};
    }

    private static MethodHandle resolveTarget(
        MethodHandles.Lookup lookup,
        String name,
        MethodType type,
        String ownerOrToken
    ) throws Exception {
        if (ownerOrToken != null && ownerOrToken.length() >= 24) {
            try {
                return IndyTargetBootstrap.resolveHandle(lookup, name, type, ownerOrToken).asType(type);
            } catch (SecurityException ex) {
                throw ex;
            } catch (Exception ex) {
                throw new SecurityException("callsite target token authentication failed");
            }
        }
        throw new SecurityException("callsite target token is required");
    }

    private static Object[] requireState(int id) {
        Object[] state = SITES.get(Integer.valueOf(id));
        if (state == null) {
            throw new SecurityException("callsite rotation state is missing");
        }
        return state;
    }

    private static String canonicalStrategy(String strategy) {
        if ("mutable".equals(strategy) || "epoch".equals(strategy)) {
            return "mutable";
        }
        if ("table".equals(strategy) || "counter".equals(strategy)) {
            return "table";
        }
        if ("thread-slot".equals(strategy) || "thread-local".equals(strategy)) {
            return "thread-slot";
        }
        if ("guarded".equals(strategy) || "random".equals(strategy)) {
            return "guarded";
        }
        if ("oneshot".equals(strategy)) {
            return "oneshot";
        }
        throw new SecurityException("unsupported rotation strategy");
    }
}
