/*
 * Derived from dex2jar 2.4.28, dex-translator sources, under Apache License 2.0.
 * Source and attribution are recorded in THIRD_PARTY_NOTICES.md.
 * Modified for JavaShroud on 2026-11-26 to split classfile UTF8 constants while
 * preserving DEX registers, incoming parameters, debug locals and string identity.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.googlecode.d2j.dex;

import com.googlecode.d2j.CallSite;
import com.googlecode.d2j.DexLabel;
import com.googlecode.d2j.Proto;
import com.googlecode.d2j.DexConstants;
import com.googlecode.d2j.Field;
import com.googlecode.d2j.Method;
import com.googlecode.d2j.node.DexClassNode;
import com.googlecode.d2j.node.DexCodeNode;
import com.googlecode.d2j.node.DexFieldNode;
import com.googlecode.d2j.node.DexFileNode;
import com.googlecode.d2j.node.DexMethodNode;
import com.googlecode.d2j.node.insn.ConstStmtNode;
import com.googlecode.d2j.node.insn.DexStmtNode;
import com.googlecode.d2j.reader.Op;
import com.googlecode.d2j.visitors.DexCodeVisitor;
import com.googlecode.d2j.visitors.DexDebugVisitor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 1. Dex omits the value of static-final field if it is the default value.
 * <p>
 * 2. static-final field init by zero, but assigned in clinit
 * <p>
 * this method is try to fix the problems.
 */
public final class DexFix {

    private static final int ACC_STATIC_FINAL = DexConstants.ACC_STATIC | DexConstants.ACC_FINAL;

    private DexFix() {
        throw new UnsupportedOperationException();
    }

    public static void fixStaticFinalFieldValue(final DexFileNode dex) {
        if (dex.clzs != null) {
            for (DexClassNode classNode : dex.clzs) {
                fixStaticFinalFieldValue(classNode);
            }
        }
    }

    /**
     * Target: Class
     * <p>
     * init value to default if the field is static and final, and the field is not init in clinit method
     * <p>
     * erase the default value if the field is init in clinit method
     */
    public static void fixStaticFinalFieldValue(final DexClassNode classNode) {
        if (classNode.fields == null) {
            return;
        }
        final Map<String, DexFieldNode> fs = new HashMap<>();
        final Map<String, DexFieldNode> shouldNotBeAssigned = new HashMap<>();
        for (DexFieldNode fn : classNode.fields) {
            if ((fn.access & ACC_STATIC_FINAL) == ACC_STATIC_FINAL) {
                if (fn.cst == null) {
                    char t = fn.field.getType().charAt(0);
                    if (t == 'L' || t == '[') {
                        // ignore Object
                        continue;
                    }
                    fs.put(fn.field.getName() + ":" + fn.field.getType(), fn);
                } else if (isPrimitiveZero(fn.field.getType(), fn.cst)) {
                    shouldNotBeAssigned.put(fn.field.getName() + ":" + fn.field.getType(), fn);
                }
            }
        }
        if (fs.isEmpty() && shouldNotBeAssigned.isEmpty()) {
            return;
        }
        DexMethodNode node = null;
        if (classNode.methods != null) {
            for (DexMethodNode mn : classNode.methods) {
                if (mn.method.getName().equals("<clinit>")) {
                    node = mn;
                    break;
                }
            }
        }
        if (node != null) {
            if (node.codeNode != null) {
                node.codeNode.accept(new DexCodeVisitor() {
                    @Override
                    public void visitFieldStmt(Op op, int a, int b, Field field) {
                        switch (op) {
                        case SPUT:
                        case SPUT_BOOLEAN:
                        case SPUT_BYTE:
                        case SPUT_CHAR:
                        case SPUT_OBJECT:
                        case SPUT_SHORT:
                        case SPUT_WIDE:
                            if (field.getOwner().equals(classNode.className)) {
                                String key = field.getName() + ":" + field.getType();
                                fs.remove(key);
                                DexFieldNode dn = shouldNotBeAssigned.get(key);
                                if (dn != null) {
                                    //System.out.println(field.getName() + ":" + field.getType());
                                    dn.cst = null;
                                }
                            }
                            break;
                        default:
                            // ignored
                            break;
                        }
                    }
                });
            } else {
                // has init but no code
                return;
            }
        }

        for (DexFieldNode fn : fs.values()) {
            fn.cst = getDefaultValueOfType(fn.field.getType().charAt(0));
        }

    }

    /**
     * Target: Method
     * <p>
     * Fixes too long strings not being translated correctly
     * </p>
     */
    public static void fixTooLongStringConstant(final DexMethodNode methodNode) {
        if (methodNode.codeNode == null) {
            return;
        }
        boolean needsSplitting = false;
        for (DexStmtNode statement : methodNode.codeNode.stmts) {
            if (isOversizedString(statement)) {
                needsSplitting = true;
                break;
            }
        }
        if (!needsSplitting) {
            return;
        }

        // Reserve v0 and shift every original register, including incoming parameters.
        DexCodeNode shifted = new DexCodeNode();
        methodNode.codeNode.accept(new ShiftedRegisterVisitor(shifted));
        List<DexStmtNode> statements = new ArrayList<>();
        for (DexStmtNode statement : shifted.stmts) {
            if (isOversizedString(statement)) {
                ConstStmtNode constant = (ConstStmtNode) statement;
                DexCodeNode generated = new DexCodeNode();
                emitLongString(generated, constant.a, (String) constant.value);
                statements.addAll(generated.stmts);
            } else {
                statements.add(statement);
            }
        }
        shifted.stmts = statements;
        methodNode.codeNode = shifted;
    }

    private static final int CONSTANT_UTF8_LIMIT = 65535;
    private static final int MIN_OVERSIZED_UTF16_LENGTH = CONSTANT_UTF8_LIMIT / 3 + 1;

    private static boolean isOversizedString(DexStmtNode statement) {
        if (!(statement instanceof ConstStmtNode)
                || (statement.op != Op.CONST_STRING && statement.op != Op.CONST_STRING_JUMBO)) {
            return false;
        }
        Object value = ((ConstStmtNode) statement).value;
        if (!(value instanceof String)) {
            return false;
        }
        String text = (String) value;
        if (text.length() < MIN_OVERSIZED_UTF16_LENGTH) {
            return false;
        }
        int bytes = 0;
        for (int index = 0; index < text.length(); index++) {
            bytes += modifiedUtf8Width(text.charAt(index));
            if (bytes > CONSTANT_UTF8_LIMIT) {
                return true;
            }
        }
        return false;
    }

    private static int modifiedUtf8Width(char value) {
        if (value == 0) {
            return 2;
        }
        if (value <= 0x7f) {
            return 1;
        }
        return value <= 0x7ff ? 2 : 3;
    }

    private static void emitLongString(DexCodeVisitor visitor, int destination, String text) {
        visitor.visitTypeStmt(Op.NEW_INSTANCE, destination, 0, "Ljava/lang/StringBuilder;");
        visitor.visitConstStmt(Op.CONST, 0, text.length());
        visitor.visitMethodStmt(Op.INVOKE_DIRECT, new int[] {destination, 0},
                new Method("Ljava/lang/StringBuilder;", "<init>", new String[] {"I"}, "V"));
        int start = 0;
        while (start < text.length()) {
            int end = start;
            int bytes = 0;
            while (end < text.length()) {
                int width = modifiedUtf8Width(text.charAt(end));
                if (bytes + width > CONSTANT_UTF8_LIMIT) {
                    break;
                }
                bytes += width;
                end++;
            }
            visitor.visitConstStmt(Op.CONST_STRING, 0, text.substring(start, end));
            visitor.visitMethodStmt(Op.INVOKE_VIRTUAL, new int[] {destination, 0},
                    new Method("Ljava/lang/StringBuilder;", "append",
                            new String[] {"Ljava/lang/String;"}, "Ljava/lang/StringBuilder;"));
            start = end;
        }
        visitor.visitMethodStmt(Op.INVOKE_VIRTUAL, new int[] {destination},
                new Method("Ljava/lang/StringBuilder;", "toString", new String[0], "Ljava/lang/String;"));
        visitor.visitStmt1R(Op.MOVE_RESULT_OBJECT, destination);
        // DEX string constants are interned, including those exceeding a classfile UTF8 entry.
        visitor.visitMethodStmt(Op.INVOKE_VIRTUAL, new int[] {destination},
                new Method("Ljava/lang/String;", "intern", new String[0], "Ljava/lang/String;"));
        visitor.visitStmt1R(Op.MOVE_RESULT_OBJECT, destination);
    }

    private static final class ShiftedRegisterVisitor extends DexCodeVisitor {
        private ShiftedRegisterVisitor(DexCodeVisitor visitor) {
            super(visitor);
        }

        private static int shift(int register) {
            return register < 0 ? register : register + 1;
        }

        private static int[] shift(int[] registers) {
            int[] shifted = registers.clone();
            for (int index = 0; index < shifted.length; index++) {
                shifted[index] = shift(shifted[index]);
            }
            return shifted;
        }

        @Override
        public void visitRegister(int total) {
            super.visitRegister(Math.addExact(total, 1));
        }

        @Override
        public void visitStmt1R(Op op, int a) {
            super.visitStmt1R(op, shift(a));
        }

        @Override
        public void visitStmt2R(Op op, int a, int b) {
            super.visitStmt2R(op, shift(a), shift(b));
        }

        @Override
        public void visitStmt2R1N(Op op, int a, int b, int content) {
            super.visitStmt2R1N(op, shift(a), shift(b), content);
        }

        @Override
        public void visitStmt3R(Op op, int a, int b, int c) {
            super.visitStmt3R(op, shift(a), shift(b), shift(c));
        }

        @Override
        public void visitTypeStmt(Op op, int a, int b, String type) {
            super.visitTypeStmt(op, shift(a), shift(b), type);
        }

        @Override
        public void visitConstStmt(Op op, int register, Object value) {
            super.visitConstStmt(op, shift(register), value);
        }

        @Override
        public void visitFieldStmt(Op op, int a, int b, Field field) {
            super.visitFieldStmt(op, shift(a), shift(b), field);
        }

        @Override
        public void visitFillArrayDataStmt(Op op, int register, Object array) {
            super.visitFillArrayDataStmt(op, shift(register), array);
        }

        @Override
        public void visitFilledNewArrayStmt(Op op, int[] registers, String type) {
            super.visitFilledNewArrayStmt(op, shift(registers), type);
        }

        @Override
        public void visitJumpStmt(Op op, int a, int b, DexLabel label) {
            super.visitJumpStmt(op, shift(a), shift(b), label);
        }

        @Override
        public void visitMethodStmt(Op op, int[] registers, Method method) {
            super.visitMethodStmt(op, shift(registers), method);
        }

        @Override
        public void visitMethodStmt(Op op, int[] registers, CallSite callSite) {
            super.visitMethodStmt(op, shift(registers), callSite);
        }

        @Override
        public void visitMethodStmt(Op op, int[] registers, Method method, Proto proto) {
            super.visitMethodStmt(op, shift(registers), method, proto);
        }

        @Override
        public void visitPackedSwitchStmt(Op op, int register, int firstCase, DexLabel[] labels) {
            super.visitPackedSwitchStmt(op, shift(register), firstCase, labels);
        }

        @Override
        public void visitSparseSwitchStmt(Op op, int register, int[] cases, DexLabel[] labels) {
            super.visitSparseSwitchStmt(op, shift(register), cases, labels);
        }

        @Override
        public DexDebugVisitor visitDebug() {
            return new DexDebugVisitor(super.visitDebug()) {
                @Override
                public void visitStartLocal(int register, DexLabel label, String name, String type, String signature) {
                    super.visitStartLocal(shift(register), label, name, type, signature);
                }

                @Override
                public void visitEndLocal(int register, DexLabel label) {
                    super.visitEndLocal(shift(register), label);
                }

                @Override
                public void visitRestartLocal(int register, DexLabel label) {
                    super.visitRestartLocal(shift(register), label);
                }
            };
        }
    }

    private static Object getDefaultValueOfType(char t) {
        switch (t) {
        case 'B':
            return (byte) 0;
        case 'Z':
            return Boolean.FALSE;
        case 'S':
            return (short) 0;
        case 'C':
            return (char) 0;
        case 'I':
            return 0;
        case 'F':
            return (float) 0.0;
        case 'J':
            return 0L;
        case 'D':
            return 0.0;
        case '[':
        case 'L':
        default:
            return null;
        // impossible
        }
    }

    static boolean isPrimitiveZero(String desc, Object value) {
        if (value != null && desc != null && !desc.isEmpty()) {
            switch (desc.charAt(0)) {
            // case 'V':// VOID_TYPE
            case 'Z':// BOOLEAN_TYPE
                return !((Boolean) value);
            case 'C':// CHAR_TYPE
                return (Character) value == (char) 0;
            case 'B':// BYTE_TYPE
                return (Byte) value == 0;
            case 'S':// SHORT_TYPE
                return (Short) value == 0;
            case 'I':// INT_TYPE
                return (Integer) value == 0;
            case 'F':// FLOAT_TYPE
                return (Float) value == 0f;
            case 'J':// LONG_TYPE
                return (Long) value == 0L;
            case 'D':// DOUBLE_TYPE
                return (Double) value == 0.0;
            default:
                break;
            }
        }
        return false;
    }

}
