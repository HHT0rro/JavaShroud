import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.ClassReader;

/**
 * Maps old CASE methods to a reference JAR by bytecode semantics rather than
 * method count or obfuscated names. The input target file is a UTF-8 TSV with
 * token, owner, name, descriptor columns and is normally derived from CASE
 * recovered/ir2 metadata.
 */
public final class CaseMethodIdentityMapper implements Opcodes {
    private static final String HEADER = String.join("\t",
            "token", "case_owner", "case_name", "case_descriptor", "case_source_file",
            "status", "match_tier", "candidate_count", "reference_owner", "reference_name",
            "reference_descriptor", "reference_source_file", "strict_fingerprint",
            "structural_fingerprint", "candidate_identities", "candidate_scores");

    private CaseMethodIdentityMapper() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.err.println("Usage: CaseMethodIdentityMapper <clean.jar> <reference.jar> <targets.tsv> <report.tsv>");
            System.exit(2);
        }
        Path cleanJar = Path.of(args[0]);
        Path referenceJar = Path.of(args[1]);
        Path targetsPath = Path.of(args[2]);
        Path reportPath = Path.of(args[3]);

        Map<String, MethodRecord> clean = loadMethods(cleanJar);
        List<MethodRecord> reference = new ArrayList<>(loadMethods(referenceJar).values());
        reference.sort(Comparator.comparing(MethodRecord::identity));
        List<Target> targets = loadTargets(targetsPath);
        Map<String, String> classMappings = inferClassMappings(clean.values(), reference);

        try (BufferedWriter writer = Files.newBufferedWriter(reportPath, StandardCharsets.UTF_8)) {
            writer.write(HEADER);
            writer.newLine();
            for (Target target : targets) {
                MethodRecord caseMethod = clean.get(target.identity());
                Mapping mapping = map(caseMethod, reference, classMappings);
                writeRow(writer, target, caseMethod, mapping);
            }
        }
    }

    private static List<Target> loadTargets(Path path) throws Exception {
        List<Target> targets = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            String line;
            int lineNumber = 0;
            while ((line = reader.readLine()) != null) {
                lineNumber++;
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }
                String[] columns = line.split("\\t", -1);
                if (columns.length != 4) {
                    throw new IllegalArgumentException("Expected four TSV columns at " + path + ":" + lineNumber);
                }
                targets.add(new Target(columns[0], columns[1], columns[2], columns[3]));
            }
        }
        return targets;
    }

    private static Map<String, MethodRecord> loadMethods(Path jarPath) throws Exception {
        Map<String, MethodRecord> methods = new LinkedHashMap<>();
        try (JarFile jar = new JarFile(jarPath.toFile())) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.isDirectory() || !entry.getName().endsWith(".class") || entry.getName().equals("module-info.class")) {
                    continue;
                }
                try (InputStream input = jar.getInputStream(entry)) {
                    ClassNode node = new ClassNode();
                    new ClassReader(input).accept(node, ClassReader.SKIP_FRAMES);
                    for (MethodNode method : node.methods) {
                        if (method.instructions == null || method.instructions.size() == 0) {
                            continue;
                        }
                        MethodRecord record = MethodRecord.of(node.name, node.sourceFile, method);
                        MethodRecord previous = methods.put(record.identity(), record);
                        if (previous != null) {
                            throw new IllegalStateException("Duplicate method identity: " + record.identity());
                        }
                    }
                }
            }
        }
        return methods;
    }

    private static Mapping map(MethodRecord caseMethod, List<MethodRecord> reference, Map<String, String> classMappings) {
        if (caseMethod == null) {
            return Mapping.missing();
        }
        String mappedOwner = classMappings.get(caseMethod.owner);
        List<MethodRecord> scope = mappedOwner == null ? reference : collect(reference, candidate -> mappedOwner.equals(candidate.owner));
        List<MethodRecord> strict = collect(scope, candidate -> candidate.strictFingerprint.equals(caseMethod.strictFingerprint));
        List<MethodRecord> sourceStrict = withSource(strict, caseMethod.sourceFile);
        if (sourceStrict.size() == 1) {
            return Mapping.matched("strict-source", sourceStrict, sourceStrict.get(0));
        }
        if (strict.size() == 1) {
            return Mapping.matched("strict", strict, strict.get(0));
        }

        List<MethodRecord> structural = collect(scope,
                candidate -> candidate.structuralFingerprint.equals(caseMethod.structuralFingerprint));
        List<MethodRecord> sourceStructural = withSource(structural, caseMethod.sourceFile);
        if (sourceStructural.size() == 1) {
            return Mapping.matched("structural-source", sourceStructural, sourceStructural.get(0));
        }
        if (structural.size() == 1) {
            return Mapping.matched("structural", structural, structural.get(0));
        }

        Mapping fuzzy = fuzzy(caseMethod, scope, mappedOwner != null);
        if (fuzzy != null && "matched".equals(fuzzy.status)) {
            return fuzzy;
        }
        List<MethodRecord> signature = collect(scope,
                candidate -> normalizeDescriptor(candidate.descriptor).equals(normalizeDescriptor(caseMethod.descriptor)));
        if (mappedOwner != null && signature.size() == 1) {
            return Mapping.matched("class-identity-signature", signature, signature.get(0));
        }
        if (fuzzy != null) {
            return fuzzy;
        }
        List<MethodRecord> candidates = !strict.isEmpty() ? strict : structural;
        return Mapping.ambiguous(candidates);
    }

    private static Map<String, String> inferClassMappings(Iterable<MethodRecord> clean, Iterable<MethodRecord> reference) {
        Map<String, Set<String>> cleanStrings = classStrings(clean);
        Map<String, Set<String>> referenceStrings = classStrings(reference);
        List<MethodRecord> referenceMethods = toList(reference);
        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, Set<String>> entry : cleanStrings.entrySet()) {
            String bestOwner = null;
            int bestScore = 0;
            int secondScore = 0;
            for (Map.Entry<String, Set<String>> candidate : referenceStrings.entrySet()) {
                int score = anchorScore(entry.getValue(), candidate.getValue());
                if (score > bestScore) {
                    secondScore = bestScore;
                    bestScore = score;
                    bestOwner = candidate.getKey();
                } else if (score > secondScore) {
                    secondScore = score;
                }
            }
            if (bestOwner != null && bestScore >= 12 && bestScore - secondScore >= 6) {
                result.put(entry.getKey(), bestOwner);
            }
        }
        Map<String, Map<String, Integer>> methodAnchors = new HashMap<>();
        for (MethodRecord method : clean) {
            if (result.containsKey(method.owner)) {
                continue;
            }
            Mapping mapping = fuzzy(method, referenceMethods, false);
            if (mapping == null || !"matched".equals(mapping.status)) {
                continue;
            }
            methodAnchors
                    .computeIfAbsent(method.owner, ignored -> new HashMap<>())
                    .merge(mapping.match.owner, 1, Integer::sum);
        }
        for (Map.Entry<String, Map<String, Integer>> entry : methodAnchors.entrySet()) {
            String owner = null;
            int best = 0;
            int second = 0;
            for (Map.Entry<String, Integer> candidate : entry.getValue().entrySet()) {
                if (candidate.getValue() > best) {
                    second = best;
                    best = candidate.getValue();
                    owner = candidate.getKey();
                } else if (candidate.getValue() > second) {
                    second = candidate.getValue();
                }
            }
            if (owner != null && best > second) {
                result.put(entry.getKey(), owner);
            }
        }
        return result;
    }

    private static List<MethodRecord> toList(Iterable<MethodRecord> methods) {
        List<MethodRecord> result = new ArrayList<>();
        for (MethodRecord method : methods) {
            result.add(method);
        }
        return result;
    }

    private static Map<String, Set<String>> classStrings(Iterable<MethodRecord> methods) {
        Map<String, Set<String>> result = new HashMap<>();
        for (MethodRecord method : methods) {
            result.computeIfAbsent(method.owner, ignored -> new HashSet<>()).addAll(method.stringConstants);
        }
        return result;
    }

    private static int anchorScore(Set<String> left, Set<String> right) {
        int score = 0;
        for (String value : left) {
            if (right.contains(value) && isUsefulAnchor(value)) {
                score += Math.min(32, value.length());
            }
        }
        return score;
    }

    private static boolean isUsefulAnchor(String value) {
        return value.length() >= 4 && !value.startsWith("vbc4-meta|") && !value.startsWith("a_px");
    }

    private static Mapping fuzzy(MethodRecord caseMethod, List<MethodRecord> scope, boolean classAnchored) {
        List<FuzzyCandidate> candidates = new ArrayList<>();
        for (MethodRecord candidate : scope) {
            if (!normalizeDescriptor(candidate.descriptor).equals(normalizeDescriptor(caseMethod.descriptor))) {
                continue;
            }
            Similarity similarity = similarity(caseMethod.features, candidate.features);
            if (similarity.referenceCoverage >= 0.35 && similarity.sharedStrongFeatures > 0) {
                candidates.add(new FuzzyCandidate(candidate, similarity.compositeScore(), similarity.referenceCoverage, similarity.targetCoverage));
            }
        }
        candidates.sort(Comparator.comparingDouble(FuzzyCandidate::score).reversed().thenComparing(candidate -> candidate.method.identity()));
        if (candidates.isEmpty()) {
            return null;
        }
        FuzzyCandidate best = candidates.get(0);
        double second = candidates.size() > 1 ? candidates.get(1).score : 0.0;
        double requiredCoverage = classAnchored ? 0.82 : 0.96;
        double requiredMargin = classAnchored ? 0.06 : 0.18;
        if (best.referenceCoverage >= requiredCoverage && (candidates.size() == 1 || best.score - second >= requiredMargin)) {
            return Mapping.matched(classAnchored ? "fuzzy-class-anchor" : "fuzzy-global", candidates.stream().map(FuzzyCandidate::method).toList(), best.method);
        }
        return Mapping.ambiguous(candidates.stream().map(FuzzyCandidate::method).toList());
    }

    private static Similarity similarity(Map<String, Integer> target, Map<String, Integer> reference) {
        double referenceTotal = 0.0;
        double targetTotal = 0.0;
        double shared = 0.0;
        int strong = 0;
        for (Map.Entry<String, Integer> entry : target.entrySet()) {
            targetTotal += featureWeight(entry.getKey()) * entry.getValue();
        }
        for (Map.Entry<String, Integer> entry : reference.entrySet()) {
            double weight = featureWeight(entry.getKey());
            int referenceCount = entry.getValue();
            int sharedCount = Math.min(referenceCount, target.getOrDefault(entry.getKey(), 0));
            referenceTotal += weight * referenceCount;
            shared += weight * sharedCount;
            if (sharedCount > 0 && isStrongFeature(entry.getKey())) {
                strong += sharedCount;
            }
        }
        double referenceCoverage = referenceTotal == 0.0 ? 0.0 : shared / referenceTotal;
        double targetCoverage = targetTotal == 0.0 ? 0.0 : shared / targetTotal;
        return new Similarity(referenceCoverage, targetCoverage, strong);
    }

    private static double featureWeight(String feature) {
        if (feature.startsWith("str:")) return 12.0;
        if (feature.startsWith("lib:")) return 5.0;
        if (feature.startsWith("num:")) return 3.0;
        if (feature.startsWith("app:")) return 2.0;
        if (feature.startsWith("type:")) return 2.0;
        if (feature.startsWith("desc:")) return 4.0;
        return 1.0;
    }

    private static boolean isStrongFeature(String feature) {
        return feature.startsWith("str:") || feature.startsWith("lib:") || feature.startsWith("num:") || feature.startsWith("app:") || feature.startsWith("type:");
    }

    private static List<MethodRecord> collect(List<MethodRecord> candidates, java.util.function.Predicate<MethodRecord> predicate) {
        List<MethodRecord> result = new ArrayList<>();
        for (MethodRecord candidate : candidates) {
            if (predicate.test(candidate)) {
                result.add(candidate);
            }
        }
        return result;
    }

    private static List<MethodRecord> withSource(List<MethodRecord> candidates, String sourceFile) {
        if (sourceFile == null || sourceFile.isEmpty()) {
            return List.of();
        }
        return collect(candidates, candidate -> sourceFile.equals(candidate.sourceFile));
    }

    private static void writeRow(BufferedWriter writer, Target target, MethodRecord caseMethod, Mapping mapping) throws Exception {
        List<String> columns = new ArrayList<>();
        columns.add(target.token);
        columns.add(target.owner);
        columns.add(target.name);
        columns.add(target.descriptor);
        columns.add(caseMethod == null ? "" : nullable(caseMethod.sourceFile));
        columns.add(mapping.status);
        columns.add(mapping.tier);
        columns.add(Integer.toString(mapping.candidates.size()));
        columns.add(mapping.match == null ? "" : mapping.match.owner);
        columns.add(mapping.match == null ? "" : mapping.match.name);
        columns.add(mapping.match == null ? "" : mapping.match.descriptor);
        columns.add(mapping.match == null ? "" : nullable(mapping.match.sourceFile));
        columns.add(caseMethod == null ? "" : caseMethod.strictFingerprint);
        columns.add(caseMethod == null ? "" : caseMethod.structuralFingerprint);
        columns.add(joinIdentities(mapping.candidates));
        columns.add(caseMethod == null ? "" : joinScores(caseMethod, mapping.candidates));
        writer.write(String.join("\t", columns.stream().map(CaseMethodIdentityMapper::tsv).toList()));
        writer.newLine();
    }

    private static String joinIdentities(List<MethodRecord> methods) {
        return methods.stream().map(MethodRecord::identity).sorted().reduce((left, right) -> left + "|" + right).orElse("");
    }

    private static String joinScores(MethodRecord caseMethod, List<MethodRecord> methods) {
        return methods.stream()
                .sorted(Comparator.comparing(MethodRecord::identity))
                .map(method -> {
                    Similarity similarity = similarity(caseMethod.features, method.features);
                    return method.identity() + "@ref=" + String.format(Locale.ROOT, "%.6f", similarity.referenceCoverage)
                            + ",target=" + String.format(Locale.ROOT, "%.6f", similarity.targetCoverage)
                            + ",score=" + String.format(Locale.ROOT, "%.6f", similarity.compositeScore());
                })
                .reduce((left, right) -> left + "|" + right)
                .orElse("");
    }

    private static String nullable(String value) {
        return value == null ? "" : value;
    }

    private static String tsv(String value) {
        return value.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n");
    }

    private record Target(String token, String owner, String name, String descriptor) {
        String identity() {
            return owner + "\\u0000" + name + "\\u0000" + descriptor;
        }
    }

    private record Mapping(String status, String tier, List<MethodRecord> candidates, MethodRecord match) {
        static Mapping missing() {
            return new Mapping("missing-case-method", "", List.of(), null);
        }

        static Mapping matched(String tier, List<MethodRecord> candidates, MethodRecord match) {
            return new Mapping("matched", tier, candidates, match);
        }

        static Mapping ambiguous(List<MethodRecord> candidates) {
            return new Mapping(candidates.isEmpty() ? "no-reference-match" : "ambiguous", "", candidates, null);
        }
    }

    private record FuzzyCandidate(MethodRecord method, double score, double referenceCoverage, double targetCoverage) {
    }

    private record Similarity(double referenceCoverage, double targetCoverage, int sharedStrongFeatures) {
        double compositeScore() {
            return referenceCoverage * 0.60 + targetCoverage * 0.40;
        }
    }

    private record MethodRecord(
            String owner,
            String name,
            String descriptor,
            String sourceFile,
            String strictFingerprint,
            String structuralFingerprint,
            Map<String, Integer> features,
            Set<String> stringConstants) {
        static MethodRecord of(String owner, String sourceFile, MethodNode method) throws Exception {
            return new MethodRecord(
                    owner,
                    method.name,
                    method.desc,
                    sourceFile,
                    digest(canonical(method, true)),
                    digest(canonical(method, false)),
                    CaseMethodIdentityMapper.features(method),
                    CaseMethodIdentityMapper.stringConstants(method));
        }

        String identity() {
            return owner + "\\u0000" + name + "\\u0000" + descriptor;
        }
    }

    private static Map<String, Integer> features(MethodNode method) {
        Map<String, Integer> result = new HashMap<>();
        addFeature(result, "desc:" + normalizeDescriptor(method.desc));
        for (AbstractInsnNode instruction = method.instructions.getFirst(); instruction != null; instruction = instruction.getNext()) {
            if (instruction instanceof LabelNode || instruction instanceof LineNumberNode || instruction instanceof FrameNode) {
                continue;
            }
            addFeature(result, "op:" + instruction.getOpcode());
            if (instruction instanceof LdcInsnNode node) {
                if (node.cst instanceof String text) {
                    addFeature(result, "str:" + digest(text));
                } else if (node.cst instanceof Number number) {
                    addFeature(result, "num:" + number);
                } else if (node.cst instanceof Type type) {
                    addFeature(result, "type:" + normalizeType(type));
                }
            } else if (instruction instanceof MethodInsnNode node) {
                addFeature(result, memberFeature(node.owner, node.name, node.desc));
            } else if (instruction instanceof FieldInsnNode node) {
                addFeature(result, memberFeature(node.owner, node.name, node.desc));
            } else if (instruction instanceof TypeInsnNode node) {
                addFeature(result, "type:" + normalizeInternal(node.desc));
            } else if (instruction instanceof IntInsnNode node) {
                addFeature(result, "num:" + node.operand);
            } else if (instruction instanceof IincInsnNode node) {
                addFeature(result, "num:" + node.incr);
            }
        }
        return Map.copyOf(result);
    }

    private static Set<String> stringConstants(MethodNode method) {
        Set<String> result = new HashSet<>();
        for (AbstractInsnNode instruction = method.instructions.getFirst(); instruction != null; instruction = instruction.getNext()) {
            if (instruction instanceof LdcInsnNode node && node.cst instanceof String text) {
                result.add(text);
            }
        }
        return Set.copyOf(result);
    }

    private static String memberFeature(String owner, String name, String descriptor) {
        return isLibrary(owner)
                ? "lib:" + owner + '.' + name + ':' + normalizeDescriptor(descriptor)
                : "app:" + normalizeDescriptor(descriptor);
    }

    private static void addFeature(Map<String, Integer> features, String feature) {
        features.merge(feature, 1, Integer::sum);
    }

    private static String canonical(MethodNode method, boolean includeOperands) {
        StringBuilder out = new StringBuilder();
        out.append("desc=").append(normalizeDescriptor(method.desc)).append('\n');
        IdentityHashMap<LabelNode, Integer> labels = new IdentityHashMap<>();
        int labelId = 0;
        for (AbstractInsnNode instruction = method.instructions.getFirst(); instruction != null; instruction = instruction.getNext()) {
            if (instruction instanceof LabelNode label) {
                labels.put(label, labelId++);
            }
        }
        for (AbstractInsnNode instruction = method.instructions.getFirst(); instruction != null; instruction = instruction.getNext()) {
            if (instruction instanceof LabelNode || instruction instanceof LineNumberNode || instruction instanceof FrameNode) {
                continue;
            }
            out.append(instruction.getOpcode());
            if (includeOperands) {
                appendOperand(out, instruction, labels);
            }
            out.append('\n');
        }
        if (includeOperands && method.tryCatchBlocks != null) {
            for (TryCatchBlockNode block : method.tryCatchBlocks) {
                out.append("try:")
                        .append(label(labels, block.start)).append(':')
                        .append(label(labels, block.end)).append(':')
                        .append(label(labels, block.handler)).append(':')
                        .append(normalizeInternal(block.type)).append('\n');
            }
        }
        return out.toString();
    }

    private static void appendOperand(StringBuilder out, AbstractInsnNode instruction, IdentityHashMap<LabelNode, Integer> labels) {
        if (instruction instanceof InsnNode) {
            return;
        }
        if (instruction instanceof IntInsnNode node) {
            out.append(":i=").append(node.operand);
        } else if (instruction instanceof VarInsnNode node) {
            out.append(":v=").append(node.var);
        } else if (instruction instanceof TypeInsnNode node) {
            out.append(":t=").append(normalizeInternal(node.desc));
        } else if (instruction instanceof FieldInsnNode node) {
            out.append(":f=").append(normalizeMember(node.owner, node.name, node.desc));
        } else if (instruction instanceof MethodInsnNode node) {
            out.append(":m=").append(normalizeMember(node.owner, node.name, node.desc));
        } else if (instruction instanceof InvokeDynamicInsnNode node) {
            out.append(":indy=").append(normalizeDescriptor(node.desc));
            out.append(":bsm=").append(normalizeHandle(node.bsm));
            for (Object argument : node.bsmArgs) {
                out.append(":arg=").append(normalizeConstant(argument));
            }
        } else if (instruction instanceof JumpInsnNode node) {
            out.append(":j=").append(label(labels, node.label));
        } else if (instruction instanceof LdcInsnNode node) {
            out.append(":ldc=").append(normalizeConstant(node.cst));
        } else if (instruction instanceof IincInsnNode node) {
            out.append(":inc=").append(node.var).append(':').append(node.incr);
        } else if (instruction instanceof TableSwitchInsnNode node) {
            out.append(":table=").append(node.min).append(':').append(node.max).append(':').append(label(labels, node.dflt));
            for (LabelNode label : node.labels) {
                out.append(':').append(label(labels, label));
            }
        } else if (instruction instanceof LookupSwitchInsnNode node) {
            out.append(":lookup=").append(label(labels, node.dflt));
            for (int index = 0; index < node.keys.size(); index++) {
                out.append(':').append(node.keys.get(index)).append('@').append(label(labels, node.labels.get(index)));
            }
        } else if (instruction instanceof MultiANewArrayInsnNode node) {
            out.append(":multi=").append(normalizeDescriptor(node.desc)).append(':').append(node.dims);
        } else {
            out.append(":kind=").append(instruction.getClass().getName());
        }
    }

    private static int label(IdentityHashMap<LabelNode, Integer> labels, LabelNode label) {
        Integer value = labels.get(label);
        if (value == null) {
            throw new IllegalStateException("Unregistered label");
        }
        return value;
    }

    private static String normalizeConstant(Object value) {
        if (value instanceof String text) {
            return "s:" + digest(text);
        }
        if (value instanceof Type type) {
            return "type:" + normalizeType(type);
        }
        if (value instanceof Handle handle) {
            return "handle:" + normalizeHandle(handle);
        }
        return value.getClass().getName() + ":" + value;
    }

    private static String normalizeHandle(Handle handle) {
        return handle.getTag() + ":" + normalizeMember(handle.getOwner(), handle.getName(), handle.getDesc());
    }

    private static String normalizeMember(String owner, String name, String descriptor) {
        if (isLibrary(owner)) {
            return owner + '.' + name + ':' + normalizeDescriptor(descriptor);
        }
        return "APP:" + normalizeDescriptor(descriptor);
    }

    private static String normalizeDescriptor(String descriptor) {
        if (descriptor.startsWith("(")) {
            StringBuilder out = new StringBuilder("(");
            for (Type argument : Type.getArgumentTypes(descriptor)) {
                out.append(normalizeType(argument));
            }
            return out.append(')').append(normalizeType(Type.getReturnType(descriptor))).toString();
        }
        return normalizeType(Type.getType(descriptor));
    }

    private static String normalizeType(Type type) {
        return switch (type.getSort()) {
            case Type.VOID, Type.BOOLEAN, Type.CHAR, Type.BYTE, Type.SHORT, Type.INT, Type.FLOAT, Type.LONG, Type.DOUBLE -> type.getDescriptor();
            case Type.ARRAY -> "[".repeat(type.getDimensions()) + normalizeType(type.getElementType());
            case Type.OBJECT -> 'L' + normalizeInternal(type.getInternalName()) + ';';
            case Type.METHOD -> normalizeDescriptor(type.getDescriptor());
            default -> throw new IllegalArgumentException("Unsupported type: " + type);
        };
    }

    private static String normalizeInternal(String internalName) {
        if (internalName == null) {
            return "-";
        }
        return isLibrary(internalName) ? internalName : "APP";
    }

    private static boolean isLibrary(String internalName) {
        return internalName.startsWith("java/") || internalName.startsWith("javax/") || internalName.startsWith("jdk/")
                || internalName.startsWith("sun/") || internalName.startsWith("com/sun/") || internalName.startsWith("org/w3c/")
                || internalName.startsWith("org/xml/") || internalName.startsWith("org/ietf/");
    }

    private static String digest(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(bytes.length * 2);
            for (byte valueByte : bytes) {
                result.append(Character.forDigit((valueByte >>> 4) & 0xF, 16));
                result.append(Character.forDigit(valueByte & 0xF, 16));
            }
            return result.toString();
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }
}
