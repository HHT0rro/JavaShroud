package io.github.hht0rro.javashroud.apk

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassWriter
import org.objectweb.asm.Opcodes
import org.objectweb.asm.tree.ClassNode
import org.objectweb.asm.tree.FieldInsnNode
import org.objectweb.asm.tree.FieldNode
import org.objectweb.asm.tree.MethodInsnNode
import org.objectweb.asm.tree.MethodNode

/**
 * Widens package-private member access across the rename boundary.
 *
 * R8-produced dex code freely relies on same-package access between classes:
 * the caller and the callee originally share a package, and package-private
 * members are legal there. The rename passes move wholesale packages, but a
 * KEPT class (manifest component, JNI declarer, resource/native-referenced)
 * stays behind in its original package while its package-mates move away —
 * and vice versa. Every such cross-boundary reference then fails at runtime:
 *   - kept caller -> moved callee:  IllegalAccessError at the call site, or an
 *     ART verifier hard reject ("cannot access ... member") on class load;
 *   - moved caller -> kept callee: same failure from the other side.
 *
 * The widening is deliberately access-only (names, descriptors and bodies are
 * untouched), and only package-private members are widened: making a private
 * member public could accidentally turn it into a virtual override of an
 * unrelated same-signature superclass method, changing dispatch semantics.
 * Widening never breaks override or dispatch relations and keeps the
 * synthesized keep plan (class + member name retention) intact.
 *
 * Java serialization hooks (`readObject`/`writeObject`/`writeReplace`/...)
 * must retain their declared access for the JVM serialization machinery to
 * accept them, so they are excluded from widening. `serialVersionUID` and
 * `CREATOR` keep their declared access (they are already externally reachable
 * by contract).
 */
internal object ApkAccessWidening {

    data class WideningOutcome(
        val classes: List<Pair<String, ByteArray>>,
        val widenedMembers: Int,
        val widenedClasses: Int,
    )

    /** Exact signatures (name:descriptor) that must never be widened. */
    private val SERIALIZATION_HOOK_SIGNATURES: Set<String> = ApkKeepRuleSynthesis.SERIALIZATION_HOOKS

    /** Member identity inside one owner: (kind, name, descriptor). */
    private data class MemberRef(val isMethod: Boolean, val name: String, val descriptor: String)

    fun widen(
        mergedClasses: List<Pair<String, ByteArray>>,
        keptClassNames: Set<String>,
        log: (String) -> Unit = {},
    ): WideningOutcome {
        if (keptClassNames.isEmpty()) {
            return WideningOutcome(mergedClasses, 0, 0)
        }
        val bytesByClass = buildMap {
            for ((entryName, bytes) in mergedClasses) put(internalNameOf(entryName), bytes)
        }
        // (a) blanket: every non-public, non-protected instance-reachable
        // method of a KEPT class becomes public — moved-away callers keep
        // their originally same-package rights against it.
        val widenTargets = mutableMapOf<String, MutableSet<MemberRef>>()
        fun addTarget(owner: String, ref: MemberRef) {
            widenTargets.getOrPut(owner) { mutableSetOf() } += ref
        }
        for (owner in keptClassNames) {
            val bytes = bytesByClass[owner] ?: continue
            val node = parseNode(bytes) ?: continue
            for (method in node.methods.orEmpty()) {
                if (method.name == "<clinit>") continue
                if (isSerializationHook(method.name, method.desc)) continue
                if (needsWidening(method.access)) addTarget(owner, MemberRef(isMethod = true, name = method.name, descriptor = method.desc))
            }
        }
        // (b) ref scan: every member a KEPT class references on a non-kept
        // owner was same-package-accessible in the input; after the owner
        // moves, the reference must stay legal, so that member is widened on
        // the (renamed) owner instead.
        for (owner in keptClassNames) {
            val bytes = bytesByClass[owner] ?: continue
            val node = parseNode(bytes) ?: continue
            for (method in node.methods.orEmpty()) {
                val instructions = method.instructions ?: continue
                for (instruction in instructions) {
                    when (instruction) {
                        is MethodInsnNode -> {
                            if (instruction.owner == owner || instruction.owner !in bytesByClass) continue
                            if (instruction.owner in keptClassNames) continue
                            if (isSerializationHook(instruction.name, instruction.desc)) continue
                            addTarget(instruction.owner, MemberRef(isMethod = true, name = instruction.name, descriptor = instruction.desc))
                        }
                        is FieldInsnNode -> {
                            if (instruction.owner == owner || instruction.owner !in bytesByClass) continue
                            if (instruction.owner in keptClassNames) continue
                            if (instruction.name == "serialVersionUID" || instruction.name == "CREATOR") continue
                            addTarget(instruction.owner, MemberRef(isMethod = false, name = instruction.name, descriptor = instruction.desc))
                        }
                    }
                }
            }
        }
        // (c) class-level widening: package-private classes participate in the
        // same same-package contract as their members. A kept class touching a
        // renamed (moved) package-private class — or renamed code touching a
        // kept package-private class — fails with "Illegal class access"
        // before any member check. Widening every package-private class to
        // public (what R8's -allowaccessmodification emits) closes both
        // directions; visibility is not part of the keep contract.
        var widenedClassesCount = 0
        val classWidenSet = buildSet {
            for ((entryName, bytes) in mergedClasses) {
                val node = parseNode(bytes) ?: continue
                val access = node.access
                if (access and (Opcodes.ACC_PUBLIC or Opcodes.ACC_PROTECTED or Opcodes.ACC_PRIVATE) == 0) {
                    add(internalNameOf(entryName))
                }
            }
        }
        if (widenTargets.isEmpty() && classWidenSet.isEmpty()) {
            return WideningOutcome(mergedClasses, 0, 0)
        }
        // Only widen members that actually exist with non-public access.
        var widenedMembers = 0
        var widenedClasses = 0
        val classes = mergedClasses.map { (entryName, bytes) ->
            val internalName = internalNameOf(entryName)
            val targets = widenTargets[internalName]
            val classNeedsWidening = internalName in classWidenSet
            if (targets == null && !classNeedsWidening) return@map entryName to bytes
            var working = bytes
            var widenedInClass = 0
            if (targets != null) {
                val result = widenClassMembers(working, internalName, targets)
                if (result != null) {
                    working = result.first
                    widenedInClass = result.second
                }
            }
            if (classNeedsWidening) {
                widenClassAccess(working)?.let { working = it }
            }
            if (working === bytes) return@map entryName to bytes
            widenedClasses += 1
            widenedMembers += widenedInClass
            entryName to working
        }
        if (widenedMembers > 0 || widenedClasses > 0) {
            log(
                "access widening: $widenedMembers member(s) plus package-private classes across " +
                    "$widenedClasses class(es) widened to public for the rename boundary",
            )
        }
        return WideningOutcome(classes, widenedMembers, widenedClasses)
    }

    /** ACC_PUBLIC set on a package-private class; null when unchanged. */
    private fun widenClassAccess(classBytes: ByteArray): ByteArray? {
        return try {
            val node = ClassNode()
            ClassReader(classBytes).accept(node, 0)
            if (node.access and Opcodes.ACC_PUBLIC != 0) return null
            node.access = node.access or Opcodes.ACC_PUBLIC
            val writer = ClassWriter(0)
            node.accept(writer)
            writer.toByteArray()
        } catch (_: Exception) {
            null
        }
    }

    /** ACC_PUBLIC set on the matching members; null (and the count) when nothing changed. */
    private fun widenClassMembers(classBytes: ByteArray, internalName: String, targets: Set<MemberRef>): Pair<ByteArray, Int>? {
        return try {
            val node = ClassNode()
            ClassReader(classBytes).accept(node, 0)
            var changed = 0
            val className = node.name.ifBlank { internalName }
            for (method in node.methods.orEmpty()) {
                if (needsWidening(method.access) && MemberRef(true, method.name, method.desc) in targets) {
                    method.access = method.access or Opcodes.ACC_PUBLIC
                    changed += 1
                }
            }
            for (field in node.fields.orEmpty()) {
                if (needsWidening(field.access) && MemberRef(false, field.name, field.desc) in targets) {
                    field.access = field.access or Opcodes.ACC_PUBLIC
                    changed += 1
                }
            }
            if (changed == 0 || className != internalName) return null
            val writer = ClassWriter(0)
            node.accept(writer)
            writer.toByteArray() to changed
        } catch (_: Exception) {
            null
        }
    }

    private fun needsWidening(access: Int): Boolean =
        access and (Opcodes.ACC_PUBLIC or Opcodes.ACC_PROTECTED or Opcodes.ACC_PRIVATE) == 0

    private fun isSerializationHook(name: String, descriptor: String): Boolean =
        "$name:$descriptor" in SERIALIZATION_HOOK_SIGNATURES

    private fun parseNode(bytes: ByteArray): ClassNode? = try {
        val node = ClassNode()
        ClassReader(bytes).accept(node, ClassReader.SKIP_DEBUG or ClassReader.SKIP_FRAMES)
        node
    } catch (_: Exception) {
        null
    }

    private fun internalNameOf(entryName: String): String = entryName.removeSuffix(".class")
}
