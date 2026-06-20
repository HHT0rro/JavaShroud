package io.github.hht0rro.javashroud.model.analysis

import io.github.hht0rro.javashroud.model.config.RuleSpec

data class TargetSelector(
    val classPattern: String,
    val memberPattern: String?,
    val memberDescriptorPattern: String?,
)

data class RuleMatch(
    val rule: RuleSpec,
    val selector: TargetSelector,
    val matchedClassNames: List<String>,
    val matchedMembers: List<MatchedMember>,
)
