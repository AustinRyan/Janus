from __future__ import annotations

import fnmatch
from dataclasses import dataclass

from janus.identity.agent import AgentIdentity


@dataclass
class ChallengeResult:
    """Outcome of an identity challenge for a specific tool invocation.

    Attributes:
        passed: Whether the challenge was successful.
        confidence: Confidence score between 0.0 and 1.0.
        reasoning: Human-readable explanation of the decision.
    """

    passed: bool
    confidence: float
    reasoning: str


class IdentityChallenger:
    """Rule-based identity challenge gate.

    Validates whether an agent is permitted to invoke a given tool based on
    its declared permission patterns.  A future version will delegate to the
    LLM classifier for richer context-aware checks.
    """

    def challenge(self, agent: AgentIdentity, tool_name: str) -> ChallengeResult:
        """Synchronously evaluate whether *agent* may call *tool_name*.

        Iterates through the agent's permissions.  If any allowed pattern
        matches via ``fnmatch``, the challenge passes.  If a matching pattern
        exists but ``allowed`` is False, the challenge explicitly fails.
        Otherwise, no match means implicit denial.
        """
        for perm in agent.permissions:
            if fnmatch.fnmatch(tool_name, perm.tool_pattern):
                if perm.allowed:
                    return ChallengeResult(
                        passed=True,
                        confidence=1.0,
                        reasoning=(
                            f"Tool '{tool_name}' matches allowed pattern "
                            f"'{perm.tool_pattern}'."
                        ),
                    )
                else:
                    return ChallengeResult(
                        passed=False,
                        confidence=1.0,
                        reasoning=(
                            f"Tool '{tool_name}' matches explicitly denied "
                            f"pattern '{perm.tool_pattern}'."
                        ),
                    )

        return ChallengeResult(
            passed=False,
            confidence=0.9,
            reasoning=(
                f"Tool '{tool_name}' does not match any permission pattern "
                f"for agent '{agent.agent_id}'."
            ),
        )
