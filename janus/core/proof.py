"""Cryptographic proof chain for tamper-evident audit trails.

Each security verdict produces a ProofNode linked to the previous
via SHA-256 hashes, forming a Merkle chain.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any


@dataclass
class ProofNode:
    node_id: str
    parent_hash: str
    step: int
    timestamp: str
    session_id: str
    agent_id: str
    tool_name: str
    tool_input: dict[str, Any]
    verdict: str
    risk_score: float
    risk_delta: float
    content_hash: str


def _compute_content_hash(
    tool_name: str,
    tool_input: dict[str, Any],
    verdict: str,
    risk_score: float,
    risk_delta: float,
) -> str:
    """Hash the core verdict content."""
    payload = json.dumps(
        {
            "tool_name": tool_name,
            "tool_input": tool_input,
            "verdict": verdict,
            "risk_score": risk_score,
            "risk_delta": risk_delta,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _compute_node_id(
    content_hash: str,
    parent_hash: str,
    step: int,
    timestamp: str,
    session_id: str,
    agent_id: str,
) -> str:
    """Hash everything to produce the node ID."""
    payload = json.dumps(
        {
            "content_hash": content_hash,
            "parent_hash": parent_hash,
            "step": step,
            "timestamp": timestamp,
            "session_id": session_id,
            "agent_id": agent_id,
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class ProofChain:
    """Per-session chain of cryptographically linked proof nodes."""

    def __init__(self) -> None:
        self._chains: dict[str, list[ProofNode]] = {}

    def add(
        self,
        session_id: str,
        agent_id: str,
        tool_name: str,
        tool_input: dict[str, Any],
        verdict: str,
        risk_score: float,
        risk_delta: float,
    ) -> ProofNode:
        """Append a new node to the session's proof chain."""
        if session_id not in self._chains:
            self._chains[session_id] = []

        chain = self._chains[session_id]
        parent_hash = chain[-1].node_id if chain else ""
        step = len(chain) + 1
        timestamp = datetime.now(UTC).isoformat()

        content_hash = _compute_content_hash(
            tool_name, tool_input, verdict,
            risk_score, risk_delta,
        )
        node_id = _compute_node_id(
            content_hash, parent_hash, step,
            timestamp, session_id, agent_id,
        )

        node = ProofNode(
            node_id=node_id,
            parent_hash=parent_hash,
            step=step,
            timestamp=timestamp,
            session_id=session_id,
            agent_id=agent_id,
            tool_name=tool_name,
            tool_input=tool_input,
            verdict=verdict,
            risk_score=risk_score,
            risk_delta=risk_delta,
            content_hash=content_hash,
        )
        chain.append(node)
        return node

    def get_chain(self, session_id: str) -> list[ProofNode]:
        return self._chains.get(session_id, [])

    def verify(self, session_id: str) -> bool:
        """Walk the chain and verify all hashes."""
        chain = self.get_chain(session_id)
        if not chain:
            return True

        for i, node in enumerate(chain):
            expected_parent = (
                chain[i - 1].node_id if i > 0 else ""
            )
            if node.parent_hash != expected_parent:
                return False

            expected_content = _compute_content_hash(
                node.tool_name, node.tool_input,
                node.verdict, node.risk_score,
                node.risk_delta,
            )
            if node.content_hash != expected_content:
                return False

            expected_id = _compute_node_id(
                node.content_hash, node.parent_hash,
                node.step, node.timestamp,
                node.session_id, node.agent_id,
            )
            if node.node_id != expected_id:
                return False

        return True

    def export(self, session_id: str) -> str:
        """Export chain as JSON."""
        chain = self.get_chain(session_id)
        return json.dumps(
            [
                {
                    "node_id": n.node_id,
                    "parent_hash": n.parent_hash,
                    "step": n.step,
                    "timestamp": n.timestamp,
                    "session_id": n.session_id,
                    "agent_id": n.agent_id,
                    "tool_name": n.tool_name,
                    "tool_input": n.tool_input,
                    "verdict": n.verdict,
                    "risk_score": n.risk_score,
                    "risk_delta": n.risk_delta,
                    "content_hash": n.content_hash,
                }
                for n in chain
            ],
            indent=2,
        )
