from __future__ import annotations

import pytest

from janus.sandbox.inspector import ResultInspector
from janus.sandbox.mock_env import MockEnvironment, SimulationResult
from janus.sandbox.policy import SandboxPolicy
from tests.conftest import make_request


@pytest.fixture
def policy() -> SandboxPolicy:
    return SandboxPolicy()


@pytest.fixture
def mock_env(policy: SandboxPolicy) -> MockEnvironment:
    return MockEnvironment(policy)


@pytest.fixture
def inspector() -> ResultInspector:
    return ResultInspector()


def test_policy_always_sandbox(policy: SandboxPolicy) -> None:
    assert policy.requires_sandbox("execute_code") is True
    assert policy.requires_sandbox("financial_transfer") is True
    assert policy.requires_sandbox("delete_file") is True


def test_policy_never_sandbox(policy: SandboxPolicy) -> None:
    assert policy.requires_sandbox("read_file") is False
    assert policy.requires_sandbox("list_files") is False
    assert policy.requires_sandbox("search_web") is False


def test_policy_unknown_tool(policy: SandboxPolicy) -> None:
    assert policy.requires_sandbox("some_custom_tool") is False


async def test_simulation_produces_result(mock_env: MockEnvironment) -> None:
    request = make_request(tool_name="execute_code", tool_input={"code": "print('hello')"})
    result = await mock_env.simulate(request)

    assert isinstance(result, SimulationResult)
    assert result.tool_name == "execute_code"
    assert isinstance(result.simulated_output, dict)
    assert result.execution_time_ms >= 0


async def test_inspector_flags_sensitive_data(inspector: ResultInspector) -> None:
    result = SimulationResult(
        tool_name="execute_code",
        simulated_output={"stdout": "Found api_key=sk-1234567890abcdef"},
        execution_time_ms=10.0,
    )
    request = make_request(tool_name="execute_code")
    verdict = await inspector.inspect(result, request)

    assert verdict.safe is False
    assert "sensitive" in verdict.finding.lower() or "api_key" in verdict.finding.lower()


async def test_inspector_passes_clean_output(inspector: ResultInspector) -> None:
    result = SimulationResult(
        tool_name="read_file",
        simulated_output={"content": "This is a normal document with no sensitive data."},
        execution_time_ms=5.0,
    )
    request = make_request(tool_name="read_file")
    verdict = await inspector.inspect(result, request)

    assert verdict.safe is True
