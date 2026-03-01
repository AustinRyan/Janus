"""REST API routes for tool registration and management."""
from __future__ import annotations

from typing import Any

import structlog
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from janus.tools.models import RegisteredTool

logger = structlog.get_logger()

router = APIRouter(prefix="/api/tools", tags=["tools"])


# ── Request/Response schemas ───────────────────────────────────────────


class ToolRegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: str = ""
    type: str = Field(default="webhook", pattern="^(webhook|mcp)$")
    endpoint: str = ""
    method: str = "POST"
    auth_type: str = Field(default="none", pattern="^(none|bearer|api_key|hmac)$")
    auth_credential: str = ""
    input_schema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    mcp_server_name: str = ""


class ToolUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    type: str | None = Field(default=None, pattern="^(webhook|mcp)$")
    endpoint: str | None = None
    method: str | None = None
    auth_type: str | None = Field(default=None, pattern="^(none|bearer|api_key|hmac)$")
    auth_credential: str | None = None
    input_schema: dict[str, Any] | None = None
    timeout_seconds: float | None = Field(default=None, ge=1.0, le=300.0)
    mcp_server_name: str | None = None
    is_active: bool | None = None


class ToolOut(BaseModel):
    id: str
    name: str
    description: str
    type: str
    endpoint: str
    method: str
    auth_type: str
    input_schema: dict[str, Any]
    timeout_seconds: float
    mcp_server_name: str
    is_active: bool
    created_at: str
    updated_at: str


class ToolTestRequest(BaseModel):
    input: dict[str, Any] = Field(default_factory=dict)


class ToolTestResponse(BaseModel):
    success: bool
    result: dict[str, Any]
    tool_name: str


def _tool_out(t: RegisteredTool) -> ToolOut:
    return ToolOut(
        id=t.id,
        name=t.name,
        description=t.description,
        type=t.type,
        endpoint=t.endpoint,
        method=t.method,
        auth_type=t.auth_type,
        input_schema=t.input_schema,
        timeout_seconds=t.timeout_seconds,
        mcp_server_name=t.mcp_server_name,
        is_active=t.is_active,
        created_at=t.created_at,
        updated_at=t.updated_at,
    )


# ── Endpoints ──────────────────────────────────────────────────────────


@router.get("", response_model=list[ToolOut])
async def list_tools(active_only: bool = True) -> list[ToolOut]:
    from janus.web.app import state

    assert state.tool_registry is not None
    tools = await state.tool_registry.list_tools(active_only=active_only)
    return [_tool_out(t) for t in tools]


@router.post("", response_model=ToolOut, status_code=201)
async def register_tool(req: ToolRegisterRequest) -> ToolOut:
    from janus.web.app import state

    assert state.tool_registry is not None

    # Validate webhook tools have an endpoint
    if req.type == "webhook" and not req.endpoint:
        raise HTTPException(status_code=400, detail="Webhook tools require an endpoint URL")
    if req.type == "mcp" and not req.mcp_server_name:
        raise HTTPException(status_code=400, detail="MCP tools require a server name")

    try:
        tool = await state.tool_registry.register(
            name=req.name,
            description=req.description,
            type=req.type,
            endpoint=req.endpoint,
            method=req.method,
            auth_type=req.auth_type,
            auth_credential=req.auth_credential,
            input_schema=req.input_schema,
            timeout_seconds=req.timeout_seconds,
            mcp_server_name=req.mcp_server_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    # Refresh the executor's tool cache
    if state.tool_executor is not None:
        await state.tool_executor.refresh_definitions()

    return _tool_out(tool)


@router.get("/{tool_id}", response_model=ToolOut)
async def get_tool(tool_id: str) -> ToolOut:
    from janus.web.app import state

    assert state.tool_registry is not None
    tool = await state.tool_registry.get_by_id(tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")
    return _tool_out(tool)


@router.put("/{tool_id}", response_model=ToolOut)
async def update_tool(tool_id: str, req: ToolUpdateRequest) -> ToolOut:
    from janus.web.app import state

    assert state.tool_registry is not None
    fields = req.model_dump(exclude_none=True)
    tool = await state.tool_registry.update(tool_id, **fields)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")

    # Refresh cache
    if state.tool_executor is not None:
        await state.tool_executor.refresh_definitions()

    return _tool_out(tool)


@router.delete("/{tool_id}", status_code=204)
async def delete_tool(tool_id: str) -> None:
    from janus.web.app import state

    assert state.tool_registry is not None
    deleted = await state.tool_registry.delete(tool_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Tool not found")

    # Refresh cache
    if state.tool_executor is not None:
        await state.tool_executor.refresh_definitions()


@router.post("/{tool_id}/test", response_model=ToolTestResponse)
async def test_tool(tool_id: str, req: ToolTestRequest) -> ToolTestResponse:
    """Test-execute a registered tool with sample input."""
    from janus.web.app import state

    assert state.tool_registry is not None
    assert state.tool_executor is not None

    tool = await state.tool_registry.get_by_id(tool_id)
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool not found")

    result = await state.tool_executor.execute(tool.name, req.input)
    success = "error" not in result

    return ToolTestResponse(
        success=success,
        result=result,
        tool_name=tool.name,
    )
