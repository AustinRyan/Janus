from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SandboxPolicy:
    """Defines which tools require sandbox simulation before real execution."""

    always_sandbox: set[str] = field(default_factory=lambda: {
        "execute_code", "database_write", "delete_file",
        "modify_permissions", "send_email", "financial_transfer",
    })
    never_sandbox: set[str] = field(default_factory=lambda: {
        "read_file", "list_files", "search_web",
    })

    def requires_sandbox(self, tool_name: str) -> bool:
        if tool_name in self.never_sandbox:
            return False
        if tool_name in self.always_sandbox:
            return True
        return False
