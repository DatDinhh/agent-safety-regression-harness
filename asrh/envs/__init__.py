"""Synthetic environment package for ASRH.

``asrh.envs`` owns the deterministic in-memory testbench used by runner and
tool modules:

- file system state with trust labels;
- synthetic inbox/outbox state;
- labeled memory values;
- code-enforced policy decisions;
- sandbox event and tool-call traces.

The package initializer is intentionally lightweight. It imports only data
structures and helper functions, not model providers or CLI applications.
"""

from __future__ import annotations

from typing import Final

from asrh.envs.email_box import (
    DEFAULT_INBOX_ID_PREFIX,
    EmailBox,
    EmailBoxError,
    EmailNotFound,
    EmailObject,
    SentEmailRecord,
)
from asrh.envs.file_system import (
    DEFAULT_WRITTEN_FILE_TRUST_LEVEL,
    FileAlreadyExists,
    FileNotFound,
    FileObject,
    FileSystem,
    FileSystemError,
    FileSystemSnapshot,
    FileWriteResult,
    UnsafeFilePath,
)
from asrh.envs.memory_store import (
    DEFAULT_MEMORY_TRUST_LEVEL,
    MEMORY_KEY_PATTERN,
    SENSITIVE_MEMORY_KEYWORDS,
    MemoryItem,
    MemoryKeyNotFound,
    MemoryStore,
    MemoryStoreError,
    UnsafeMemoryKey,
    infer_trust_level,
    validate_memory_key,
)
from asrh.envs.policy import (
    EMAIL_TOOL_NAME,
    EXECUTABLE_SUFFIXES,
    HIGH_RISK_TOOL_NAMES,
    LIST_FILES_TOOL_NAME,
    NETWORK_TOOL_NAME,
    READ_FILE_TOOL_NAME,
    SHELL_TOOL_NAME,
    SENSITIVE_TRUST_LEVEL,
    UNTRUSTED_TRUST_LEVEL,
    WRITE_FILE_TOOL_NAME,
    Policy,
    PolicyConfigurationError,
    PolicyError,
    PolicyOutcome,
    ToolPolicyDecision,
    env_flag,
    extract_forbidden_patterns,
)
from asrh.envs.sandbox import (
    DEFAULT_TOOL_OUTPUT_CONTENT_TYPE,
    SANDBOX_EVENT_CREATED,
    SANDBOX_EVENT_ERROR,
    SANDBOX_EVENT_POLICY_BLOCK,
    SANDBOX_EVENT_TOOL_CALL,
    Event,
    SandboxBuildError,
    SandboxEnv,
    SandboxError,
    SandboxToolResult,
    ToolCallRecord,
    ToolExecutionError,
    build_sandbox_from_case,
)

ENV_PACKAGE_NAME: Final[str] = "asrh.envs"
"""Import path for the ASRH synthetic environment package."""

ENV_SANDBOX_MODULE: Final[str] = "asrh.envs.sandbox"
"""Import path for sandbox environment construction and dispatch."""

ENV_POLICY_MODULE: Final[str] = "asrh.envs.policy"
"""Import path for policy primitives."""

ENV_FILE_SYSTEM_MODULE: Final[str] = "asrh.envs.file_system"
"""Import path for synthetic file state."""

ENV_EMAIL_BOX_MODULE: Final[str] = "asrh.envs.email_box"
"""Import path for synthetic email state."""

ENV_MEMORY_STORE_MODULE: Final[str] = "asrh.envs.memory_store"
"""Import path for synthetic memory state."""

__all__: Final[tuple[str, ...]] = (
    "DEFAULT_INBOX_ID_PREFIX",
    "DEFAULT_MEMORY_TRUST_LEVEL",
    "DEFAULT_TOOL_OUTPUT_CONTENT_TYPE",
    "DEFAULT_WRITTEN_FILE_TRUST_LEVEL",
    "EMAIL_TOOL_NAME",
    "ENV_EMAIL_BOX_MODULE",
    "ENV_FILE_SYSTEM_MODULE",
    "ENV_MEMORY_STORE_MODULE",
    "ENV_PACKAGE_NAME",
    "ENV_POLICY_MODULE",
    "ENV_SANDBOX_MODULE",
    "EXECUTABLE_SUFFIXES",
    "EmailBox",
    "EmailBoxError",
    "EmailNotFound",
    "EmailObject",
    "Event",
    "FileAlreadyExists",
    "FileNotFound",
    "FileObject",
    "FileSystem",
    "FileSystemError",
    "FileSystemSnapshot",
    "FileWriteResult",
    "HIGH_RISK_TOOL_NAMES",
    "LIST_FILES_TOOL_NAME",
    "MEMORY_KEY_PATTERN",
    "MemoryItem",
    "MemoryKeyNotFound",
    "MemoryStore",
    "MemoryStoreError",
    "NETWORK_TOOL_NAME",
    "Policy",
    "PolicyConfigurationError",
    "PolicyError",
    "PolicyOutcome",
    "READ_FILE_TOOL_NAME",
    "SANDBOX_EVENT_CREATED",
    "SANDBOX_EVENT_ERROR",
    "SANDBOX_EVENT_POLICY_BLOCK",
    "SANDBOX_EVENT_TOOL_CALL",
    "SENSITIVE_MEMORY_KEYWORDS",
    "SENSITIVE_TRUST_LEVEL",
    "SHELL_TOOL_NAME",
    "SandboxBuildError",
    "SandboxEnv",
    "SandboxError",
    "SandboxToolResult",
    "SentEmailRecord",
    "ToolCallRecord",
    "ToolExecutionError",
    "ToolPolicyDecision",
    "UNTRUSTED_TRUST_LEVEL",
    "UnsafeFilePath",
    "UnsafeMemoryKey",
    "WRITE_FILE_TOOL_NAME",
    "build_sandbox_from_case",
    "env_flag",
    "extract_forbidden_patterns",
    "infer_trust_level",
    "validate_memory_key",
)
