"""Sandbox-backed tool package for ASRH.

The package exposes model-facing tool descriptors and registry helpers. Concrete
execution still goes through ``asrh.envs.SandboxEnv`` so policy checks and trace
records stay centralized.
"""

from __future__ import annotations

from typing import Final

from asrh.tools.base import *
from asrh.tools.email_tools import *
from asrh.tools.file_tools import *
from asrh.tools.network_tools import *
from asrh.tools.registry import *
from asrh.tools.shell_tools import *

TOOLS_PACKAGE_NAME: Final[str] = "asrh.tools"
TOOLS_BASE_MODULE: Final[str] = "asrh.tools.base"
TOOLS_REGISTRY_MODULE: Final[str] = "asrh.tools.registry"
TOOLS_FILE_MODULE: Final[str] = "asrh.tools.file_tools"
TOOLS_EMAIL_MODULE: Final[str] = "asrh.tools.email_tools"
TOOLS_SHELL_MODULE: Final[str] = "asrh.tools.shell_tools"
TOOLS_NETWORK_MODULE: Final[str] = "asrh.tools.network_tools"

__all__: Final[tuple[str, ...]] = tuple(
    name for name in globals() if not name.startswith("_") and name not in {"annotations", "Final"}
)
