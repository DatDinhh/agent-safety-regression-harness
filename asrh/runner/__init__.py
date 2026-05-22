"""Runtime execution layer for ASRH.

The runner package connects YAML case loading, mitigations, sandboxed tools,
agent execution, deterministic checkers, and JSONL trace persistence.  Importing
this package does not import provider SDKs or perform external side effects.
"""

from __future__ import annotations

from typing import Final

from asrh.runner.result import *  # noqa: F403
from asrh.runner.trace import *  # noqa: F403
from asrh.runner.run_case import *  # noqa: F403
from asrh.runner.run_suite import *  # noqa: F403

RUNNER_PACKAGE_NAME: Final[str] = "asrh.runner"
RUNNER_CASE_MODULE: Final[str] = "asrh.runner.run_case"
RUNNER_SUITE_MODULE: Final[str] = "asrh.runner.run_suite"
RUNNER_TRACE_MODULE: Final[str] = "asrh.runner.trace"
RUNNER_RESULT_MODULE: Final[str] = "asrh.runner.result"

__all__: Final[tuple[str, ...]] = tuple(
    name for name in globals() if not name.startswith("_") and name not in {"annotations", "Final"}
)
