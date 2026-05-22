"""Baseline mitigation mode for ASRH.

``none`` is the control condition. It applies no additional prompt guard or
policy hardening beyond the base sandbox policy derived from the YAML case.
"""

from __future__ import annotations

from typing import Final

from asrh.mitigations.base import BaseMitigationStrategy, MITIGATION_NONE


class NoMitigationStrategy(BaseMitigationStrategy):
    """No-op baseline strategy."""

    name: str = MITIGATION_NONE
    description: str = "Baseline mode with no extra mitigation beyond case-defined sandbox policy."
    prompt_guard: bool = False
    code_enforced: bool = False
    taint_tracking: bool = False
    human_approval: bool = False
    final_output_scan: bool = False


NoMitigation = NoMitigationStrategy
NONE_MITIGATION: Final[NoMitigationStrategy] = NoMitigationStrategy()

__all__: Final[tuple[str, ...]] = (
    "NONE_MITIGATION",
    "NoMitigation",
    "NoMitigationStrategy",
)
