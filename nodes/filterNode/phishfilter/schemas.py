"""Data contracts of the Filter component.

Plain dataclasses (no external dependency) so the Filter can be built and
tested without the Parser. When Daniel's Parser is ready, add a small adapter
that builds a ParsedEmail from his output.
"""
from dataclasses import dataclass, field
from typing import Literal

# Exactly two outcomes. There is no "legitimate" and no "soft" result.
Decision = Literal["phishing", "not_detected"]


@dataclass
class ParsedEmail:
    """The only field the Filter needs from the Parser."""
    # The domain the email was sent from, lowercase (e.g. "evil.com")
    sender_domain: str = ""


@dataclass
class FilterResult:
    """Verbal result, same spirit as the agents' output (no numeric scores)."""
    decision: Decision
    findings: list[str] = field(default_factory=list)     # what was found
    sources: list[str] = field(default_factory=list)      # which lists matched
    checked: list[str] = field(default_factory=list)      # what was checked
    limitations: list[str] = field(default_factory=list)  # what is not covered
