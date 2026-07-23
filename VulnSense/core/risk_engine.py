from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List

from .scanner import Finding


@dataclass(frozen=True)
class BusinessContext:
    handles_customer_data: bool
    internet_facing: bool
    environment: str
    business_criticality: str


@dataclass(frozen=True)
class ScoredFinding:
    finding: Finding
    contextual_score: float
    risk_level: str
    justification: str


class RiskEngine:
    DATA_MULTIPLIERS = {True: 1.6, False: 1.0}
    EXPOSURE_MULTIPLIERS = {True: 1.4, False: 1.0}
    ENVIRONMENT_MULTIPLIERS = {"production": 1.5, "staging": 1.1, "development": 0.7}
    CRITICALITY_MULTIPLIERS = {"low": 0.8, "medium": 1.1, "high": 1.5}
    MAX_RAW_SCORE = 4 * 1.6 * 1.4 * 1.5 * 1.5

    def __init__(self, context: BusinessContext):
        self.context = context

    def score(self, findings: Iterable[Finding]) -> List[ScoredFinding]:
        scored: List[ScoredFinding] = []
        for finding in findings:
            contextual_score = self._calculate_contextual_score(finding.base_severity)
            risk_level = self._bucket_score(contextual_score)
            justification = self._build_justification(finding.base_severity, contextual_score, risk_level)
            scored.append(
                ScoredFinding(
                    finding=finding,
                    contextual_score=contextual_score,
                    risk_level=risk_level,
                    justification=justification,
                )
            )
        scored.sort(key=lambda item: (item.contextual_score, item.finding.base_severity), reverse=True)
        return scored

    def _calculate_contextual_score(self, base_severity: int) -> float:
        data_multiplier = self.DATA_MULTIPLIERS[self.context.handles_customer_data]
        exposure_multiplier = self.EXPOSURE_MULTIPLIERS[self.context.internet_facing]
        environment_multiplier = self.ENVIRONMENT_MULTIPLIERS.get(self.context.environment.lower(), 1.0)
        criticality_multiplier = self.CRITICALITY_MULTIPLIERS.get(self.context.business_criticality.lower(), 1.0)
        raw_score = base_severity * data_multiplier * exposure_multiplier * environment_multiplier * criticality_multiplier
        normalized = (raw_score / self.MAX_RAW_SCORE) * 10.0
        return round(max(0.0, min(10.0, normalized)), 1)

    def _bucket_score(self, contextual_score: float) -> str:
        if contextual_score >= 8.0:
            return "Critical"
        if contextual_score >= 6.0:
            return "High"
        if contextual_score >= 3.5:
            return "Medium"
        return "Low"

    def _build_justification(self, base_severity: int, contextual_score: float, risk_level: str) -> str:
        reasons = []
        if self.context.handles_customer_data:
            reasons.append("customer data handling increased the impact")
        else:
            reasons.append("no customer data handling reduced the impact")

        if self.context.internet_facing:
            reasons.append("internet exposure increased the likelihood of abuse")
        else:
            reasons.append("internal-only exposure reduced the likelihood of abuse")

        environment = self.context.environment.lower()
        if environment == "production":
            reasons.append("production deployment amplified business impact")
        elif environment == "staging":
            reasons.append("staging environment kept the score moderately elevated")
        else:
            reasons.append("development environment reduced business impact")

        criticality = self.context.business_criticality.lower()
        if criticality == "high":
            reasons.append("high business criticality made the finding more urgent")
        elif criticality == "medium":
            reasons.append("medium business criticality kept the score above baseline")
        else:
            reasons.append("low business criticality restrained the final score")

        return (
            f"A base severity of {base_severity} normalized to {contextual_score}/10 and bucketed as {risk_level}. "
            + " ".join(reasons)
        )
