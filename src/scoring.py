"""
scoring.py
- Computes a single risk score per vulnerability
- Buckets scores into clear risk levels
"""

from __future__ import annotations
import pandas as pd


def exposure_modifier(exposure: str) -> int:
    """
    External assets carry higher risk than internal ones.
    """
    exposure = str(exposure).lower().strip()
    if exposure == "external":
        return 5
    return 0


def calculate_risk_score(row: pd.Series) -> int:
    """
    Explainable risk scoring formula.

    Components:
    - Technical risk: severity_cvss × exploitability
    - Business impact: business_criticality × data_sensitivity
    - Exposure bonus: external-facing assets
    """

    technical_risk = row["severity_cvss"] * row["exploitability"]
    business_impact = row["business_criticality"] * row["data_sensitivity"]
    exposure_bonus = exposure_modifier(row["exposure"])

    total_score = technical_risk + business_impact + exposure_bonus

    return int(round(total_score))


def risk_level(score: int) -> str:
    """
    Convert numeric score into human-readable risk tiers.
    """
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def score_vulnerabilities(df: pd.DataFrame) -> pd.DataFrame:
    """
    Adds risk_score and risk_level columns to a merged asset/vuln dataframe.
    """
    df = df.copy()

    df["risk_score"] = df.apply(calculate_risk_score, axis=1)
    df["risk_level"] = df["risk_score"].apply(risk_level)

    return df


def categorize_risk(row: pd.Series) -> str:
    """
    Rule-based categorization to make triage more explainable.
    Uses existing columns from the merged dataframe.
    """
    cvss = float(row.get("severity_cvss", 0))
    exposure = str(row.get("exposure", "")).lower().strip()
    exploitability = float(row.get("exploitability", 0))
    business_criticality = float(row.get("business_criticality", 0))
    data_sensitivity = float(row.get("data_sensitivity", 0))

    # 1) Very high technical severity
    if cvss >= 9:
        return "Critical Infrastructure"

    # 2) External + meaningfully exploitable + high severity
    if exposure == "external" and cvss >= 7 and exploitability >= 7:
        return "Network Exposure"

    # 3) Likely exploitable regardless of exposure
    if exploitability >= 8:
        return "Exploitable Vulnerability"

    # 4) High business impact drivers
    if business_criticality >= 8 or data_sensitivity >= 8:
        return "High Business Impact"

    return "General Risk"


def escalation_decision(row: pd.Series) -> tuple[str, str]:
    """
    Determines whether a vulnerability requires escalation
    and provides a short justification.
    """
    risk_level = row.get("risk_level", "")
    exposure = str(row.get("exposure", "")).lower().strip()
    business_criticality = float(row.get("business_criticality", 0))
    exploitability = float(row.get("exploitability", 0))

    if risk_level == "Critical":
        return "Yes", "Critical risk level"

    if risk_level == "High" and exposure == "external":
        return "Yes", "High risk on external asset"

    if business_criticality >= 8:
        return "Yes", "High business impact"

    if exploitability >= 8:
        return "Yes", "Highly exploitable vulnerability"

    return "No", "Does not meet escalation criteria"
