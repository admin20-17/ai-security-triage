"""
triage.py
- Orchestrates ingestion, scoring, and output
"""

from pathlib import Path
import pandas as pd
import uuid
from datetime import datetime

from ingest import load_data
from scoring import score_vulnerabilities



def main() -> None:
    # Load validated data
    assets_df, vulns_df = load_data()

    # Merge vulnerabilities with asset context
    merged_df = vulns_df.merge(
        assets_df,
        on="asset_id",
        how="left"
    )

    # Apply risk scoring
    scored_df = score_vulnerabilities(merged_df)

    # Select and order output columns
    output_cols = [
        "asset_id",
        "asset_name",
        "asset_type",
        "vuln_id",
        "cve_id",
        "severity_cvss",
        "exploitability",
        "business_criticality",
        "data_sensitivity",
        "exposure",
        "risk_score",
        "risk_level",
    ]

    scored_df = scored_df[output_cols]
    print("COLUMNS:", list(scored_df.columns))
    print("ROWS:", len(scored_df))

    # ---- Final output polish ----

# Stable sorting (highest risk first)
scored_df = scored_df.sort_values(
    by=["risk_score", "vuln_id"],
    ascending=[False, True]
)

# Lock column order
COL_ORDER = ["vuln_id", "risk_score", "risk_level"]
scored_df = scored_df[COL_ORDER]

# Write results
repo_root = Path(__file__).resolve().parents[1]
output_path = repo_root / "output" / "results.csv"
output_path.parent.mkdir(parents=True, exist_ok=True)

scored_df.to_csv(output_path, index=False)


    print("\n✅ Triage complete.")
    print(f"Results written to: {output_path}")
    print(scored_df[["vuln_id", "risk_score", "risk_level"]].sort_values(
        by="risk_score", ascending=False
    ).to_string(index=False))


if __name__ == "__main__":
    main()
