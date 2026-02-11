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

    # ---- Final output polish ----
    run_id = str(uuid.uuid4())
    generated_at = datetime.now().isoformat(timespec="seconds")
    scored_df.insert(0, "run_id", run_id)
    scored_df.insert(1, "generated_at", generated_at)

    # Stable sorting (highest risk first)
    scored_df = scored_df.sort_values(
        by=["risk_score", "vuln_id"],
        ascending=[False, True]
    )

    # Lock column order (FULL output)
    COL_ORDER = ["run_id", "generated_at"] + output_cols
    scored_df = scored_df[COL_ORDER]

    # ---- Console summary ----
    print("\nTriage complete.")
    print(f"Rows scored: {len(scored_df)}")

    if "risk_level" in scored_df.columns:
        counts = scored_df["risk_level"].value_counts()
        print("\nFindings by risk_level:")
        for level, cnt in counts.items():
            print(f"  {level}: {cnt}")

    show_cols = [c for c in ["asset_id", "vuln_id", "cve_id", "risk_score", "risk_level"] if c in scored_df.columns]
    if show_cols and "risk_score" in scored_df.columns:
        print("\nTop findings:")
        print(
            scored_df[show_cols]
            .head(5)
            .to_string(index=False)
        )

    # Write results
    repo_root = Path(__file__).resolve().parents[1]
    output_path = repo_root / "output" / "results.csv"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    scored_df.to_csv(output_path, index=False)

    print(f"\nResults written to: {output_path}")




if __name__ == "__main__":
    main()
