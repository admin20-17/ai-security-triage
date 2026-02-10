"""
ingest.py
- Loads CSVs from /data
- Validates required columns and allowed values
- Fails loudly with clear errors (team-friendly)
"""

from __future__ import annotations

import sys
from pathlib import Path
import pandas as pd


# --- Config: expected schema ---
ASSETS_REQUIRED_COLS = [
    "asset_id",
    "asset_name",
    "asset_type",
    "business_criticality",
    "data_sensitivity",
    "exposure",
]

VULNS_REQUIRED_COLS = [
    "vuln_id",
    "asset_id",
    "cve_id",
    "severity_cvss",
    "exploitability",
    "known_exploit",
]

ALLOWED_EXPOSURE = {"internal", "external"}
ALLOWED_YESNO = {"yes", "no"}


class DataValidationError(Exception):
    """Raised when input data fails validation."""


def _die(msg: str, code: int = 1) -> None:
    print(f"\n❌ ERROR: {msg}\n", file=sys.stderr)
    sys.exit(code)


def _require_file(path: Path) -> None:
    if not path.exists():
        raise DataValidationError(f"Missing file: {path.as_posix()}")


def _require_columns(df: pd.DataFrame, required: list[str], label: str) -> None:
    missing = [c for c in required if c not in df.columns]
    if missing:
        raise DataValidationError(
            f"{label} is missing required columns: {missing}\n"
            f"Found columns: {list(df.columns)}"
        )


def _normalize_str_series(s: pd.Series) -> pd.Series:
    # Convert to string, strip, lowercase; preserve NaNs
    return s.astype("string").str.strip().str.lower()


def _validate_assets(df_assets: pd.DataFrame) -> pd.DataFrame:
    _require_columns(df_assets, ASSETS_REQUIRED_COLS, "assets.csv")

    # Normalize exposure
    df_assets["exposure"] = _normalize_str_series(df_assets["exposure"])
    bad_exposure = sorted(set(df_assets["exposure"].dropna()) - ALLOWED_EXPOSURE)
    if bad_exposure:
        raise DataValidationError(
            f"assets.csv has invalid exposure values: {bad_exposure}. "
            f"Allowed: {sorted(ALLOWED_EXPOSURE)}"
        )

    # business_criticality and data_sensitivity must be ints 1-5
    for col in ["business_criticality", "data_sensitivity"]:
        try:
            df_assets[col] = pd.to_numeric(df_assets[col], errors="raise").astype(int)
        except Exception:
            raise DataValidationError(
                f"assets.csv column '{col}' must be numeric integers (1-5)."
            )
        bad = df_assets[(df_assets[col] < 1) | (df_assets[col] > 5)]
        if not bad.empty:
            raise DataValidationError(
                f"assets.csv column '{col}' must be between 1 and 5. "
                f"Bad rows asset_id: {bad['asset_id'].tolist()}"
            )

    # asset_id must be unique + non-empty
    df_assets["asset_id"] = df_assets["asset_id"].astype("string").str.strip()
    if df_assets["asset_id"].isna().any() or (df_assets["asset_id"] == "").any():
        raise DataValidationError("assets.csv has empty asset_id values.")
    dupes = df_assets[df_assets["asset_id"].duplicated()]["asset_id"].tolist()
    if dupes:
        raise DataValidationError(f"assets.csv has duplicate asset_id values: {dupes}")

    return df_assets


def _validate_vulns(df_vulns: pd.DataFrame, asset_ids: set[str]) -> pd.DataFrame:
    _require_columns(df_vulns, VULNS_REQUIRED_COLS, "vulnerabilities.csv")

    # Normalize yes/no
    df_vulns["known_exploit"] = _normalize_str_series(df_vulns["known_exploit"])
    bad_yesno = sorted(set(df_vulns["known_exploit"].dropna()) - ALLOWED_YESNO)
    if bad_yesno:
        raise DataValidationError(
            f"vulnerabilities.csv has invalid known_exploit values: {bad_yesno}. "
            f"Allowed: {sorted(ALLOWED_YESNO)}"
        )

    # severity_cvss must be float 0-10
    try:
        df_vulns["severity_cvss"] = pd.to_numeric(df_vulns["severity_cvss"], errors="raise")
    except Exception:
        raise DataValidationError("vulnerabilities.csv column 'severity_cvss' must be numeric (0-10).")
    bad_cvss = df_vulns[(df_vulns["severity_cvss"] < 0) | (df_vulns["severity_cvss"] > 10)]
    if not bad_cvss.empty:
        raise DataValidationError(
            f"vulnerabilities.csv severity_cvss must be between 0 and 10. "
            f"Bad rows vuln_id: {bad_cvss['vuln_id'].tolist()}"
        )

    # exploitability must be int 1-5
    try:
        df_vulns["exploitability"] = pd.to_numeric(df_vulns["exploitability"], errors="raise").astype(int)
    except Exception:
        raise DataValidationError("vulnerabilities.csv column 'exploitability' must be integer (1-5).")
    bad_expl = df_vulns[(df_vulns["exploitability"] < 1) | (df_vulns["exploitability"] > 5)]
    if not bad_expl.empty:
        raise DataValidationError(
            f"vulnerabilities.csv exploitability must be between 1 and 5. "
            f"Bad rows vuln_id: {bad_expl['vuln_id'].tolist()}"
        )

    # asset_id must exist in assets.csv
    df_vulns["asset_id"] = df_vulns["asset_id"].astype("string").str.strip()
    missing_assets = sorted(set(df_vulns["asset_id"].dropna()) - asset_ids)
    if missing_assets:
        raise DataValidationError(
            f"vulnerabilities.csv references unknown asset_id values: {missing_assets}"
        )

    # vuln_id must be non-empty; duplicates are allowed? We'll enforce unique for cleanliness.
    df_vulns["vuln_id"] = df_vulns["vuln_id"].astype("string").str.strip()
    if df_vulns["vuln_id"].isna().any() or (df_vulns["vuln_id"] == "").any():
        raise DataValidationError("vulnerabilities.csv has empty vuln_id values.")
    dupes = df_vulns[df_vulns["vuln_id"].duplicated()]["vuln_id"].tolist()
    if dupes:
        raise DataValidationError(f"vulnerabilities.csv has duplicate vuln_id values: {dupes}")

    return df_vulns


def load_data(repo_root: Path | None = None) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Returns: (assets_df, vulnerabilities_df)
    """
    if repo_root is None:
        # src/ingest.py -> repo root is parent of src/
        repo_root = Path(__file__).resolve().parents[1]

    data_dir = repo_root / "data"
    assets_path = data_dir / "assets.csv"
    vulns_path = data_dir / "vulnerabilities.csv"

    _require_file(assets_path)
    _require_file(vulns_path)

    df_assets = pd.read_csv(assets_path)
    df_vulns = pd.read_csv(vulns_path)

    df_assets = _validate_assets(df_assets)
    asset_ids = set(df_assets["asset_id"].tolist())

    df_vulns = _validate_vulns(df_vulns, asset_ids)

    return df_assets, df_vulns


def main() -> None:
    try:
        assets, vulns = load_data()
    except DataValidationError as e:
        _die(str(e), code=2)

    print("\n✅ Data loaded and validated successfully.\n")
    print(f"Assets: {len(assets)} rows | Unique asset_id: {assets['asset_id'].nunique()}")
    print(f"Vulnerabilities: {len(vulns)} rows | Unique vuln_id: {vulns['vuln_id'].nunique()}")

    # Helpful quick peek
    print("\n--- Assets (head) ---")
    print(assets.head(3).to_string(index=False))

    print("\n--- Vulnerabilities (head) ---")
    print(vulns.head(3).to_string(index=False))
    print("")


if __name__ == "__main__":
    main()

