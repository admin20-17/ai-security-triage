🔐 AI Security Triage

AI Security Triage is a structured, explainable Python-based vulnerability prioritization engine.

It ingests asset and vulnerability data, applies a transparent risk scoring model, categorizes risk types, flags escalation cases, and outputs prioritized remediation guidance.

This project simulates a realistic security triage workflow used by SOC and vulnerability management teams.

🎯 What This Project Does

- Merges asset context with vulnerability findings

- Applies weighted, explainable risk scoring

- Assigns human-readable risk tiers (Critical / High / Medium / Low)

- Categorizes risk type (e.g., Network Exposure, Business Impact)

- Flags escalation scenarios with justification

- Produces decision-ready, sorted output

⚙️ How It Works

1️⃣ Ingestion

- Loads assets.csv

- Loads vulnerabilities.csv

- Merges on asset_id

2️⃣ Risk Scoring Model

Risk score is calculated as:

(severity_cvss × exploitability)
+ (business_criticality × data_sensitivity)
+ exposure_modifier


Where:

- External exposure adds additional weight

- Output is rounded to an integer

3️⃣ Risk Tier Mapping

Score	Risk Level
≥ 75	Critical
≥ 50	High
≥ 25	Medium
< 25	Low

4️⃣ Risk Categorization

Rule-based tagging for explainability:

- Critical Infrastructure

- Network Exposure

- Exploitable Vulnerability

- High Business Impact

- General Risk

5️⃣ Escalation Logic

A vulnerability is escalated if:

- Risk level is Critical

- High risk on an external asset

- Business criticality ≥ 8

- Exploitability ≥ 8

Output includes:

- escalation_flag

- escalation_reason

📊 Output

The engine generates:

output/results.csv


Columns include:

- run_id

- generated_at

- Asset context fields

- risk_score

- risk_level

- risk_category

- escalation_flag

- escalation_reason

Results are sorted by highest risk first.

Console summaries display:

- Total rows scored

- Findings by risk level

- Top prioritized vulnerabilities

🚀 Quick Start
pip install -r requirements.txt
python src/triage.py

📂 Project Structure
ai-security-triage/
│
├── src/
│   ├── ingest.py
│   ├── scoring.py
│   └── triage.py
│
├── data/
│   ├── assets.csv
│   └── vulnerabilities.csv
│
├── docs/
│   └── walkthrough.md
│
├── output/  (ignored by Git)
│
├── requirements.txt
└── README.md

🧠 Design Principles

- Deterministic and explainable logic (no black-box scoring)

- Modular architecture

- Reproducible output

- Clear separation of ingestion, scoring, and orchestration

- Portfolio-ready structure

🔮 Future Enhancements

- Docker containerization

- REST API interface

- Lightweight dashboard

- Extended scoring weight configuration

- CI pipeline integration