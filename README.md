# AI Security Triage

AI Security Triage is a lightweight Python-based risk scoring pipeline that ingests asset and vulnerability data, applies a structured scoring model, and produces prioritized remediation output.

The goal of this project is to simulate a realistic security triage workflow:
- Merge asset context with vulnerability data
- Apply consistent, explainable risk scoring
- Output sorted, decision-ready results
- Provide clear console summaries for quick analysis

---

## 📂 Project Structure

ai-security-triage/
│
├── src/
│   ├── triage.py          # Orchestrates ingestion, scoring, and output
│   ├── ingest.py          # Loads and validates input data
│   └── scoring.py         # Risk scoring logic
│
├── data/
│   └── samples/           # Sample input files
│
├── output/                # Generated results (ignored by Git)
│
├── requirements.txt
└── README.md

---

## 🚀 How to Run

From the project root:

```bash
python src/triage.py

