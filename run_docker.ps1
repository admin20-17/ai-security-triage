# Build + run the AI Security Triage tool in Docker (Windows PowerShell)
docker build -t ai-security-triage:latest .
docker run --rm -v "${PWD}:/app" ai-security-triage:latest