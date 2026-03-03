# SmishGuard: USPS "Urgent Notice" SMiShing + Attachment Triage (Mini IT/Cyber Project)

This project turns a real-world SMS phishing ("smishing") example into a repeatable **IR-style workflow** + a small **Python triage CLI**.

## What it does
- Parses SMS text (or a text file) and extracts:
  - phone numbers
  - URLs/domains
  - attachment filenames
  - obvious lure phrases (e.g., "urgent notice", "unable to deliver", "click here")
- Applies simple detection heuristics:
  - **Brand impersonation** (USPS) + urgent delivery issue
  - **Call-to-action** + link/attachment
  - **Domain allowlist** checks (e.g., real `usps.com` vs lookalikes)
  - **Suspicious attachment** patterns (unexpected PDF, invoice, etc.)
- Outputs:
  - structured JSON (for logging)
  - a human-readable summary
  - an IOC list you can paste into a ticket or report

> This is a *defensive* project—no exploitation or malware development.

## Quickstart
```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

python -m smishguard.cli --text "USPS: Urgent Notice... USPS.COM/REDELIVERY CLICK HERE" --from "+1 (705) 854-1876" --attachment "USPS-Notice-USD497.pdf"
```

## Example output
- Risk score: `HIGH`
- IOCs:
  - phone: `+1 (705) 854-1876`
  - attachment: `USPS-Notice-USD497.pdf`
  - url (as written): `USPS.COM/REDELIVERY`

## Project deliverables
- `smishguard/cli.py` — CLI tool
- `smishguard/analyzers.py` — parsing + heuristics
- `docs/incident_report_template.md` — 1-page report template
- `docs/ioc_list.md` — IOC list example
- `docs/sigma_smishing_keyword_rule.yml` — basic content rule (email/SMS gateways)
- `tests/` — small unit test set
- GitHub Actions workflow for tests + lint

## Safety
If you ever obtain the real attachment:
- **Do not open it on your main machine**
- Use a disposable VM (Windows Sandbox, VirtualBox, etc.)
- Hash it (SHA256) and submit the hash/file to your org’s tooling (or VirusTotal in a personal learning context)

## License
MIT
