# Reply Mirror - AI Agent Challenge 2026
## Multi-Agent Fraud Detection System

### Requirements
- Python 3.8+
- No external libraries required (stdlib only)

### Usage
```bash
python3 agents_v2.py --verbose
```

### Options
- `--verbose` / `-v`    : Show top fraud transactions per dataset
- `--threshold` / `-t`  : Base score threshold (default 0.28)
- `--data-root` / `-d`  : Root directory of datasets

### Architecture: 5 Cooperative Agents

1. **TransactionAnalystAgent** — Statistical profiling per user: z-score on amounts, unusual hours, low balance, late-night withdrawals, burst detection
2. **AnomalyDetectorAgent** — GPS-based: detects user located >500km from home during transaction, impossible travel speed (>900 km/h)
3. **PhishingDetectorAgent** — Scans emails/SMS for phishing signals (fake domains like paypa1-secure.net, urgency patterns), correlates victim identity with sender IBAN, boosts suspicion within 7-day window
4. **ContextEnrichmentAgent** — User profile risk amplification: phishing-vulnerable descriptions, transactions >25% annual salary, elderly+unusual patterns
5. **RecipientIntelligenceAgent** — One-time large recipients, money mule detection (3+ senders), IBAN country mismatches

**OrchestratorAgent** — Weighted aggregation (Anomaly 30%, Phishing 22%, Transaction 25%, Context 13%, Recipient 10%) with adaptive thresholding per dataset.

### Output Files
- `outputs/truman_train_output.txt` — 3 fraud IDs
- `outputs/bnw_train_output.txt`    — 47 fraud IDs
- `outputs/deus_train_output.txt`   — 53 fraud IDs
- `outputs/truman_val_output.txt`   — 3 fraud IDs
- `outputs/bnw_val_output.txt`      — 59 fraud IDs
- `outputs/deus_val_output.txt`     — 57 fraud IDs
