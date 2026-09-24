# Multi-Agent Fraud Detection System

A Python multi-agent system that flags fraudulent financial transactions. Built for the **Reply Mirror – AI Agent Challenge 2026**. It uses only the Python standard library (3.8+).

Five specialised agents each score every transaction from a different angle, and an orchestrator combines their scores with dataset-adaptive thresholds.

## Architecture

| Agent | What it looks at |
|---|---|
| **TransactionAnalystAgent** | Per-user statistical profile: amount z-scores, unusual hours, low balance, late-night withdrawals, bursts |
| **AnomalyDetectorAgent** | GPS pings: user far from home during a transaction, impossible travel speed (> 900 km/h, Haversine distance) |
| **PhishingDetectorAgent** | Emails/SMS: urgency patterns, look-alike domains (e.g. `paypa1-secure.net`), correlation with the victim's later transfers |
| **ContextEnrichmentAgent** | User-profile risk: phishing-vulnerable profiles, transactions above 25 % of annual salary |
| **RecipientIntelligenceAgent** | One-time large recipients, money-mule patterns (3+ distinct senders), IBAN country mismatches |
| **OrchestratorAgent** | Weighted aggregation (anomaly 30 %, transaction 25 %, phishing 22 %, context 13 %, recipient 10 %) with per-dataset thresholds |

## Run

```bash
python3 agents_v2.py --verbose
```

Options: `--verbose/-v` (print top fraud transactions per dataset), `--threshold/-t` (base score threshold, default 0.28), `--data-root/-d` (folder that contains the dataset directories).

Results are written to `outputs/` (one fraud transaction ID per line). The challenge datasets are in the dataset folders next to the script. If you reuse them, check the challenge terms first.

## Dataset Profiles & Performance Metrics
The system dynamically scales across three distinct scenario environments. Below is the summary of the datasets processed and the exact fraud detection rates achieved during validation:

* **The Truman Show (Train/Val)**
  * **Volume**: 80 transactions | 3 users | 829 location pings
  * **Fraud Rate**: ~3.8% (3 flagged)
  * **Primary Threat Vector**: Targeted social engineering combined with sudden, extreme geographic anomalies (e.g., GPS 6,800km from home).
* **Brave New World (Train/Val)**
  * **Volume**: ~522 transactions | 7 users | 1,917 location pings
  * **Fraud Rate**: 9.0% - 11.3% (47-59 flagged)
  * **Primary Threat Vector**: High-volume phishing campaigns leading to unauthorized e-commerce and international transfers.
* **Deus Ex (Train/Val)**
  * **Volume**: ~2,000 transactions | 12 users | 3,263 location pings
  * **Fraud Rate**: 2.6% - 2.8% (53-57 flagged)
  * **Primary Threat Vector**: Highly sophisticated fraud involving "impossible travel" speeds (>900 km/h) and coordinated money mule networks (4+ distinct senders).

## Adaptive Thresholding Strategy
Instead of a static cutoff, the `OrchestratorAgent` applies dataset-specific threshold tuning based on the environment's threat landscape:
- **Truman / BNW (Threshold: 0.10):** These datasets are relatively clean but require higher sensitivity to meet recall requirements. 
- **Deus Ex (Threshold: 0.25):** Contains incredibly strong geographic signals (e.g., Haversine distances > 5000km). The threshold is kept stricter to prevent false positives from normal, high-wealth user travel.
- **Fail-Safe Fallback:** If the static threshold yields 0 flagged transactions, the orchestrator automatically falls back to a top-1% or top-5% percentile cutoff to guarantee baseline detection.

## Technical Deep Dive: Key Signal Highlights
* **Mathematical Outliers:** The `TransactionAnalystAgent` calculates live standard deviations. A z-score `> 3.0` applies a high penalty (0.30), while extreme anomalies `> 4.0` trigger severe alerts (0.45 weight).
* **Kinematic Verification:** The `AnomalyDetectorAgent` calculates the Great-Circle (Haversine) distance between consecutive GPS pings. Travel speeds exceeding 900 km/h instantly trigger an "impossible travel" multiplier.
* **NLP Phishing Signatures:** The `PhishingDetectorAgent` uses Regex to scan communications for urgent directives (`48 hours`, `immediately`) coupled with obfuscated domains (`paypa1`, `amaz0n`, `secure-bank-login`).
* **Socio-Economic Correlation:** The `ContextEnrichmentAgent` scales transaction risk against annual salary. A single transaction exceeding 25% of a user's declared salary generates an immediate risk boost, particularly for elderly users (>70 years old) engaging in late-night e-commerce.

## License

MIT, see [LICENSE](LICENSE).
