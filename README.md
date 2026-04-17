### Dataset Profiles & Performance Metrics
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

### Adaptive Thresholding Strategy
Instead of a static cutoff, the `OrchestratorAgent` applies dataset-specific threshold tuning based on the environment's threat landscape:
- **Truman / BNW (Threshold: 0.10):** These datasets are relatively clean but require higher sensitivity to meet recall requirements. 
- **Deus Ex (Threshold: 0.25):** Contains incredibly strong geographic signals (e.g., Haversine distances > 5000km). The threshold is kept stricter to prevent false positives from normal, high-wealth user travel.
- **Fail-Safe Fallback:** If the static threshold yields 0 flagged transactions, the orchestrator automatically falls back to a top-1% or top-5% percentile cutoff to guarantee baseline detection.

### Technical Deep Dive: Key Signal Highlights
* **Mathematical Outliers:** The `TransactionAnalystAgent` calculates live standard deviations. A z-score `> 3.0` applies a high penalty (0.30), while extreme anomalies `> 4.0` trigger severe alerts (0.45 weight).
* **Kinematic Verification:** The `AnomalyDetectorAgent` calculates the Great-Circle (Haversine) distance between consecutive GPS pings. Travel speeds exceeding 900 km/h instantly trigger an "impossible travel" multiplier.
* **NLP Phishing Signatures:** The `PhishingDetectorAgent` uses Regex to scan communications for urgent directives (`48 hours`, `immediately`) coupled with obfuscated domains (`paypa1`, `amaz0n`, `secure-bank-login`).
* **Socio-Economic Correlation:** The `ContextEnrichmentAgent` scales transaction risk against annual salary. A single transaction exceeding 25% of a user's declared salary generates an immediate risk boost, particularly for elderly users (>70 years old) engaging in late-night e-commerce.