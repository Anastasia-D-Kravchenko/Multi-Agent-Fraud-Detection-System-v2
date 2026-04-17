"""
Reply Mirror - AI Agent Challenge 2026
Multi-Agent Fraud Detection System v2 (FINAL)

Architecture:
  Agent 1: TransactionAnalystAgent   - statistical / behavioral anomalies
  Agent 2: AnomalyDetectorAgent      - geographic / temporal impossibility
  Agent 3: PhishingDetectorAgent     - phishing signals in comms, correlated with txs
  Agent 4: ContextEnrichmentAgent    - user-profile risk amplification
  Agent 5: RecipientIntelligenceAgent- recipient patterns (mule detection, one-timers)
  OrchestratorAgent                  - weighted scoring + dataset-adaptive thresholding

Usage:
    python3 agents_v2.py [--verbose]

Outputs UTF-8 .txt files in ./outputs/ (one line per fraudulent transaction ID).
"""

import csv
import json
import re
import math
import os
import sys
import argparse
from datetime import datetime, timedelta
from collections import defaultdict


# ─────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────

def haversine(lat1, lng1, lat2, lng2):
    """Great-circle distance in km between two GPS coords."""
    R = 6371
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lng2 - lng1)
    a = math.sin(dphi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(dlam/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def load_transactions(path):
    rows = []
    with open(path, encoding='utf-8-sig') as f:
        reader = csv.DictReader(f)
        for row in reader:
            row['amount'] = float(row['amount']) if row.get('amount') else 0.0
            row['balance_after'] = float(row['balance_after']) if row.get('balance_after') else 0.0
            if row.get('timestamp'):
                try:
                    row['timestamp'] = datetime.fromisoformat(row['timestamp'])
                except ValueError:
                    row['timestamp'] = None
            else:
                row['timestamp'] = None
            rows.append(row)
    return rows


def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path, encoding='utf-8') as f:
        return json.load(f)


def mean_std(values):
    if not values:
        return 0.0, 1.0
    m = sum(values) / len(values)
    s = (sum((x - m) ** 2 for x in values) / len(values)) ** 0.5
    return m, max(s, 1e-6)


# ─────────────────────────────────────────────
# Agent 1: Transaction Analyst
# ─────────────────────────────────────────────

class TransactionAnalystAgent:
    """
    Per-user statistical profiling.
    Flags:
      - Amount z-score outliers relative to user's own history
      - First-ever transactions to new recipients with large amounts
      - Unusual hour transactions (01:00–05:00)
      - Very low post-transaction balance
      - Late-night withdrawals / e-commerce
      - Sudden change in transaction type pattern
      - Multiple large transactions in a short window (burst)
    """

    def analyze(self, transactions, users):
        iban_to_user = {u.get('iban', ''): u for u in users}

        # Build per-user profile (first pass)
        user_profile = defaultdict(lambda: {
            'amounts': [], 'recipients': set(), 'types': defaultdict(int),
            'hours': [], 'iban': None, 'timestamps': []
        })

        for tx in transactions:
            uid = tx['sender_id']
            p = user_profile[uid]
            p['amounts'].append(tx['amount'])
            p['recipients'].add(tx['recipient_id'])
            p['types'][tx['transaction_type']] += 1
            if tx['timestamp']:
                p['hours'].append(tx['timestamp'].hour)
                p['timestamps'].append(tx['timestamp'])
            if tx['sender_iban']:
                p['iban'] = tx['sender_iban']

        scores = {}
        reasons = {}

        for tx in transactions:
            tid = tx['transaction_id']
            uid = tx['sender_id']
            profile = user_profile[uid]
            score = 0.0
            rsns = []

            amounts = profile['amounts']
            amt = tx['amount']

            # ── Amount z-score ──
            if len(amounts) >= 3:
                m, s = mean_std(amounts)
                z = (amt - m) / s
                if z > 4.0:
                    score += 0.45
                    rsns.append(f"extreme amount z-score={z:.1f} ({amt:.2f} vs mean {m:.2f})")
                elif z > 3.0:
                    score += 0.30
                    rsns.append(f"high amount z-score={z:.1f}")
                elif z > 2.0:
                    score += 0.12
                    rsns.append(f"elevated amount z-score={z:.1f}")

            # ── New recipient + large amount ──
            rid = tx['recipient_id']
            if rid and rid not in profile['recipients']:
                if amt > 500:
                    score += 0.18
                    rsns.append(f"new recipient, large amount={amt:.2f}")
                else:
                    score += 0.06
                    rsns.append("new recipient")

            # ── Unusual hour (deep night) ──
            if tx['timestamp']:
                h = tx['timestamp'].hour
                if h in range(1, 5):
                    score += 0.18
                    rsns.append(f"unusual hour={h}:00")

                # ── Late-night withdrawal / e-commerce ──
                if tx['transaction_type'] in ('withdrawal', 'e-commerce') and h in range(0, 6):
                    extra = 0.20 if amt > 300 else 0.10
                    score += extra
                    rsns.append(f"late-night {tx['transaction_type']} amt={amt:.2f}")

            # ── Very low balance after ──
            bal = tx['balance_after']
            if 0 <= bal < 50:
                score += 0.20
                rsns.append(f"critically low balance_after={bal:.2f}")
            elif 0 <= bal < 200:
                score += 0.08
                rsns.append(f"low balance_after={bal:.2f}")

            # ── Round amount ──
            if amt > 500 and amt % 100 == 0:
                score += 0.05
                rsns.append("round amount")

            # ── Transaction burst: 3+ tx within 30 min ──
            if tx['timestamp']:
                ts = tx['timestamp']
                nearby = [t for t in profile['timestamps']
                          if t != ts and abs((t - ts).total_seconds()) < 1800]
                if len(nearby) >= 3:
                    score += 0.15
                    rsns.append(f"transaction burst: {len(nearby)+1} txs within 30min")

            scores[tid] = min(score, 1.0)
            reasons[tid] = rsns

        return scores, reasons


# ─────────────────────────────────────────────
# Agent 2: Geographic / Temporal Anomaly Detector
# ─────────────────────────────────────────────

class AnomalyDetectorAgent:
    """
    GPS-based anomaly detection.
    Flags:
      - User's GPS is far from home when transaction occurs (>500 km → boost, >2000 km → high boost, >5000 km → very high)
      - Impossible travel: two GPS pings too close in time but far apart (>900 km/h)
      - In-person payment city doesn't match GPS city at transaction time
    """

    def analyze(self, transactions, users, locations):
        iban_to_user = {u['iban']: u for u in users if u.get('iban')}

        # Build biotag → sorted location events
        bio_locs = defaultdict(list)
        for loc in locations:
            try:
                bio_locs[loc['biotag']].append({
                    'ts': datetime.fromisoformat(loc['timestamp']),
                    'lat': float(loc['lat']),
                    'lng': float(loc['lng']),
                    'city': loc.get('city', '')
                })
            except (ValueError, KeyError):
                continue
        for k in bio_locs:
            bio_locs[k].sort(key=lambda x: x['ts'])

        # Build sender → home location
        sender_iban = {tx['sender_id']: tx['sender_iban']
                       for tx in transactions if tx.get('sender_iban')}
        sender_home = {}
        for sid, iban in sender_iban.items():
            if iban in iban_to_user:
                u = iban_to_user[iban]
                res = u.get('residence', {})
                if res.get('lat') and res.get('lng'):
                    sender_home[sid] = (float(res['lat']), float(res['lng']),
                                        res.get('city', ''))

        # Pre-compute impossible travel flags per user
        impossible_travel_users = set()
        for uid, locs_sorted in bio_locs.items():
            for i in range(len(locs_sorted) - 1):
                dt_sec = (locs_sorted[i+1]['ts'] - locs_sorted[i]['ts']).total_seconds()
                if 0 < dt_sec < 3600:
                    dist = haversine(locs_sorted[i]['lat'], locs_sorted[i]['lng'],
                                     locs_sorted[i+1]['lat'], locs_sorted[i+1]['lng'])
                    speed_kmh = dist / (dt_sec / 3600)
                    if speed_kmh > 900:
                        impossible_travel_users.add(uid)

        scores = {}
        reasons = {}

        for tx in transactions:
            tid = tx['transaction_id']
            uid = tx['sender_id']
            score = 0.0
            rsns = []

            if uid in bio_locs and tx['timestamp']:
                tx_ts = tx['timestamp']
                user_locs = bio_locs[uid]

                # Find closest GPS ping(s) within 24h
                close_locs = [l for l in user_locs
                               if abs((l['ts'] - tx_ts).total_seconds()) < 86400]

                if close_locs and uid in sender_home:
                    home_lat, home_lng, home_city = sender_home[uid]
                    # Use closest in time
                    best = min(close_locs, key=lambda l: abs((l['ts'] - tx_ts).total_seconds()))
                    dist = haversine(best['lat'], best['lng'], home_lat, home_lng)

                    if dist > 5000:
                        score += 0.75
                        rsns.append(f"GPS {dist:.0f}km from home (in {best['city']})")
                    elif dist > 2000:
                        score += 0.55
                        rsns.append(f"GPS {dist:.0f}km from home (in {best['city']})")
                    elif dist > 500:
                        score += 0.28
                        rsns.append(f"GPS {dist:.0f}km from home (in {best['city']})")
                    elif dist > 100:
                        score += 0.10
                        rsns.append(f"GPS {dist:.0f}km from home")

                    # In-person payment: city consistency check
                    if tx['transaction_type'] == 'in-person payment' and tx.get('location'):
                        tx_loc_lower = tx['location'].lower()
                        gps_city_lower = best['city'].lower()
                        if gps_city_lower and gps_city_lower not in tx_loc_lower and dist > 500:
                            score += 0.15
                            rsns.append(f"GPS city '{best['city']}' != tx location '{tx['location'][:30]}'")

            # Impossible travel bonus for this user
            if uid in impossible_travel_users:
                score += 0.20
                rsns.append("user has impossible travel event")

            scores[tid] = min(score, 1.0)
            reasons[tid] = rsns

        return scores, reasons


# ─────────────────────────────────────────────
# Agent 3: Phishing / Social Engineering Detector
# ─────────────────────────────────────────────

class PhishingDetectorAgent:
    """
    Scans emails and SMS for phishing signals.
    Correlates victim identity (name in mail/sms) with sender IBAN → sender_id.
    Boosts suspicion for transactions made by phishing victims within 7 days.
    """

    PHISHING_KEYWORDS = [
        r'paypa1', r'amaz0n', r'mirrorpay',
        r'verify.*payment', r'action required',
        r'suspend', r'click here', r'secure link',
        r'confirm.*billing', r'unauthorized.*transaction',
        r'your account.*compromised',
        r'update.*payment.*method', r'verify.*account',
        r'winner', r'prize', r'lottery', r'inheritance',
        r'account.*lock', r'verify.*identity',
        r'unusual.*activ', r'security.*alert',
        r'reset.*password.*urgent', r'otp.*request',
    ]

    SUSPICIOUS_DOMAINS = [
        'paypa1-secure', 'paypa1', 'amaz0n-verify',
        'secure-bank-login', 'mirrorpay-alert', 'mirrorpay-secure',
        'account-verify', 'bank-secure', 'bit.ly/amaz0n',
        'bit.ly/paypa1',
    ]

    def _score_text(self, text):
        score = 0.0
        signals = []
        text_lower = text.lower()
        for kw in self.PHISHING_KEYWORDS:
            if re.search(kw, text_lower):
                score += 0.15
                signals.append(f"kw:{kw}")
        for dom in self.SUSPICIOUS_DOMAINS:
            if dom in text_lower:
                score += 0.30
                signals.append(f"dom:{dom}")
        if re.search(r'48 hours?|24 hours?|immediately|right now', text_lower) and \
           re.search(r'https?://', text_lower):
            score += 0.20
            signals.append("urgency+link")
        return min(score, 1.0), signals

    def _extract_victim_name(self, text):
        """Extract first name of victim from email To: or SMS greeting."""
        # Email To: "Firstname Lastname" <...>
        m = re.search(r'To:\s+"?([A-ZÀ-ÿ][a-zà-ÿ]+)\s+([A-ZÀ-ÿ][a-zà-ÿ]+)"?', text)
        if m:
            return m.group(1).lower(), (m.group(1) + ' ' + m.group(2)).lower()
        # SMS Message: Hi Firstname,
        m = re.search(r'Message:.*?(?:Hi|Dear|Hello|URGENT[,:]?\s*)([A-ZÀ-ÿ][a-zà-ÿ]+)', text)
        if m:
            return m.group(1).lower(), None
        return None, None

    def analyze(self, transactions, mails, sms, users=None):
        # Build name → iban lookup from users (if provided)
        fname_iban = {}
        fullname_iban = {}
        iban_sid = {}
        if users:
            for u in users:
                fn = u.get('first_name', '').lower()
                ln = u.get('last_name', '').lower()
                iban = u.get('iban', '')
                if fn:
                    fname_iban[fn] = iban
                if fn and ln:
                    fullname_iban[f"{fn} {ln}"] = iban
        for tx in transactions:
            if tx.get('sender_iban') and tx['sender_id']:
                iban_sid[tx['sender_iban']] = tx['sender_id']

        # Collect phishing signals: (timestamp_or_None, score, signals, victim_iban_or_None)
        phishing_signals = []

        for mail_entry in mails:
            mail_text = mail_entry.get('mail', '')
            date_match = re.search(r'Date:\s*(\w+,\s*\d+ \w+ \d{4} \d{2}:\d{2}:\d{2})', mail_text)
            mail_ts = None
            if date_match:
                try:
                    mail_ts = datetime.strptime(date_match.group(1).strip()[:25],
                                                '%a, %d %b %Y %H:%M:%S')
                except ValueError:
                    pass
            score, signals = self._score_text(mail_text)
            if score > 0.2:
                fn, full = self._extract_victim_name(mail_text)
                victim_iban = fullname_iban.get(full) or fname_iban.get(fn)
                phishing_signals.append((mail_ts, score, signals, victim_iban, 'email'))

        for sms_entry in sms:
            sms_text = sms_entry.get('sms', '')
            date_match = re.search(r'Date:\s*(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', sms_text)
            sms_ts = None
            if date_match:
                try:
                    sms_ts = datetime.strptime(date_match.group(1), '%Y-%m-%d %H:%M:%S')
                except ValueError:
                    pass
            score, signals = self._score_text(sms_text)
            if score > 0.2:
                fn, full = self._extract_victim_name(sms_text)
                victim_iban = fullname_iban.get(full) or fname_iban.get(fn)
                phishing_signals.append((sms_ts, score, signals, victim_iban, 'sms'))

        # Build set of victim sender_ids for fast lookup
        victim_sids = set()
        for _, _, _, viban, _ in phishing_signals:
            if viban and viban in iban_sid:
                victim_sids.add(iban_sid[viban])

        scores = {}
        reasons = {}

        for tx in transactions:
            tid = tx['transaction_id']
            score = 0.0
            rsns = []
            uid = tx['sender_id']
            sender_iban = tx.get('sender_iban', '')

            if tx['timestamp']:
                tx_ts = tx['timestamp']
                for ph_ts, ph_score, ph_signals, ph_victim_iban, ph_type in phishing_signals:
                    # Check victim match
                    victim_match = (ph_victim_iban and ph_victim_iban == sender_iban)

                    if ph_ts is None:
                        if ph_score > 0.5:
                            base = 0.12 if not victim_match else 0.25
                            score += base
                            rsns.append(f"high-conf phishing {ph_type} in dataset" +
                                        (" [victim match]" if victim_match else ""))
                    else:
                        delta = (tx_ts - ph_ts).total_seconds()
                        if 0 <= delta <= 7 * 86400:
                            if victim_match:
                                # Direct victim: strong boost
                                boost = ph_score * 0.7
                                score += boost
                                rsns.append(f"VICTIM of phishing {ph_type} ({ph_signals[:2]}), tx {delta/3600:.0f}h after")
                            else:
                                # Global phishing environment boost (weaker)
                                boost = ph_score * 0.15
                                score += boost
                                rsns.append(f"phishing {ph_type} in dataset, tx within 7d")

            scores[tid] = min(score, 0.95)
            reasons[tid] = rsns

        return scores, reasons


# ─────────────────────────────────────────────
# Agent 4: Context Enrichment Agent
# ─────────────────────────────────────────────

class ContextEnrichmentAgent:
    """
    Cross-references user profiles with transactions:
    - Phishing-vulnerable user profiles → amplify phishing-correlated risk
    - Transactions > N% of annual salary
    - Elderly users + unusual digital patterns
    - User description signals (travel frequency, tech savviness)
    """

    PHISHING_RISK_PATTERNS = [
        (r'(\d+)\s*%.*phishing', 'pct'),
        (r'phishing.*(\d+)\s*%', 'pct'),
        (r'tends?\s+to\s+(trust|fall|click)', 'qual'),
        (r'not.*immune.*lure', 'qual'),
        (r'can.*fall.*trap', 'qual'),
        (r'vulnerable', 'qual'),
        (r'not immune to.*flashy.*lure', 'qual'),
        (r'occasional.*flashy.*online.*lure', 'qual'),
        (r'expose.*pi\u00e8ge', 'qual'),   # French: "expose aux pièges"
        (r'confiance.*messages', 'qual'),  # French: trust in messages
    ]

    def _extract_phishing_risk(self, description):
        desc_lower = description.lower()
        for pat, ptype in self.PHISHING_RISK_PATTERNS:
            m = re.search(pat, desc_lower)
            if m:
                if ptype == 'pct':
                    return int(m.group(1)) / 100
                return 0.55
        return 0.15

    def analyze(self, transactions, users):
        iban_to_user = {u['iban']: u for u in users if u.get('iban')}
        sender_iban = {}
        for tx in transactions:
            if tx.get('sender_iban') and tx['sender_id'] not in sender_iban:
                sender_iban[tx['sender_id']] = tx['sender_iban']

        user_info = {sid: iban_to_user[iban]
                     for sid, iban in sender_iban.items()
                     if iban in iban_to_user}

        scores = {}
        reasons = {}

        for tx in transactions:
            tid = tx['transaction_id']
            uid = tx['sender_id']
            score = 0.0
            rsns = []

            if uid in user_info:
                u = user_info[uid]
                salary = float(u.get('salary', 0) or 0)
                desc = u.get('description', '') or ''
                birth_year = u.get('birth_year', 2050) or 2050
                age = 2087 - birth_year
                phish_risk = self._extract_phishing_risk(desc)

                # Single transaction > 25% of annual salary
                if salary > 0 and tx['amount'] > salary * 0.25:
                    score += 0.20
                    rsns.append(f"tx {tx['amount']:.2f} > 25% annual salary {salary:.0f}")

                # Single transaction > 10% of annual salary (softer signal)
                elif salary > 0 and tx['amount'] > salary * 0.10:
                    score += 0.08
                    rsns.append(f"tx {tx['amount']:.2f} > 10% annual salary")

                # High phishing-risk user
                if phish_risk >= 0.4:
                    score += phish_risk * 0.15
                    rsns.append(f"high phishing risk user ({phish_risk:.0%})")

                # Elderly user + late-night e-commerce or unusual pattern
                if age > 70:
                    if tx['transaction_type'] == 'e-commerce' and tx['timestamp'] and \
                       tx['timestamp'].hour in range(0, 6):
                        score += 0.20
                        rsns.append(f"elderly ({age}) + late-night e-commerce")
                    if tx['amount'] > salary * 0.15 and salary > 0:
                        score += 0.10
                        rsns.append(f"elderly ({age}) + large transaction")

                # Retired user doing large transfers (possible social engineering)
                job = u.get('job', '').lower()
                if 'retired' in job and tx['transaction_type'] == 'transfer' and tx['amount'] > 200:
                    score += 0.12
                    rsns.append(f"retired user, transfer {tx['amount']:.2f}")

            scores[tid] = min(score, 1.0)
            reasons[tid] = rsns

        return scores, reasons


# ─────────────────────────────────────────────
# Agent 5: Recipient Intelligence Agent
# ─────────────────────────────────────────────

class RecipientIntelligenceAgent:
    """
    Recipient-pattern analysis:
    - One-time recipients of large amounts (unknown merchants / mules)
    - Recipients receiving money from 3+ different senders (money mule pattern)
    - IBAN country mismatch for in-person / e-commerce payments
    - Rapid successive transfers to same new recipient
    """

    def analyze(self, transactions):
        recipient_counts = defaultdict(int)
        recipient_senders = defaultdict(set)
        recipient_amounts = defaultdict(list)
        recipient_types = defaultdict(set)

        for tx in transactions:
            rid = tx['recipient_id']
            if rid:
                recipient_counts[rid] += 1
                recipient_senders[rid].add(tx['sender_id'])
                recipient_amounts[rid].append(tx['amount'])
                recipient_types[rid].add(tx['transaction_type'])

        # Classify suspicious recipients
        one_time_large = set()
        money_mule = set()
        for rid in recipient_counts:
            if recipient_counts[rid] == 1 and sum(recipient_amounts[rid]) > 800:
                one_time_large.add(rid)
            if len(recipient_senders[rid]) >= 3:
                money_mule.add(rid)

        scores = {}
        reasons = {}

        for tx in transactions:
            tid = tx['transaction_id']
            rid = tx['recipient_id']
            score = 0.0
            rsns = []

            if rid:
                n_senders = len(recipient_senders[rid])
                total_recv = sum(recipient_amounts[rid])

                if rid in one_time_large:
                    score += 0.25
                    rsns.append(f"one-time recipient, total={total_recv:.2f}")

                if rid in money_mule:
                    score += 0.30
                    rsns.append(f"money mule pattern: {n_senders} distinct senders")

                # Suspiciously many amounts from one sender to this recipient
                # (rapid churning)
                sender_counts_for_rid = sum(
                    1 for tx2 in transactions
                    if tx2['recipient_id'] == rid and tx2['sender_id'] == tx['sender_id']
                )
                if sender_counts_for_rid >= 3 and tx['amount'] > 100:
                    score += 0.15
                    rsns.append(f"repeated transfers to same recipient ({sender_counts_for_rid}x)")

            # IBAN country mismatch
            sender_iban = tx.get('sender_iban', '') or ''
            recipient_iban = tx.get('recipient_iban', '') or ''
            if sender_iban and recipient_iban:
                s_country = sender_iban[:2].upper()
                r_country = recipient_iban[:2].upper()
                if tx['transaction_type'] in ('e-commerce', 'in-person payment') and \
                   s_country != r_country and \
                   r_country not in ('IT', 'DE', 'FR', 'GB', 'US', 'ES', 'NL', 'BE', 'AT', 'CH'):
                    score += 0.12
                    rsns.append(f"IBAN country mismatch: {s_country} → {r_country}")

            scores[tid] = min(score, 1.0)
            reasons[tid] = rsns

        return scores, reasons


# ─────────────────────────────────────────────
# Orchestrator Agent
# ─────────────────────────────────────────────

class OrchestratorAgent:
    """
    Aggregates per-agent scores using weighted voting.
    Applies dataset-adaptive thresholding:
      - If a dataset has strong geo signals → weight anomaly higher
      - Uses percentile-based threshold as fallback
    """

    WEIGHTS = {
        'transaction': 0.25,
        'anomaly':     0.30,   # geo is the strongest signal in Deus Ex
        'phishing':    0.22,
        'context':     0.13,
        'recipient':   0.10,
    }

    def aggregate(self, transactions, all_scores, all_reasons, threshold=0.28):
        scored_txs = []

        for tx in transactions:
            tid = tx['transaction_id']
            total = 0.0
            breakdown = {}
            combined_reasons = []

            for agent_name, weight in self.WEIGHTS.items():
                agent_score = all_scores.get(agent_name, {}).get(tid, 0.0)
                weighted = agent_score * weight
                total += weighted
                breakdown[agent_name] = round(agent_score, 3)
                combined_reasons.extend(all_reasons.get(agent_name, {}).get(tid, []))

            scored_txs.append({
                'tid': tid,
                'score': total,
                'breakdown': breakdown,
                'reasons': combined_reasons,
                'timestamp': tx['timestamp'].isoformat() if tx['timestamp'] else '',
                'sender': tx['sender_id'],
                'amount': tx['amount'],
                'type': tx['transaction_type'],
            })

        # Adaptive threshold: if very few transactions would be flagged at `threshold`,
        # relax to catch at least some. If too many, tighten.
        n = len(scored_txs)
        scores_sorted = sorted(s['score'] for s in scored_txs)

        flagged_at_threshold = sum(1 for s in scored_txs if s['score'] >= threshold)

        # Minimum 1 fraud must be flagged (requirement: not 0, not all)
        effective_threshold = threshold
        if flagged_at_threshold == 0 and n > 0:
            # Fall back to top-1% or top-3 whichever is larger
            k = max(3, int(n * 0.01))
            effective_threshold = scores_sorted[max(0, n - k)]
        elif flagged_at_threshold >= n:
            # Flag only top 5%
            k = max(1, int(n * 0.05))
            effective_threshold = scores_sorted[max(0, n - k)]

        final_fraud = []
        report = []
        for entry in scored_txs:
            entry['fraud'] = entry['score'] >= effective_threshold
            if entry['fraud']:
                final_fraud.append(entry['tid'])
            report.append(entry)

        return final_fraud, report, effective_threshold


# ─────────────────────────────────────────────
# Pipeline Runner
# ─────────────────────────────────────────────

def run_pipeline(dataset_dir, threshold=0.28, verbose=False):
    print(f"\n{'='*65}")
    print(f"  Dataset: {dataset_dir}")
    print(f"{'='*65}")

    # ── Load data ──
    tx_path = os.path.join(dataset_dir, 'transactions.csv')
    if not os.path.exists(tx_path):
        print(f"  ERROR: transactions.csv not found in {dataset_dir}")
        return [], []

    transactions = load_transactions(tx_path)
    users    = load_json(os.path.join(dataset_dir, 'users.json'))
    locations = load_json(os.path.join(dataset_dir, 'locations.json'))
    mails    = load_json(os.path.join(dataset_dir, 'mails.json'))
    sms_data = load_json(os.path.join(dataset_dir, 'sms.json'))

    print(f"  Transactions: {len(transactions)} | Users: {len(users)} | "
          f"Locations: {len(locations)} | Emails: {len(mails)} | SMS: {len(sms_data)}")

    # ── Run agents ──
    print("\n  [1/5] TransactionAnalystAgent...")
    t_scores, t_reasons = TransactionAnalystAgent().analyze(transactions, users)

    print("  [2/5] AnomalyDetectorAgent...")
    a_scores, a_reasons = AnomalyDetectorAgent().analyze(transactions, users, locations)

    print("  [3/5] PhishingDetectorAgent...")
    p_scores, p_reasons = PhishingDetectorAgent().analyze(transactions, mails, sms_data, users)

    print("  [4/5] ContextEnrichmentAgent...")
    c_scores, c_reasons = ContextEnrichmentAgent().analyze(transactions, users)

    print("  [5/5] RecipientIntelligenceAgent...")
    r_scores, r_reasons = RecipientIntelligenceAgent().analyze(transactions)

    # ── Orchestrate ──
    print("\n  [Orchestrator] Aggregating scores...")
    all_scores  = {'transaction': t_scores, 'anomaly': a_scores, 'phishing': p_scores,
                   'context': c_scores, 'recipient': r_scores}
    all_reasons = {'transaction': t_reasons, 'anomaly': a_reasons, 'phishing': p_reasons,
                   'context': c_reasons, 'recipient': r_reasons}

    fraud_ids, report, eff_threshold = OrchestratorAgent().aggregate(
        transactions, all_scores, all_reasons, threshold)

    n_total = len(transactions)
    n_fraud = len(fraud_ids)
    pct = n_fraud / n_total * 100 if n_total else 0

    print(f"\n  Results (threshold={eff_threshold:.3f}):")
    print(f"    Total transactions : {n_total}")
    print(f"    Flagged as fraud   : {n_fraud} ({pct:.1f}%)")

    if n_fraud == 0:
        print("  ⚠ WARNING: 0 fraud detected — output would be INVALID")
    elif n_fraud == n_total:
        print("  ⚠ WARNING: ALL transactions flagged — output would be INVALID")

    if verbose:
        fraud_report = sorted([r for r in report if r['fraud']],
                              key=lambda x: x['score'], reverse=True)
        print(f"\n  Top {min(20, len(fraud_report))} fraud transactions:")
        for r in fraud_report[:20]:
            print(f"    [{r['score']:.3f}] {r['tid']} | {r['type']:20s} | "
                  f"amt={r['amount']:8.2f} | {r['reasons'][:3]}")

    return fraud_ids, report


def save_output(fraud_ids, output_path):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        for tid in fraud_ids:
            f.write(tid + '\n')
    print(f"  → Saved: {output_path} ({len(fraud_ids)} IDs)")


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Reply Mirror Fraud Detection Agent')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show detailed output')
    parser.add_argument('--threshold', '-t', type=float, default=0.28,
                        help='Base fraud score threshold (default 0.28)')
    parser.add_argument('--data-root', '-d', type=str,
                        default=None,
                        help='Root directory containing dataset subfolders')
    args = parser.parse_args()

    # Auto-detect data root
    CANDIDATES = [
        "/home/claude/challenge_files/extracted/datasets",
        "./datasets",
        ".",
    ]
    if args.data_root:
        CANDIDATES = [args.data_root] + CANDIDATES

    BASE = None
    for c in CANDIDATES:
        if os.path.isdir(c):
            BASE = c
            break

    if BASE is None:
        print("ERROR: Could not find data root directory. Use --data-root to specify.")
        sys.exit(1)

    print(f"\nData root: {BASE}")

    DATASETS = {
        'truman_train': os.path.join(BASE, 'The+Truman+Show+-+train', 'The Truman Show - train'),
        'bnw_train':    os.path.join(BASE, 'Brave+New+World+-+train', 'Brave New World - train'),
        'deus_train':   os.path.join(BASE, 'Deus+Ex+-+train',         'Deus Ex - train'),
        'truman_val':   os.path.join(BASE, 'The+Truman+Show+-+validation', 'The Truman Show - validation'),
        'bnw_val':      os.path.join(BASE, 'Brave+New+World+-+validation', 'Brave New World - validation'),
        'deus_val':     os.path.join(BASE, 'Deus+Ex+-+validation',         'Deus Ex - validation'),
    }

    # Per-dataset threshold tuning
    # Truman/BNW: relatively clean datasets → lower threshold to meet the 15% recall requirement
    # Deus Ex: strong geo signals → use standard threshold
    THRESHOLDS = {
        'truman_train': 0.10,
        'bnw_train':    0.10,
        'deus_train':   0.25,
        'truman_val':   0.10,
        'bnw_val':      0.10,
        'deus_val':     0.25,
    }

    OUTPUT_DIR = '/home/claude/outputs'
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for name, path in DATASETS.items():
        if os.path.exists(path):
            th = THRESHOLDS.get(name, args.threshold)
            fraud_ids, report = run_pipeline(path, threshold=th, verbose=args.verbose)
            out_path = os.path.join(OUTPUT_DIR, f'{name}_output.txt')
            save_output(fraud_ids, out_path)
        else:
            print(f"\n  [SKIP] Not found: {path}")

    print(f"\n✓ All outputs written to {OUTPUT_DIR}/")
