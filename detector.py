# detector.py
# Heuristics to decide whether a file behavior looks like ransomware (defensive)
import math, os, collections

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    ps = [float(c) / len(data) for c in counts.values()]
    return -sum(p * math.log2(p) for p in ps)

def file_entropy(path, sample_bytes=4096):
    try:
        with open(path, "rb") as f:
            data = f.read(sample_bytes)
        return shannon_entropy(data)
    except Exception:
        return 0.0

# Simple heuristic: if many files are modified within a short window, and many display
# high entropy, treat as suspicious.
def is_ransomware_wave(event_stats, entropy_stats, cfg):
    # event_stats: number of modified files in window
    # entropy_stats: list of entropies sampled from modified files
    if event_stats >= cfg['modified_threshold']:
        high_entropy = sum(1 for e in entropy_stats if e >= cfg['entropy_threshold'])
        # If a large fraction are high-entropy, raise alarm
        if high_entropy >= cfg['high_entropy_count']:
            return True
    return False


def score_files(event_stats, entropy_stats, cfg):
    """Return a simple threat score (0-100) and per-file breakdown.

    The score is based on: number of modified files vs threshold, fraction of
    high-entropy files, and average entropy. Returns dict with `score` and
    `details` list.
    """
    score = 0.0
    details = []
    # baseline: proportion of modified files
    try:
        prop = min(1.0, float(event_stats) / max(1.0, cfg.get('modified_threshold', 12)))
    except Exception:
        prop = 0.0
    score += prop * 40.0

    if entropy_stats:
        avg_e = sum(entropy_stats) / len(entropy_stats)
        high_entropy = sum(1 for e in entropy_stats if e >= cfg.get('entropy_threshold', 7.5))
        frac_high = high_entropy / len(entropy_stats)
        # avg entropy contribution (normalized assuming entropy up to 8)
        score += (avg_e / 8.0) * 30.0
        score += frac_high * 30.0
        for e in entropy_stats:
            reason = 'high' if e >= cfg.get('entropy_threshold', 7.5) else 'low'
            details.append({'entropy': e, 'reason': reason})
    else:
        details.append({'entropy': None, 'reason': 'no-samples'})

    # clamp
    score = max(0.0, min(100.0, score))
    return {'score': round(score, 1), 'details': details}
