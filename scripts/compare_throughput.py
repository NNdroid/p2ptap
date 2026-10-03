"""Summarize paired Go overlay benchmarks; MB/s counts delivered payload only."""

import json
import re
import statistics
import sys
from pathlib import Path


def read_samples(path):
    samples = {}
    key = None
    for line in path.read_text(encoding="utf-8").splitlines():
        # Direct logger output can split Go's benchmark name and result across
        # lines. Keep the most recent name until its metric line arrives.
        match = re.search(r"BenchmarkThroughput_(TCP|UDP)/(TCP|QUIC|WebRTC|WebTransport)-\d+\s", line)
        if match:
            key = f"{match[1]}/{match[2]}"
        if key is None:
            continue
        metrics = dict((unit, float(value)) for value, unit in re.findall(
            r"([\d.]+)\s+(MB/s|%delivered|frames/s|written|dispatch_drops|undrained)\b", line))
        if "MB/s" in metrics and "%delivered" in metrics:
            samples.setdefault(key, []).append(metrics)
            key = None
    return samples


def summarize(directory):
    baseline = read_samples(directory / "transport-baseline.txt")
    candidate = read_samples(directory / "transport-candidate.txt")
    expected = {f"{payload}/{transport}" for payload in ("TCP", "UDP")
                for transport in ("TCP", "QUIC", "WebRTC", "WebTransport")}
    if set(baseline) != expected or set(candidate) != expected:
        raise ValueError("missing transport results; refusing an incomplete comparison")
    print("Delivered overlay payload; identical Info-level harness, GOMAXPROCS=4, "
          "100000-frame target, 2-second injection cap, 6-second total drain budget, "
          "five alternating pairs.")
    print("\nThis uses MemTAP and real loopback transports; it does not measure kernel "
          "TCP congestion control, WAN links, or native TAP throughput.\n")
    print("| Payload/transport | Baseline MB/s median [min, max] | Candidate MB/s median [min, max] | Change | Min delivery base / candidate | Max undrained base / candidate |")
    print("|---|---:|---:|---:|---:|---:|")
    result = {}
    for key in sorted(expected):
        old, new = baseline[key], candidate[key]
        if len(old) != 5 or len(new) != 5:
            raise ValueError(f"{key}: expected five samples per revision")
        if any("undrained" not in sample or "dispatch_drops" not in sample for sample in old + new):
            raise ValueError(f"{key}: missing drain accounting; use the current harness for both revisions")
        if any(s["%delivered"] != 100 or s["undrained"] != 0 or s["dispatch_drops"] != 0 for s in new):
            raise ValueError(f"{key}: candidate lost or failed to drain frames; refusing a throughput win")
        old_rates = [s["MB/s"] for s in old]
        new_rates = [s["MB/s"] for s in new]
        old_median, new_median = statistics.median(old_rates), statistics.median(new_rates)
        if old_median <= 0:
            raise ValueError(f"{key}: baseline made no progress")
        change = 100 * (new_median / old_median - 1)
        delivery_old = min(s["%delivered"] for s in old)
        delivery_new = min(s["%delivered"] for s in new)
        undrained_old = max(s["undrained"] for s in old)
        undrained_new = max(s["undrained"] for s in new)
        print(f"| {key} | {old_median:.2f} [{min(old_rates):.2f}, {max(old_rates):.2f}] "
              f"| {new_median:.2f} [{min(new_rates):.2f}, {max(new_rates):.2f}] "
              f"| {change:+.1f}% | {delivery_old:.2f}% / {delivery_new:.2f}% "
              f"| {undrained_old:.0f} / {undrained_new:.0f} |")
        result[key] = {"baseline": old, "candidate": new, "change_percent": change}
    (directory / "comparison.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    summarize(Path(sys.argv[1]))
