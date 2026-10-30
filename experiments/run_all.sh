#!/usr/bin/env bash
# Re-creates every number and figure of the evaluation (takes a few minutes).
set -e
cd "$(dirname "$0")"
python3 evaluate.py        # main results, ablation, sweep, Wilcoxon tests  -> results/results.json
python3 extra_eval.py      # ARP parameter grid, scan latency, Poisson check -> results/results_extra.json
python3 make_figs.py       # figures (needs results.json)                    -> docs/figures/*.pdf
python3 make_figs_extra.py # taxonomy + prominent-works figures
