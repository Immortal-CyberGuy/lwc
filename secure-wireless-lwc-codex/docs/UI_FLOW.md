# Project UI Flow (Codex Version)

## Start dashboard
- `python -m src.ui.dashboard`
- or `python main.py dashboard`

Default URL: `http://127.0.0.1:8091`

## Workflow sections in the dashboard
1. **Workflow**
   - Key setup, validation, benchmarks, attack proof, reporting.
2. **Run Controls**
   - One-click actions for verify, tests, quick/full benchmarks, all attacks, and chart generation.
3. **Lightweight Key Strategy**
   - Profile table (`minimal`, `balanced`, `hardened`) with rekey thresholds and nonce strategy.
4. **Benchmark Summary + Raw Rows**
   - Reads `results/benchmark_results.csv` and `results/benchmark_summary.csv`.
5. **Attack Evidence**
   - Reads PASS/FAIL from `results/attack_logs/*.log`.
6. **Charts**
   - Displays all six charts directly from `results/`.
7. **Submission Pack Check**
   - Confirms presence of benchmark/evidence/report files.

## Intended use on demo day
1. Open dashboard.
2. Run `verify` and `tests`.
3. Run quick benchmark and all attacks.
4. Generate charts.
5. Use same screen to show attack evidence and chart comparison in viva.

