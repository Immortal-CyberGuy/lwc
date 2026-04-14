from __future__ import annotations

import argparse
import csv
import html
import mimetypes
import subprocess
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from src.utils.key_manager import recommended_profiles

ROOT_DIR = Path(__file__).resolve().parents[2]
RESULTS_DIR = ROOT_DIR / "results"
DOCS_DIR = ROOT_DIR / "docs"

TASKS = {
    "verify": [sys.executable, "verify_setup.py"],
    "tests": [sys.executable, "-m", "pytest", "tests", "-q"],
    "benchmark_quick": [sys.executable, "main.py", "benchmark_quick"],
    "benchmark_full": [sys.executable, "main.py", "benchmark_full"],
    "attack_all": [sys.executable, "main.py", "attack_all"],
    "charts": [sys.executable, "main.py", "charts"],
}


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _extract_attack_result(log_path: Path) -> str:
    if not log_path.exists():
        return "MISSING"
    content = log_path.read_text(encoding="utf-8", errors="ignore")
    if "RESULT:" not in content:
        return "UNKNOWN"
    if "PASS" in content:
        return "PASS"
    if "FAIL" in content:
        return "FAIL"
    return "UNKNOWN"


def collect_project_state(root_dir: Path = ROOT_DIR) -> dict[str, object]:
    results_dir = root_dir / "results"
    docs_dir = root_dir / "docs"

    benchmark_rows = _read_csv(results_dir / "benchmark_results.csv")
    summary_rows = _read_csv(results_dir / "benchmark_summary.csv")

    charts = [
        "chart1_throughput.png",
        "chart2_enc_time.png",
        "chart3_memory.png",
        "chart4_enc_dec.png",
        "chart5_tradeoff.png",
        "chart6_attacks.png",
    ]
    available_charts = [name for name in charts if (results_dir / name).exists()]

    attack_status = {
        "eavesdrop": _extract_attack_result(results_dir / "attack_logs" / "eavesdrop_demo.log"),
        "replay": _extract_attack_result(results_dir / "attack_logs" / "replay_demo.log"),
        "mitm": _extract_attack_result(results_dir / "attack_logs" / "mitm_demo.log"),
    }

    evidence_files = [
        "benchmark_results.csv",
        "benchmark_summary.csv",
        "run1.csv",
        "run2.csv",
        "run3.csv",
        "test_results_latest.txt",
    ]
    present_evidence = [name for name in evidence_files if (results_dir / name).exists()]

    docs_expected = ["Final_Report.md", "Presentation_Outline.md"]
    docs_present = [name for name in docs_expected if (docs_dir / name).exists()]

    return {
        "benchmark_rows": benchmark_rows,
        "summary_rows": summary_rows,
        "available_charts": available_charts,
        "attack_status": attack_status,
        "evidence_files": present_evidence,
        "docs_present": docs_present,
        "profiles": recommended_profiles(),
    }


def _table_from_rows(rows: list[dict[str, str]], max_rows: int = 24) -> str:
    if not rows:
        return "<p class='muted'>No table data available yet.</p>"

    headers = list(rows[0].keys())
    head_html = "".join(f"<th>{html.escape(col)}</th>" for col in headers)
    body_lines = []
    for row in rows[:max_rows]:
        cells = "".join(f"<td>{html.escape(str(row.get(col, '')))}</td>" for col in headers)
        body_lines.append(f"<tr>{cells}</tr>")
    body_html = "".join(body_lines)
    return (
        "<div class='table-wrap'>"
        f"<table><thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table>"
        "</div>"
    )


def _profile_rows_html(state: dict[str, object]) -> str:
    profiles = state["profiles"]
    lines = []
    for profile in profiles:
        lines.append(
            "<tr>"
            f"<td>{html.escape(profile.name)}</td>"
            f"<td>{profile.root_key_bytes}</td>"
            f"<td>{profile.engine_key_bytes}</td>"
            f"<td>{profile.rekey_after_messages}</td>"
            f"<td>{profile.nonce_fixed_field_bytes}</td>"
            f"<td>{html.escape(profile.description)}</td>"
            "</tr>"
        )
    return "".join(lines)


def render_dashboard_html(
    state: dict[str, object],
    last_task: str = "",
    task_output: str = "",
) -> str:
    chart_blocks = []
    for chart in state["available_charts"]:
        src = f"/artifact?path={urllib.parse.quote('results/' + chart)}"
        chart_blocks.append(
            "<div class='chart-card'>"
            f"<h4>{html.escape(chart)}</h4>"
            f"<img src='{src}' alt='{html.escape(chart)}'/>"
            "</div>"
        )
    charts_html = "".join(chart_blocks) if chart_blocks else "<p class='muted'>Charts not generated yet.</p>"

    attack_status = state["attack_status"]
    output_block = ""
    if last_task:
        output_block = (
            "<section class='panel'>"
            f"<h3>Last Run: {html.escape(last_task)}</h3>"
            f"<pre>{html.escape(task_output)}</pre>"
            "</section>"
        )

    benchmark_table = _table_from_rows(state["benchmark_rows"], max_rows=40)
    summary_table = _table_from_rows(state["summary_rows"], max_rows=12)

    evidence_items = "".join(f"<li>{html.escape(item)}</li>" for item in state["evidence_files"])
    docs_items = "".join(f"<li>{html.escape(item)}</li>" for item in state["docs_present"])

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LWC Project Dashboard</title>
  <style>
    :root {{
      --bg: #f5f7fa;
      --panel: #ffffff;
      --text: #1c2530;
      --muted: #5d6b79;
      --accent: #124c7a;
      --border: #d8e1ea;
      --ok: #1f7a44;
      --warn: #b87400;
      --bad: #b31d28;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: "Segoe UI", "Calibri", sans-serif;
      color: var(--text);
      background: var(--bg);
      line-height: 1.4;
    }}
    header {{
      background: var(--accent);
      color: #fff;
      padding: 16px 24px;
    }}
    header h1 {{
      margin: 0 0 6px 0;
      font-size: 22px;
    }}
    main {{
      padding: 20px;
      max-width: 1400px;
      margin: 0 auto;
      display: grid;
      gap: 16px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
    }}
    .panel h2, .panel h3 {{
      margin-top: 0;
    }}
    .muted {{ color: var(--muted); }}
    .row {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    }}
    .card {{
      background: #f8fbff;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
    }}
    .pill {{
      padding: 2px 8px;
      border-radius: 999px;
      font-weight: 600;
      display: inline-block;
      margin-left: 6px;
    }}
    .ok {{ background: #e5f6eb; color: var(--ok); }}
    .warn {{ background: #fff3dc; color: var(--warn); }}
    .bad {{ background: #fde8ea; color: var(--bad); }}
    table {{
      border-collapse: collapse;
      width: 100%;
      font-size: 13px;
    }}
    th, td {{
      border: 1px solid var(--border);
      padding: 6px 8px;
      text-align: left;
      vertical-align: top;
    }}
    th {{ background: #eef4fa; }}
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: 8px;
    }}
    .chart-grid {{
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    }}
    .chart-card {{
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px;
      background: #fff;
    }}
    .chart-card h4 {{
      margin: 0 0 8px 0;
      font-size: 13px;
      color: var(--muted);
    }}
    .chart-card img {{
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 4px;
      background: #fff;
    }}
    .task-grid {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .task-grid a {{
      text-decoration: none;
      padding: 6px 10px;
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text);
      background: #f9fcff;
      font-size: 13px;
    }}
    pre {{
      margin: 0;
      background: #0e1621;
      color: #d7e3f0;
      border-radius: 8px;
      padding: 10px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 420px;
    }}
  </style>
</head>
<body>
  <header>
    <h1>Secure Wireless LWC Dashboard</h1>
    <div>Professional project flow: key strategy -> secure transport -> benchmarks -> attacks -> charts/report artifacts.</div>
  </header>

  <main>
    <section class="panel">
      <h2>Workflow</h2>
      <div class="row">
        <div class="card"><strong>1. Key Setup</strong><br>Use 128-bit minimum keys and profile-based HKDF derivation.</div>
        <div class="card"><strong>2. Validate Build</strong><br>Run setup verification and test suite before experiments.</div>
        <div class="card"><strong>3. Measure</strong><br>Generate benchmark CSV, repeated runs, and summary table.</div>
        <div class="card"><strong>4. Prove Security</strong><br>Run eavesdrop/replay/MITM demos and capture PASS/FAIL logs.</div>
        <div class="card"><strong>5. Report</strong><br>Generate six charts and attach final report + presentation outline.</div>
      </div>
    </section>

    <section class="panel">
      <h2>Run Controls</h2>
      <div class="task-grid">
        <a href="/run?task=verify">Run Verify</a>
        <a href="/run?task=tests">Run Tests</a>
        <a href="/run?task=benchmark_quick">Benchmark Quick</a>
        <a href="/run?task=benchmark_full">Benchmark Full</a>
        <a href="/run?task=attack_all">Run All Attacks</a>
        <a href="/run?task=charts">Generate Charts</a>
      </div>
      <p class="muted">Each action runs the codex project commands locally and prints terminal output below.</p>
    </section>

    {output_block}

    <section class="panel">
      <h2>Lightweight Key Strategy</h2>
      <p>
        Project key policy uses profile-driven root keys, HKDF-derived per-engine keys, and
        counter-based nonce construction guidance (fixed field + monotonic counter).
      </p>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Profile</th>
              <th>Root Key (bytes)</th>
              <th>Derived Engine Key (bytes)</th>
              <th>Rekey Threshold (messages)</th>
              <th>Nonce Fixed Field (bytes)</th>
              <th>Intended Use</th>
            </tr>
          </thead>
          <tbody>
            {_profile_rows_html(state)}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <h2>Benchmark Summary</h2>
      {summary_table}
      <h3>Benchmark Raw Rows</h3>
      {benchmark_table}
    </section>

    <section class="panel">
      <h2>Attack Evidence</h2>
      <div class="row">
        <div class="card">Eavesdrop: <span class="pill {'ok' if attack_status['eavesdrop'] == 'PASS' else 'warn' if attack_status['eavesdrop'] == 'MISSING' else 'bad'}">{html.escape(attack_status['eavesdrop'])}</span></div>
        <div class="card">Replay: <span class="pill {'ok' if attack_status['replay'] == 'PASS' else 'warn' if attack_status['replay'] == 'MISSING' else 'bad'}">{html.escape(attack_status['replay'])}</span></div>
        <div class="card">MITM: <span class="pill {'ok' if attack_status['mitm'] == 'PASS' else 'warn' if attack_status['mitm'] == 'MISSING' else 'bad'}">{html.escape(attack_status['mitm'])}</span></div>
      </div>
      <p class="muted">Statuses come from results/attack_logs/*.log.</p>
    </section>

    <section class="panel">
      <h2>Charts</h2>
      <div class="chart-grid">
        {charts_html}
      </div>
    </section>

    <section class="panel">
      <h2>Submission Pack Check</h2>
      <div class="row">
        <div class="card">
          <h3>Evidence Files</h3>
          <ul>{evidence_items if evidence_items else "<li>None found yet.</li>"}</ul>
        </div>
        <div class="card">
          <h3>Docs Files</h3>
          <ul>{docs_items if docs_items else "<li>None found yet.</li>"}</ul>
        </div>
      </div>
    </section>
  </main>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "LWCDashboard/1.0"

    def _send_html(self, body: str, status: int = 200) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_bytes(self, payload: bytes, content_type: str = "application/octet-stream") -> None:
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _safe_artifact_path(self, raw_path: str) -> Path | None:
        candidate = (ROOT_DIR / raw_path).resolve()
        if ROOT_DIR not in candidate.parents and candidate != ROOT_DIR:
            return None
        return candidate

    def _run_task(self, task: str) -> tuple[str, str]:
        if task not in TASKS:
            return task, f"Unknown task '{task}'."

        cmd = TASKS[task]
        try:
            completed = subprocess.run(
                cmd,
                cwd=ROOT_DIR,
                capture_output=True,
                text=True,
                timeout=1800,
            )
        except subprocess.TimeoutExpired:
            return task, "Task timed out after 1800 seconds."

        output = (
            f"$ {' '.join(cmd)}\n"
            f"Exit code: {completed.returncode}\n\n"
            f"{completed.stdout}\n"
            f"{completed.stderr}"
        )
        return task, output.strip()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        query = urllib.parse.parse_qs(parsed.query)

        if parsed.path == "/artifact":
            raw_path = query.get("path", [""])[0]
            target = self._safe_artifact_path(raw_path)
            if not raw_path or target is None or not target.exists() or not target.is_file():
                self.send_error(404, "Artifact not found.")
                return
            content_type, _ = mimetypes.guess_type(str(target))
            self._send_bytes(target.read_bytes(), content_type or "application/octet-stream")
            return

        if parsed.path == "/run":
            task = query.get("task", [""])[0]
            last_task, output = self._run_task(task)
            state = collect_project_state()
            body = render_dashboard_html(state, last_task=last_task, task_output=output)
            self._send_html(body)
            return

        state = collect_project_state()
        body = render_dashboard_html(state)
        self._send_html(body)


def run_dashboard(host: str = "127.0.0.1", port: int = 8091) -> None:
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"[DASHBOARD] Serving on http://{host}:{port}")
    print("[DASHBOARD] Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[DASHBOARD] Stopped.")
    finally:
        server.server_close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Project dashboard for the codex implementation.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address.")
    parser.add_argument("--port", type=int, default=8091, help="Bind port.")
    return parser


def main() -> None:
    args = _parser().parse_args()
    run_dashboard(host=args.host, port=args.port)


if __name__ == "__main__":
    main()

