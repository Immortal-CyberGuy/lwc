from pathlib import Path

import pandas as pd

from src.ui.dashboard import collect_project_state, render_dashboard_html


def test_dashboard_state_and_render(tmp_path: Path):
    (tmp_path / "results" / "attack_logs").mkdir(parents=True, exist_ok=True)
    (tmp_path / "docs").mkdir(parents=True, exist_ok=True)

    # Minimal benchmark + summary fixtures.
    pd.DataFrame(
        [
            {
                "algorithm": "ASCON-AEAD128",
                "payload_bytes": 16,
                "iterations": 2,
                "avg_encrypt_us": 10.1,
                "avg_decrypt_us": 9.8,
                "throughput_kbps": 120.0,
                "enc_peak_mem_kb": 5.1,
                "dec_peak_mem_kb": 5.2,
            }
        ]
    ).to_csv(tmp_path / "results" / "benchmark_results.csv", index=False)

    pd.DataFrame(
        [
            {
                "algorithm": "ASCON-AEAD128",
                "avg_encrypt_us": 10.1,
                "avg_decrypt_us": 9.8,
                "throughput_kbps": 120.0,
                "enc_peak_mem_kb": 5.1,
            }
        ]
    ).to_csv(tmp_path / "results" / "benchmark_summary.csv", index=False)

    # Attack logs.
    (tmp_path / "results" / "attack_logs" / "eavesdrop_demo.log").write_text("RESULT: PASS\n", encoding="utf-8")
    (tmp_path / "results" / "attack_logs" / "replay_demo.log").write_text("RESULT: PASS\n", encoding="utf-8")
    (tmp_path / "results" / "attack_logs" / "mitm_demo.log").write_text("RESULT: FAIL\n", encoding="utf-8")

    # Document markers.
    (tmp_path / "docs" / "Final_Report.md").write_text("ok", encoding="utf-8")

    state = collect_project_state(tmp_path)
    html_doc = render_dashboard_html(state, last_task="tests", task_output="ok")

    assert state["attack_status"]["eavesdrop"] == "PASS"
    assert state["attack_status"]["mitm"] == "FAIL"
    assert "Secure Wireless LWC Dashboard" in html_doc
    assert "Lightweight Key Strategy" in html_doc
    assert "Benchmark Summary" in html_doc
    assert "Last Run: tests" in html_doc

