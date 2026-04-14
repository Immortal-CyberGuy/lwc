from pathlib import Path

from src.attacks.eavesdrop_demo import run_demo as run_eavesdrop_demo
from src.attacks.mitm_demo import run_demo as run_mitm_demo
from src.attacks.replay_demo import run_demo as run_replay_demo


def test_eavesdrop_demo(tmp_path: Path):
    log_file = tmp_path / "eavesdrop.log"
    result = run_eavesdrop_demo(str(log_file))
    assert result["result"] == "PASS"
    assert result["plaintext_in_raw"] is False
    assert log_file.exists()


def test_replay_demo(tmp_path: Path):
    log_file = tmp_path / "replay.log"
    result = run_replay_demo(str(log_file))
    assert result["result"] == "PASS"
    assert result["statuses"] == ["OK", "REPLAY_REJECTED", "REPLAY_REJECTED"]
    assert log_file.exists()


def test_mitm_demo(tmp_path: Path):
    log_file = tmp_path / "mitm.log"
    result = run_mitm_demo(str(log_file))
    assert result["result"] == "PASS"
    assert result["receiver_status"] == "AUTH_FAILURE"
    assert log_file.exists()
