import logging
import tempfile
import uuid
from pathlib import Path

import pytest

from src.utils.key_manager import generate_psk, load_key, save_key
from src.utils.logger import get_logger


def test_generate_psk_length():
    assert len(generate_psk(16)) == 16
    with pytest.raises(ValueError):
        generate_psk(0)


def test_save_load_key_roundtrip():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp) / "k.bin"
        k = generate_psk(16)
        save_key(p, k)
        assert load_key(p) == k


def test_get_logger_emits(capfd):
    log = get_logger(f"lwc_log_{uuid.uuid4().hex}", level=logging.WARNING)
    log.warning("hello")
    err = capfd.readouterr().err
    assert "hello" in err
    assert "WARNING" in err
