import os
import tempfile

import pandas as pd

from src.benchmark.visualize import generate_all_charts


def _minimal_csv(path: str) -> None:
    rows = []
    algos = ["ASCON-AEAD128", "AES-128-GCM", "SPECK-128/128-CTR-HMAC", "PRESENT-80-CTR-HMAC"]
    for algo in algos:
        for size in (16, 256, 1024):
            rows.append(
                {
                    "algorithm": algo,
                    "payload_bytes": size,
                    "iterations": 100,
                    "avg_encrypt_us": 10.0 + hash(algo + str(size)) % 50,
                    "avg_decrypt_us": 9.0 + hash(algo) % 40,
                    "throughput_kbps": float(size),
                    "enc_peak_mem_kb": 64.0,
                    "dec_peak_mem_kb": 62.0,
                }
            )
    pd.DataFrame(rows).to_csv(path, index=False)


def test_generate_all_charts_writes_pngs():
    with tempfile.TemporaryDirectory() as tmp:
        csv_path = os.path.join(tmp, "bench.csv")
        out_dir = os.path.join(tmp, "out")
        _minimal_csv(csv_path)
        paths = generate_all_charts(csv_path, out_dir)
        assert len(paths) == 6
        for p in paths:
            assert os.path.isfile(p)
            assert os.path.getsize(p) > 1000
