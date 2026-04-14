import statistics


def ns_to_us(value_ns: int | float) -> float:
    return float(value_ns) / 1000.0


def bytes_per_second_to_kilobytes_per_second(value_bps: float) -> float:
    return value_bps / 1024.0


def mean_and_stdev(values: list[float]) -> tuple[float, float]:
    if not values:
        return 0.0, 0.0
    if len(values) == 1:
        return values[0], 0.0
    return statistics.mean(values), statistics.stdev(values)
