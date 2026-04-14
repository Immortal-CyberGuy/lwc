class ReplayGuard:
    """Sliding-window anti-replay (RFC 4303 style)."""

    def __init__(self, window_size=64):
        self.window_size = window_size
        self.highest_seq = 0
        self.bitmap = 0

    def check_and_update(self, seq_num: int) -> bool:
        """Return True if packet is fresh, False if replay or invalid."""
        if seq_num == 0:
            return False
        if seq_num > self.highest_seq:
            shift = seq_num - self.highest_seq
            if shift >= self.window_size:
                self.bitmap = 1
            else:
                self.bitmap = (self.bitmap << shift) | 1
            self.highest_seq = seq_num
            return True
        diff = self.highest_seq - seq_num
        if diff >= self.window_size:
            return False
        bit = 1 << diff
        if self.bitmap & bit:
            return False
        self.bitmap |= bit
        return True
