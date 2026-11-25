"""L2: staleness-window measurement with the bounded-staleness prediction (Theorem 3)."""
import time


def measure_window(decide, end_grant, poll=0.25, limit=200.0):
    """Call end_grant() (revocation commit, or wait for expiry), then poll decide() until it
    denies. Returns (window_s, allows_after_end). decide() -> True iff allow."""
    end_grant()
    t0 = time.monotonic(); allows = 0
    while time.monotonic() - t0 <= limit:
        if not decide():
            return round(time.monotonic() - t0, 3), allows
        allows += 1
        time.sleep(poll)
    return None, allows


def predicted_window(tau, delta, invalidated_after_commit):
    """Theorem 3: tau - delta if the end of the grant does not invalidate the cached copy,
    0 (up to the invalidation latency) if it is invalidated after commit."""
    return 0.0 if invalidated_after_commit else max(0.0, tau - delta)
