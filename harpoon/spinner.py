"""Spinning loading animation for long-running tasks."""
import itertools
import sys
import threading
import time

SPINNER_CHARS = "|/-\\"


def run_with_spinner(prefix: str, fn, *args, **kwargs):
    """Run fn; show spinner in background until it completes. Return fn's result."""
    result = [None]
    exception = [None]

    def target():
        try:
            result[0] = fn(*args, **kwargs)
        except Exception as e:
            exception[0] = e

    thread = threading.Thread(target=target, daemon=True)
    thread.start()

    write = sys.stdout.write
    flush = sys.stdout.flush
    for c in itertools.cycle(SPINNER_CHARS):
        if not thread.is_alive():
            break
        write(f"\r{prefix}{c} ")
        flush()
        time.sleep(0.1)

    write("\r" + " " * (len(prefix) + 2) + "\r")
    flush()
    thread.join()
    if exception[0]:
        raise exception[0]
    return result[0]
