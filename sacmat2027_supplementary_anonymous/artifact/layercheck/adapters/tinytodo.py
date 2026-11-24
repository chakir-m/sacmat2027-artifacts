"""TinyTodo adapter (HTTP). Reuses the server lifecycle of ../../wp3_tinytodo.py."""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))


def load(src, binary, work):
    sys.argv = [sys.argv[0], src, binary, work, os.devnull]
    import wp3_tinytodo as T
    return T
