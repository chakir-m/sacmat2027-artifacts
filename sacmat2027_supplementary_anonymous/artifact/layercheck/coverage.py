"""Coverage of a bounded world space against all satisfiable observation vectors (Theorem 2).
CHAIN-9 instance: ../wp1_coverage.py (run as a script; its satisfiable_vectors/realised_vectors
are the reusable parts and take the atom encoding as their only system-specific input)."""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check_chain9(out_dir, python=sys.executable):
    subprocess.run([python, os.path.join(HERE, "wp1_coverage.py"), out_dir], check=True, capture_output=True)
    return json.load(open(os.path.join(out_dir, "wp1_coverage.json")))
