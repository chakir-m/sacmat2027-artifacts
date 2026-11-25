"""Criterion G (data independence), generic driver. The CHAIN-9 configuration (sort map,
target functions, helpers) is in ../wp1_genericity_check.py; this module exposes it as a
function so other Python PDPs can be checked by supplying their own configuration."""
import json, os, subprocess, sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check_python_pdp(pdp_path, helper_path, out_json, python=sys.executable):
    r = subprocess.run([python, os.path.join(HERE, "wp1_genericity_check.py"), pdp_path, helper_path, out_json],
                       capture_output=True, text=True)
    return r.returncode == 0, json.load(open(out_json))
