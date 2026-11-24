# Supplementary material

- `paper/submission_anonymous.pdf`: the submitted paper.
- `artifact/`: every script. **Start with `artifact/REPRODUCE.md`**, which explains how to re-run each experiment, with the command, the expected numbers and the running time. `artifact/README.md` describes each script.
- `results/phase3/` to `results/phase6/` and `artifact/results/`: the raw outputs of every run reported. `results/phase6/summary_phase6.json` collects the final numbers.
- `fork-patches/`: thirteen patches that turn the frozen snapshot of the system (v1) into v2 (`git am`); patch 0013 is the final v2. Patch 0005 adds a switch used only by the cost ablation; it is off by default.

The frozen snapshot of v1 is not included, to preserve anonymity; it is identified by the SHA-256 prefix given in the paper. The code and the artifact call the employee role `analyst`.
