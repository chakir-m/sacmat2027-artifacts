# Sources (your working copy, not for upload)

- `sacmat_10p/`: the 10-page SACMAT submission, self-contained (all proofs inside, in the body or in Appendix B). `pdflatex main_anon; bibtex main_anon; pdflatex main_anon; pdflatex main_anon` builds the anonymous PDF; `main` builds the working draft with the system name and author notes.
- `extended_for_journal/`: the 24-page extended version, kept for a later journal version (e.g. ACM TOPS). It is not part of the submission.

Both `main.tex` files contain the AI-use acknowledgement commented out, for the camera-ready decision.
