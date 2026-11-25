# SACMAT 2027 (Cycle 2): submission checklist

## What is in this folder

| File | Use | Upload? |
|---|---|---|
| `SACMAT2027_submission_anonymous.pdf` | The paper to submit: 10 pages of body, plus references and Appendices A–C (12 pages in total). Includes the artifact link. | **Yes, as the paper** |
| `sacmat2027_supplementary_anonymous.zip` | Anonymous artifact: the paper, scripts, raw results, 13 v2 patches and a README. It contains no names. It is the same content as the anonymous repository. | **Yes, only if HotCRP has a supplementary-material field** |
| `SACMAT2027_working_draft.pdf` | The same paper with the author placeholders and red author notes visible. For you only. | No |
| `sacmat2027_sources_working.zip` | LaTeX sources of the 10-page paper, and of the 24-page extended version kept for a later journal version. The commented AI acknowledgement is in `main.tex`. | No |
| `extended_version_for_journal_anonymous.pdf` | The 24-page extended version, for a later journal version (for example ACM TOPS), after SACMAT. | No |
| `final_version_changes.md` | What changed in this final version. | No |

Artifact link (already in Appendix C): https://anonymous.4open.science/r/sacmat2027-artifacts-4DCC/

## Before 12 February 2027 (AoE)

1. **Human review.** Have at least one reader who works in access control read the submission PDF. Content changes only if they find a real problem.
2. **System name (OpenZTAC) stays unfindable until 29 March 2027.**
   - Keep the code repository private.
   - Check that `henceforth.co.ma` is offline or does not display "OpenZTAC".
   - Do not post a preprint or slides that use the name.
3. **Anonymous repository:**
   - Open the link in a private browser window and check that the files are visible and that no name, username or email appears.
   - Replace `paper/submission_anonymous.pdf` in your GitHub repository with the new PDF from this folder (OpenZTAC name, new conclusion, link included).
   - Make sure the expiry date is after camera-ready (May 2027).
   - Do not change the repository after the deadline.
4. **Recheck the call for papers** in late January (https://www.sacmat.org/2027/call-for-papers.php) for any change in page limits, anonymity rules or required sections.

## On HotCRP: https://sacmat27-cycle2.hotcrp.com/

1. Create your account, and add the ORCID iDs for all authors (the CFP asks for them).
2. Fill in:
   - the title: *Beyond the Decision Point: Layered Conformance Checking of a Zero-Trust ABAC System*;
   - the abstract, copied from the PDF;
   - the authors (reviewers do not see them);
   - the topics;
   - the conflicts of interest.
3. Upload `SACMAT2027_submission_anonymous.pdf`.
4. If there is a supplementary-material field, upload `sacmat2027_supplementary_anonymous.zip`.
5. Submit before **12 February 2027, 23:59 AoE**. The notification is expected on 29 March 2027.

## If the paper is accepted (camera-ready by 3 May 2027)

- Build `main` instead of `main_anon`, then fill in the author names and affiliations (the red `\TODO` notes).
- If you release the code, you can call the system open-source again and add the public link.
- Decide on the AI-use acknowledgement. ACM's policy on generative AI asks for disclosure; the text is ready, commented out in `main.tex`.
- Replace the anonymous link with the public repository. If you wish, add the frozen v1 snapshot.
- Complete the ACM rights form and the open-access fee (APC), unless your institution is part of ACM Open.
- One author registers and presents in person (Durham, UK, 19–21 July 2027).

## Afterwards

- Prepare the extended journal version (for example ACM TOPS) from `extended_for_journal/`. Journals usually require substantial new material beyond the conference paper, so check the journal's rules.
