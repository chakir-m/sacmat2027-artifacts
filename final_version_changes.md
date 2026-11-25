# SACMAT 2027: final 10-page version, what changed

**Files**
- Anonymous build: `sacmat_10p_final_anonymous.pdf`, 12 pages.
- Working build: `sacmat_10p_final_working.pdf`.

**Page limits**
- The body ends at the bottom of page 10.
- References and Appendices A–C fill pages 10 (end) to 12, within the 2-page allowance.

**Build checks**
- 0 errors, 0 overfull boxes, 0 undefined references.
- Anonymity grep is clean.
- Every number in the paper also appears in the verified long version. A script checked this; the only exceptions are two layout lengths.

**Self-containment**
- The paper no longer cites or depends on the extended version.
- Every theorem and proposition has a complete proof, either right after it or in Appendix B.

## Restored

**Section 3 (system and model)**
- Notation paragraph.
- Definition 3.1 State: attribute functions, assignment and delegation relations, other state parts.
- Grant-set equations for G^asg and G^del.
- Risk-score formula ρ(u,c) and threshold θ.
- Definitions of sameDept, sameDiv and sameDiv°.
- Definition 3.2 Rule chain, with first-applicable semantics.
- Definition 3.3 Routes.
- Definition 3.4 Runs, with all six event kinds and well-formedness W1–W3.

**Section 4 (threat model)**
- Definition 4.1 Adversary, with Cap1–Cap4.
- Definition 4.2 Attack goals, with G1–G5.
- Historical reading of G1/G2.

**Section 5 (layered conformance)**
- Full Definition 5.1, including L2⁺ and L2ᶜ.
- Full proof of Theorem 5.2 (composition).
- Proposition 5.3 (independence) moved here from the discussion, with its proof.

**Section 6 (method)**
- Criterion G (a)–(e).
- Lemma 6.1, with its proof.
- Theorem 6.2, with its proof.
- Theorem 6.3, with its proof.
- **Proposition 6.4 (mixed views)**, now a formal proposition with the concrete run as its proof.
- **Proposition 6.5 (single witness)**, with its proof.

**Section 7 (evaluation)**
- Proofs of Theorem 7.1, Proposition 7.2 and Proposition 7.3.
- Proposition 7.2 states the decision projection π_d, and adds the note that the deciding rule can differ.
- Proof of Proposition 7.4 (freshness of the v2 cache).
- **Figure 2:** the running example traced rule by rule for v1 and v2, replacing the small table.
- **Figure 4:** why the v2 cache closes the race.

**Appendix B (new): Proofs**
- Lemma 6.1, Theorem 6.3, Propositions 6.5 and 5.3, Theorem 7.1, Proposition 7.4.
- The two statements that also need proofs in the body, Theorem 5.2 and Theorem 6.2, have them there.

## Cut or shortened to make room (no finding or number about the system was removed)

**Tables**
- The related-work table: the text already covers it.
- The comparison table is now one column wide, with systems as rows and L1/L2/L3 as columns.
- From the comparison table:
  - the Zanzibar row (it was a design, not a measurement; Zanzibar is now mentioned in the text);
  - the "Model" and "Freshness design" rows;
  - TinyTodo's policy-reload time (0.12–0.90 s). The TinyTodo failure (the new `forbid` was never enforced, 20/20) stays.

**Figures**
- The running-example figure lost its organisation chart (Finance/Legal, Ana/Dan/Lea). The organisation is described in the text.

**Text**
- The ten seeded G violations: the full list is replaced by "from … to …". The 10 seeded, 3 initially accepted and all 10 flagged counts stay.
- The earlier two-run cost measurement (16–25 % for decisions on another machine) is dropped. The paper never reported it as a result.
- The ledger retention-job crash (part of F10) is dropped.
- Two lines from the discussion: "we would write the threat model before the chain", and part of the generality caveats (data-dependent context construction).
- Shorter wording throughout: abstract, contributions (now a numbered paragraph), RQ3, RQ4, RQ5, the five answer boxes, discussion and conclusion.

**Other fixes**
- The undefined labels E1 and E1b are replaced by "L1 check" and "cold-cache oracle".
- The RQ3 answer no longer says "only two routes ask the PDP". It now says "only the decision API and the file endpoints".
- Fixed a double period after "Paths around the PDP".

## Supplementary package

`sacmat2027_supplementary_anonymous.zip` now contains only:
- the paper;
- the artifact;
- the results;
- the 13 patches;
- a README.

The extended version is no longer in it. It stays in your sources package as `extended_for_journal/`, for a later journal version.
<<<<<<< HEAD

## Update of 25 November 2026

- **System name:** the submission now uses **OpenZTAC** instead of "Atrium". "Atrium" collides with CDVI's ATRIUM physical access-control product. OpenZTAC is not public, and you confirmed it is used only locally. The extended version uses OpenZTAC too.
  - Keep the repository private, and make sure `henceforth.co.ma` does not publicly show the name, until the decision (29 March 2027).
- **Wording:**
  - "an open-source ZTA/ABAC system" became "a ZTA/ABAC system we built", because the code is not public.
  - "designed, built and deployed" became "designed and built", and "and deployed it" became "and ran it".
- **Conclusion:** there is a new second paragraph, *what a zero-trust deployment should be asked to show*. It proposes a per-deployment contract in three parts: a rule-level proof or complete check, a declared staleness bound Δ with its measurement, and a generated route inventory with its probes. It cites NIST SP 800-207 and Cedar.
- **To make room** (no result removed):
  - From the RQ5 "Other authorization systems" paragraph:
    - the TinyTodo and Backstage sentence, whose results are in Table 7; the Backstage citation moved into the table;
    - the Zanzibar clause; Zanzibar is still discussed in the related work and the conclusion.
  - Shorter sentences:
    - the "Generality" paragraph;
    - the "Why our proofs did not catch this" paragraph;
    - the Approach paragraph;
    - the running-example paragraph;
    - one sentence each in the related work, Section 4, Section 5 and RQ2.
  - The section references in the contributions paragraph were removed.
  - The L2 figure is 6 % smaller.
- **Checks:**
  - The body ends at the bottom of page 10, and references and appendices fill pages 11–12 (12 pages in total).
  - 0 errors, 0 overfull boxes, 0 undefined references.
  - Every number in the paper also appears in the verified long version.
=======
>>>>>>> 42fa364aea261fae9fc6322d2fbffae1eb27feb4
