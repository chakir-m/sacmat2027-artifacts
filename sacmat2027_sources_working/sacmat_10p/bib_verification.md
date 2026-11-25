# Bibliography verification (references.bib, Phase 3)

**Status key**
- **V**: authors, title, venue and year, plus DOI where listed, confirmed against a primary record: a publisher or DOI landing page, an official proceedings or table-of-contents page, an institutional repository, NIST or OASIS, or an author or vendor page.
- **V\***: confirmed, but one field came from a secondary index; the note says which.
- **Not cited**: an entry kept in the `.bib` file but not cited, so BibTeX omits it.

**Rule (PHASE 3).** The paper cites only entries marked V or V\*.

## Entries

| Key | Status | Verified against / note |
|---|---|---|
| rose2020zta | V | csrc.nist.gov SP 800-207 page: four authors, Aug 2020, DOI. |
| chandramouli2023sp800207a | V | nist.gov PDF. |
| kerman2025sp180035 | V | nist.gov citation record. |
| hu2014sp800162 | V | nist.gov publication page: seven authors, SP 800-162. The page shows the 2019 update date; the original issue is Jan 2014, which is what we cite. |
| ferraiolo2016sp800178 | V | csrc.nist.gov. |
| oasis2013xacml | V | oasis-open.org announcement: XACML 3.0 OASIS Standard, 22 Jan 2013. |
| saltzer1975protection | V\* | MIT author page (title, authors). Venue, pages and DOI 10.1109/PROC.1975.9939 from the Wikipedia article's citation, which carries the DOI. |
| jin2012abac | V | Utah LNCS 7371 bibliography index: authors, pp. 41–55, DOI 10.1007/978-3-642-31540-4_4. |
| bertino2001trbac, park2004ucon | V | tissec.bib index (Phase 2). |
| cheng2007fuzzymls, ameer2022bluesky | V | Phase 2. |
| fisler2005margrave, hu2011anomaly, turkmen2017xacmlsmt, backes2018zelkova | V | Phase 2. |
| cutler2024cedar, disselkoen2024vgd, pang2019zanzibar | V | Phase 2. |
| crampton2006saam, wei2008recycling, martin2007mutation | V | Phase 2. |
| mouelhi2008models | V | SINTEF record (MoDELS 2008, Springer, pp. 537–552). Full author list and DOI 10.1007/978-3-540-87875-9_38 from the dblp-derived MoDELS 2008 listing. |
| claessen2000quickcheck | V | Chalmers research portal: ICFP'00, pp. 268–279. The DOI was removed: the portal gives the SIGPLAN Notices DOI, not the proceedings DOI. |
| maciver2019hypothesis | V | JOSS (Phase 2). |
| jackson2012alloy | V\* | MIT ILP page: author, title, revised edition. Publisher (MIT Press) and year 2012 from bookseller records, ISBN 9780262017152. |
| xiang2025actest, son2011rolecast, monshizadeh2014mace, vatsa2025synth, vatsa2026autocedar | V | Phase 2. |
| demoura2008z3 | V | Microsoft Research publication page: TACAS 2008, pp. 337–340, DOI 10.1007/978-3-540-78800-3_24. |
| wolper1986 | V | POPL '86 table of contents (dblp mirror): pp. 184–193, DOI 10.1145/512644.512661. |
| lazic2003semantic | V | Warwick WRAP records 9389 (TLCA 2003, LNCS 2701, pp. 226–240) and 61244 (authors). |
| cedarexamples | V | Cloned repository, commit f4d2dbb (2026-10-23). |
| backstagerbac | V | npm registry metadata (8.1.6) and the installed package. |
| backstageauth | V | npm README of @backstage/plugin-auth-backend: default token expiration of one hour, allowed range 10 min to 24 h. |
| openfga | V | Release binary v1.22.1 downloaded from the project's GitHub releases; `openfga version` reports build 44054f5. Behaviour of `--check-query-cache-enabled`, `--cache-controller-enabled` and HIGHER_CONSISTENCY measured directly (`wp3/openfga.json`). |
| servos2017abac | Not cited | ACM DL could not be reached from the workspace. Removed from the paper. |
| mckeeman1998differential | Not cited | No primary record reachable. Removed from the paper. |
| sandhu1996rbac, bell1976blp | Not cited | — |

## Removed in earlier phases

See the Phase-2 notes: `heiding2023penetration`, `sachdeva2023llm`, `rose2023zta_implementation`, `cedar2023` and others.

## Phase 4

No reference was added or removed. The Phase 4 paper cites the same 38 keys as the Phase 3c paper, and `references.bib` is byte-identical to the Phase 3c file. Zanzibar (pang2019zanzibar) is compared only through statements in its paper; no Zanzibar behaviour was measured.

## Phase 5 (2026-11-19)

| Key | Status | Primary record |
|---|---|---|
| xiang2025actest | Corrected | Author order fixed to Xiang, Zhong, Mugnier, Nguyen, Zhou, Xu, as on the arXiv HTML record of 2505.12770v1. |
| schneider2000enforceable | V (added) | ACM TISSEC 3(1), Feb. 2000, pp. 30–50, DOI 10.1145/353323.353382: Scilit record of the DOI (journal, volume, issue, pages, date), CPS-VO record (author, DOI), and the author's Cornell CS513 lecture notes (citation "ACM Transactions on Information and System Security 3, 1 (February 2000), 30--50"). The ACM DL itself was not reachable from the workspace. |
| herlihy1990linearizability | V (added, no DOI) | Author-hosted PDF of the article (cs.columbia.edu/~wing/publications/HerlihyWing90.pdf): ACM TOPLAS 12(3), July 1990, pp. 463–492, copyright line "1990 ACM 0164-0925/90/0700-0463". The DOI could not be confirmed from a primary record, so the entry has none. |

## Phase 6 (22 November 2026)

| Key | Checked against | Result |
|---|---|---|
| `liu2025bacscan` | CCS '25 author PDF (yuanxzhang.github.io/paper/bacscan-ccs25.pdf) and the authors' repository BibTeX | Liu, Zhang, Li, Meng, Shi, Wang, Wang, Lin, Yang; *BACScan: Automatic Black-Box Detection of Broken-Access-Control Vulnerabilities in Web Applications*; CCS '25, pp. 1320–1333; DOI 10.1145/3719027.3744825. Matches. |
| `dharmaadi2025bacfuzz` | arXiv abstract page 2507.15984 | Dharmaadi, Alhanahnah, Pham, Mohsen, Turkmen; *BACFuzz: Exposing the Silence on Broken Access Control Vulnerabilities in Web Applications*; arXiv, 21 July 2025. No venue publication found; cited as a preprint. |

## Phase 7 (10-page version, final)

- The 10-page version is self-contained: it no longer cites an extended version, and the `extended` entry has been removed.
- All cited keys are a subset of the phase-6 keys verified above.
