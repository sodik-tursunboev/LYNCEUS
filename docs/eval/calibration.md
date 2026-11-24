# Calibration of the verdict bands (DA5 phase 3, item 4)

2026-11-22 20:33Z. Engine and rules: `1.0.0|1.5.0+ffe8541c40ee|domain-lr-3+lynceus-da5-refit|cc9937a0`. Offline: nothing was opened or fetched. **Likelihoods, not probabilities.** For each band the table gives the *detection rate* (the share of phishing samples that land in the band) and the *false-alarm rate* (the share of legitimate samples that land in it), each with its Wilson 95% interval, measured on a fitting half and again on a held-out half that the fit never saw. The sets are about half phishing and a person's traffic is a tiny fraction, so "how often is a page in this band phishing" measured here would mean nothing; it is shown only as an illustration at an assumed prevalence of 1 in 1,000.

**Criterion** (fixed before measuring, not loosened): for every band with at least 30 samples (phishing and legitimate together) in both halves, both rates on the fitting half must reproduce on the held-out half within 0.05 absolute. `python -m eval.calibrate check` re-computes it from `calibration.json`.

**Result: CALIBRATION MET.**

## D1: the address plus the opened page

Fitting half = dev split (394 phishing, 476 legitimate); held-out half = test split (406 phishing, 522 legitimate).

### By state and confidence tier

| band | samples fit / held | detection, fit | detection, held-out | gap | false alarm, fit | false alarm, held-out | gap | checked |
|---|---|---|---|---|---|---|---|---|
| MALICIOUS HIGH | 9 / 11 | 2.28% (1.21 to 4.28) | 2.71% (1.52 to 4.79) | 0.004 | 0.000% (0.000 to 0.801) | 0.000% (0.000 to 0.731) | 0.000 | no, under 30 |
| MALICIOUS MEDIUM | 29 / 30 | 7.36% (5.17 to 10.37) | 7.39% (5.22 to 10.35) | 0.000 | 0.000% (0.000 to 0.801) | 0.000% (0.000 to 0.731) | 0.000 | no, under 30 |
| SUSPICIOUS LOW | 269 / 257 | 66.8% (62.0 to 71.2) | 62.6% (57.8 to 67.1) | 0.042 | 1.26% (0.58 to 2.72) | 0.575% (0.196 to 1.676) | 0.007 | yes |
| BENIGN HIGH | 49 / 58 | 0.000% (0.000 to 0.966) | 0.000% (0.000 to 0.937) | 0.000 | 10.3% (7.9 to 13.3) | 11.1% (8.7 to 14.1) | 0.008 | yes |
| UNKNOWN LOW | 514 / 572 | 23.6% (19.7 to 28.0) | 27.3% (23.2 to 31.9) | 0.037 | 88.4% (85.3 to 91.0) | 88.3% (85.3 to 90.8) | 0.001 | yes |

### By score band

| band | samples fit / held | detection, fit | detection, held-out | gap | false alarm, fit | false alarm, held-out | gap | checked |
|---|---|---|---|---|---|---|---|---|
| score 0-44 | 49 / 58 | 0.000% (0.000 to 0.966) | 0.000% (0.000 to 0.937) | 0.000 | 10.3% (7.9 to 13.3) | 11.1% (8.7 to 14.1) | 0.008 | yes |
| score 45-59 | 130 / 136 | 32.7% (28.3 to 37.5) | 33.0% (28.6 to 37.7) | 0.003 | 0.210% (0.037 to 1.180) | 0.383% (0.105 to 1.386) | 0.002 | yes |
| score 60-79 | 126 / 108 | 31.2% (26.8 to 36.0) | 26.6% (22.5 to 31.1) | 0.046 | 0.630% (0.215 to 1.836) | 0.000% (0.000 to 0.731) | 0.006 | yes |
| score 80-94 | 39 / 40 | 9.39% (6.89 to 12.68) | 9.61% (7.11 to 12.86) | 0.002 | 0.420% (0.115 to 1.519) | 0.192% (0.034 to 1.077) | 0.002 | yes |
| score 95-100 | 12 / 14 | 3.05% (1.75 to 5.25) | 3.45% (2.07 to 5.70) | 0.004 | 0.000% (0.000 to 0.801) | 0.000% (0.000 to 0.731) | 0.000 | no, under 30 |
| unscored | 514 / 572 | 23.6% (19.7 to 28.0) | 27.3% (23.2 to 31.9) | 0.037 | 88.4% (85.3 to 91.0) | 88.3% (85.3 to 90.8) | 0.001 | yes |

### Illustration: P(phishing | tier) at an assumed 1 in 1,000 (fitting half)

Bayes from the two likelihoods above; **an illustration, not a measurement**: the prevalence is assumed, and the legitimate samples are not a person's real traffic. The conservative column uses the low end of the detection interval and the high end of the false-alarm interval.

| tier | likelihood ratio (detection / false alarm) | P(phishing) at the assumed prevalence | conservative |
|---|---|---|---|
| MALICIOUS HIGH | no legitimate sample (unbounded) | undefined (no legitimate sample) | 0.15% |
| MALICIOUS MEDIUM | no legitimate sample (unbounded) | undefined (no legitimate sample) | 0.64% |
| SUSPICIOUS LOW | 53.0 | 5.03% | 2.23% |
| BENIGN HIGH | n/a (no phishing in the band) | 0 | 0 |
| UNKNOWN LOW | 0.3 | 0.03% | 0.02% |

### Split overlap

The splits cut by address, not by registered domain, so one domain can sit in both halves. Held-out samples whose registered domain is also in the fitting half: phishing 19.2% (15.7 to 23.3), legitimate 0.578% (0.197 to 1.685). The more of this, the kinder the held-out half is to the fit.

## E1: the address engine alone

Fitting half = train split (88,938 phishing, 110,638 legitimate); held-out half = test split (44,257 phishing, 55,632 legitimate).

### By state and confidence tier

| band | samples fit / held | detection, fit | detection, held-out | gap | false alarm, fit | false alarm, held-out | gap | checked |
|---|---|---|---|---|---|---|---|---|
| MALICIOUS HIGH | 5 / 2 | 0.006% (0.002 to 0.013) | 0.005% (0.001 to 0.017) | 0.000 | 0.000% (0.000 to 0.003) | 0.000% (0.000 to 0.007) | 0.000 | no, under 30 |
| MALICIOUS MEDIUM | 700 / 325 | 0.787% (0.731 to 0.847) | 0.734% (0.659 to 0.818) | 0.001 | 0.000% (0.000 to 0.003) | 0.000% (0.000 to 0.007) | 0.000 | yes |
| SUSPICIOUS LOW | 29,812 / 15,019 | 33.4% (33.1 to 33.7) | 33.8% (33.4 to 34.3) | 0.004 | 0.103% (0.086 to 0.124) | 0.095% (0.073 to 0.125) | 0.000 | yes |
| SUSPICIOUS MEDIUM | 110 / 54 | 0.124% (0.103 to 0.149) | 0.122% (0.093 to 0.159) | 0.000 | 0.000% (0.000 to 0.003) | 0.000% (0.000 to 0.007) | 0.000 | yes |
| BENIGN HIGH | 1,056 / 511 | 1.02% (0.95 to 1.08) | 1.00% (0.91 to 1.10) | 0.000 | 0.138% (0.118 to 0.162) | 0.122% (0.096 to 0.155) | 0.000 | yes |
| UNKNOWN LOW | 167,893 / 83,978 | 64.7% (64.4 to 65.0) | 64.3% (63.9 to 64.8) | 0.004 | 99.8% (99.7 to 99.8) | 99.8% (99.7 to 99.8) | 0.000 | yes |

### By score band

| band | samples fit / held | detection, fit | detection, held-out | gap | false alarm, fit | false alarm, held-out | gap | checked |
|---|---|---|---|---|---|---|---|---|
| score 0-44 | 1,056 / 511 | 1.02% (0.95 to 1.08) | 1.00% (0.91 to 1.10) | 0.000 | 0.138% (0.118 to 0.162) | 0.122% (0.096 to 0.155) | 0.000 | yes |
| score 45-59 | 26,908 / 13,527 | 30.2% (29.9 to 30.5) | 30.5% (30.1 to 30.9) | 0.003 | 0.076% (0.061 to 0.094) | 0.068% (0.050 to 0.094) | 0.000 | yes |
| score 60-79 | 3,000 / 1,540 | 3.34% (3.22 to 3.46) | 3.45% (3.28 to 3.62) | 0.001 | 0.027% (0.019 to 0.039) | 0.027% (0.016 to 0.044) | 0.000 | yes |
| score 80-94 | 718 / 332 | 0.807% (0.751 to 0.868) | 0.750% (0.674 to 0.835) | 0.001 | 0.000% (0.000 to 0.003) | 0.000% (0.000 to 0.007) | 0.000 | yes |
| score 95-100 | 1 / 1 | 0.001% (0.000 to 0.006) | 0.002% (0.000 to 0.013) | 0.000 | 0.000% (0.000 to 0.003) | 0.000% (0.000 to 0.007) | 0.000 | no, under 30 |
| unscored | 167,893 / 83,978 | 64.7% (64.4 to 65.0) | 64.3% (63.9 to 64.8) | 0.004 | 99.8% (99.7 to 99.8) | 99.8% (99.7 to 99.8) | 0.000 | yes |

### Illustration: P(phishing | tier) at an assumed 1 in 1,000 (fitting half)

Bayes from the two likelihoods above; **an illustration, not a measurement**: the prevalence is assumed, and the legitimate samples are not a person's real traffic. The conservative column uses the low end of the detection interval and the high end of the false-alarm interval.

| tier | likelihood ratio (detection / false alarm) | P(phishing) at the assumed prevalence | conservative |
|---|---|---|---|
| MALICIOUS HIGH | no legitimate sample (unbounded) | undefined (no legitimate sample) | 0.07% |
| MALICIOUS MEDIUM | no legitimate sample (unbounded) | undefined (no legitimate sample) | 17.29% |
| SUSPICIOUS LOW | 324.2 | 24.50% | 21.10% |
| SUSPICIOUS MEDIUM | no legitimate sample (unbounded) | undefined (no legitimate sample) | 2.85% |
| BENIGN HIGH | 7.3 | 0.73% | 0.58% |
| UNKNOWN LOW | 0.6 | 0.06% | 0.06% |

### Split overlap

The splits cut by address, not by registered domain, so one domain can sit in both halves. Held-out samples whose registered domain is also in the fitting half: phishing 47.3% (46.8 to 47.7), legitimate 6.44% (6.23 to 6.64). The more of this, the kinder the held-out half is to the fit.

## Robustness: held-out samples on domains the fitting half never saw

The same criterion with every held-out sample that shares a registered domain with the fitting half removed (left: D1 328 phishing and 519 legitimate, E1 23,536 phishing and 52,058 legitimate). It is not the criterion above and `check` does not read it; it shows how much the address-level split flatters the result. Dropping the overlap also drops the repeat domains (shared hosts, mass-made names), so what remains is a different mix and not only an unseen one: a gap here means the rates depend on which domains a half holds, not necessarily that the engine is worse on a domain it has not met.

**Same criterion on those: NOT MET** (4 failing):
- e1 score 'score 45-59' detection: fit 0.3016, held-out 0.4774, gap 0.1758
- e1 score 'unscored' detection: fit 0.6468, held-out 0.4594, gap 0.1873
- e1 tier 'SUSPICIOUS LOW' detection: fit 0.3339, held-out 0.5285, gap 0.1945
- e1 tier 'UNKNOWN LOW' detection: fit 0.6468, held-out 0.4594, gap 0.1873

## What this does not show

- In this table "false alarm" is only the share of legitimate samples in the band. In a SUSPICIOUS or MALICIOUS band that is a false alarm; in BENIGN or UNKNOWN it is the share of legitimate samples that got that answer, which is what a legitimate page should get.
- A 0.05 absolute gap is wide for a band holding a small share of a class (under 5%): such a band passes the criterion by construction. Only the large bands (the UNKNOWN tier, SUSPICIOUS LOW, the 45-59 score band) are tested hard; for the others read the intervals.
- The legitimate sets are not a person's traffic: E1's are home pages of popular sites, an older dataset and 92 pages of one person's history; D1's are popular home pages and /login. A person's deep links are warned more often (DA2, `docs/eval/deeplinks.md`). The false-alarm rates are those of these sets only.
- D1 is small and live; its halves are noisy, so a band can miss the 0.05 criterion from sampling noise alone. The intervals show how much. Read the gap against them.
- UNKNOWN and ERROR carry no score; they are their own tier and the `unscored` band, never a low score.
- Mail and downloaded files are not in these sets (the mail corpus has 73 phishing and no legitimate false alarm, too few for bands); the ask table below treats them by rule, not by measurement.

## The ask table (`core/risk/asktable.py`)

**Not wired into the agent, the extension or the API in this version.** It is the table, its rules and its tests: a pure function (state, confidence tier, source, whether every provider answered, familiarity fixed to `unknown`) to a loudness (`interrupt`, `ask_once`, `banner`, `log`). Only loudness changes, never a state or a score. Hard rules, enforced by `tests/unit/test_ask_table.py`: a MALICIOUS verdict with two strong categories is never quieter than a banner (browser: interrupt); automatic responses never apply to mail or to SUSPICIOUS; UNKNOWN is logged at least and, when a provider did not answer, shown. SUSPICIOUS at LOW confidence (one strong category, the tier where the false alarms sit in the tables above) gets a banner and the two-category tiers a question; the numbers inform the table, they do not drive it at run time. An incomplete provider answer raises UNKNOWN and ERROR to at least a banner. The table (provider answers complete; confidence LOW / MEDIUM / HIGH):

| state | source | LOW | MEDIUM | HIGH |
|---|---|---|---|---|
| MALICIOUS | browser | banner | interrupt | interrupt |
| MALICIOUS | download | banner | ask_once | interrupt |
| MALICIOUS | mail | banner | ask_once | ask_once |
| SUSPICIOUS | browser | banner | ask_once | ask_once |
| SUSPICIOUS | download | log | banner | banner |
| SUSPICIOUS | mail | log | banner | banner |
| BENIGN | browser | log | log | log |
| BENIGN | download | log | log | log |
| BENIGN | mail | log | log | log |
| UNKNOWN | browser | log | log | log |
| UNKNOWN | download | log | log | log |
| UNKNOWN | mail | log | log | log |
| ERROR | browser | banner | banner | banner |
| ERROR | download | banner | banner | banner |
| ERROR | mail | log | log | log |
