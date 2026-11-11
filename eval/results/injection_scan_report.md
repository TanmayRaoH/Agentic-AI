# Output injection scanner (F14): dev-corpus measurement

- Known injection samples: 33; flagged or quarantined: 33; quarantined: 18.
- Missed: none
- Benign pages: 38; quarantined (false positives): 1 = 2.6%; flagged only: 1 = 2.6%.

Benign pages quarantined:
- prompt-injection-article: score 0.9, families ['override_phrase']

Benign pages flagged:
- report-bug: score 0.7, families ['exfil_verb_target']

These corpora were used while tuning the weights, so the numbers are optimistic; the held-out set (Phase 7) is the honest measurement.
