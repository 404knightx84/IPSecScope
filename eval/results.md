| Check | Goal | Measured | Pass |
|---|---|---|---|
| Parsing vs tshark/log/config | no check fails; skips listed | 1358 pass, 0 fail, 0 skipped over 172 runs | yes |
| Cipher family: confidently wrong runs | 0 | 0 of 160 base runs; wrong but flagged 4 | yes |
| Mode: wrong answers (leave-one-config-out) | 0 wrong | 1.0 on 95/160 answered, coverage 0.594, baseline 0.5 | yes |
| PFS: wrong answers (leave-one-config-out) | 0 wrong | 1.0 on 160/160 answered, coverage 1.0 | yes |
| Traffic: held-out repeat 4 (run level) | report accuracy per mode | acc 1.0, macro F1 1.0, wrong runs 0 | n/a |
| Traffic: held-out repeat 4 (window level, all) | report accuracy per mode | acc 0.8652, macro F1 0.8671, n 957 | n/a |
| Traffic: held-out repeat 4 (window level, tunnel) | report accuracy per mode | acc 0.8574, macro F1 0.8593, n 477 | n/a |
| Traffic: held-out repeat 4 (window level, transport) | report accuracy per mode | acc 0.8729, macro F1 0.8748, n 480 | n/a |
| Severity floor W1 | High or Critical | Counter({'Critical': 6}) over 6 runs | yes |
| Severity floor W2 | Low | Counter({'Low': 6}) over 6 runs | yes |
