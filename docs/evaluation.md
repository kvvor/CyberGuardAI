# Detection evaluation

Run `go test ./internal/detection ./internal/demo ./internal/emailparser` from
backend/. Tests use synthetic data, never operational email or real malware.

Maintain a licensed labeled corpus of legitimate, phishing and ambiguous email.
Split development and holdout samples before tuning. Evaluate with AI disabled,
then optionally repeat with explicit consent and a pinned model. Record model
and scoring version. Count suspicious/phishing as positive and legitimate as
negative. Track inconclusive as abstentions, not correct negatives. Report TP,
FP, TN, FN, precision, recall, false-positive rate and abstention coverage, broken
down by language, source format and attack type. The tiny synthetic tests are
regression checks; no production accuracy rates have been established.
