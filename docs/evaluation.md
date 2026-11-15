# Detection evaluation

## What exists

`backend/internal/evaluation` contains a labelled regression corpus of 23
**synthetic** messages (invented senders on reserved domains, no real mail, no
malware) and the metric calculation.

| Label | Cases |
|---|---|
| legitimate (8) | ordinary business mail, genuine security notice, certificate notice with long Microsoft Safe Links and a tracking pixel, newsletter with tracking URLs, legitimate urgent request, ordinary attachment, attachment name with several dots, ticket system with a different Reply-To |
| phishing (11) | credential harvesting via IP link, fake Microsoft 365 form, fake account verification, lookalike sender domain, display-name impersonation, business email compromise, payment redirection, deceptive link destination, attachment with reported detections, phishing without typical keywords, phishing with an embedded prompt injection |
| ambiguous (4) | pasted body without headers, untrusted authentication results with neutral content, attachment unknown to VirusTotal, attachment without VirusTotal |

## What is measured automatically

`go test ./internal/evaluation` checks, without any model:

- the expected technical observations are recorded for each case, and
  deception observations are **not** recorded for the legitimate cases
  (the regression for the earlier false positives on Safe Links, long URLs,
  tracking pixels, urgency and multi-dot file names);
- the evidence layer produces no score and no verdict;
- the attachment reputation summary is right for each case;
- the provider input contains no attachment bytes or raw HTML;
- every case passes through request construction, the Responses envelope and
  backend validation using the mock provider.

The mock provider is a fixed rule set. Its confusion matrix is printed for
plumbing purposes only and is **not** a measure of detection quality.

## What has not been measured

No real model has been run on the corpus: live OpenAI calls cost money and
were not authorised. Therefore **no precision, recall, false-positive rate or
F1 figure exists for any real model**, and nothing in this repository supports
a claim about real-world detection accuracy.

To run it with your own key (billed to your OpenAI account, 23 requests):

```powershell
# from backend\
$env:CYBERGUARD_LIVE_EVAL = '1'
$env:OPENAI_API_KEY = '<your key>'
$env:OPENAI_MODEL = '<model id>'
go test ./internal/evaluation -run TestLiveEvaluation -v -timeout 60m
```

The test prints each case with its verdict and then the metrics.

## How the metrics are defined

Positive = verdict `phishing` or `suspicious`; negative = `legitimate`.
`inconclusive` and failed assessments are **abstentions**: they are reported as
coverage and never counted as correct negatives. Ambiguous cases have no single
right answer and are tallied separately by verdict.

Precision = TP/(TP+FP), recall = TP/(TP+FN), false-positive rate = FP/(FP+TN),
false-negative rate = FN/(FN+TP), F1 = harmonic mean of precision and recall.

## Reading results responsibly

- 23 synthetic messages show whether behaviour regressed; they cannot estimate
  performance on real mail.
- Results depend on the selected model and can change when the provider
  updates it. Record model ID and date with every run.
- For a meaningful estimate use a licensed, labelled set of real legitimate and
  phishing mail, split into development and hold-out parts, and report results
  per language, source format and attack type.
