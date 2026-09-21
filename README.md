# `sqlitriager` - SQLi Triager with Jev AI

A small Python experiment using Jev AI to classify SQL queries as benign or malicious, with asynchronous requests and CSV-based evaluation.

## Setup

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

Create `.env` in the project root:

```dotenv
TYPESAFE_API_KEY=your_api_key
```

Keep `.env` out of version control.

## Dataset

Download [SuperviZ25-SQL](https://zenodo.org/records/17086037) and place the original CSV at `data/dataset.csv`.

Extract 2,000 random records:

```bash
uv run python -m sqlitriager.tool.sample_csv --size 2000 --seed 20260921
```

The sampler uses streaming reservoir sampling, so it does not load the entire dataset into memory. The output is `data/dataset_sample_2000.csv`.

Labels: `0` = benign, `1` = malicious.

## Run

Test with 10 records:

```bash
uv run python -m sqlitriager.tool.benchmark --limit 10 --concurrency 2
```

Evaluate the full sample:

```bash
uv run python -m sqlitriager.tool.benchmark --concurrency 20
```

Only `full_query` is sent to Jev. Labels and attack metadata are excluded from model input.

The classifier uses one Noul question per query and predicts malicious when `P(malicious) >= 0.5`. Progress is printed to the console, and per-query results are saved under `results/`.

Each execution creates a new run; it does not resume previous requests.

## Initial Results

One local run on 2,000 randomly sampled records:

| Metric | Result |
|---|---:|
| Model | `jev-1.13.0` |
| Successful requests | 2,000 / 2,000 |
| Request errors | 0 |
| Accuracy | 99.45% |
| Precision | 100.00% |
| Recall | 94.15% |
| F1 | 96.99% |
| False-positive rate | 0.00% |
| True negatives / False positives | 1,812 / 0 |
| True positives / False negatives | 177 / 11 |
| Total elapsed time | 40.29 s |
| Throughput | 49.64 queries/s |
| Request latency p50 / p95 | 352.5 / 565.6 ms |
| Observed API cost | Approximately US$0.03 |

Cost is the observed charge for this run, not a guaranteed price. Latency includes network overhead and any retries, but excludes waiting for a concurrency slot.

The sampling command above illustrates reproducible usage; its seed is not asserted to be the seed of this initial run.

## Reviewing the 11 False Negatives

Manual inspection found no explicit SQL injection payload in the 11 queries. They appeared to be ordinary searches, inserts, or updates.

The dataset authors acknowledge that sqlmap can generate requests without malicious payloads, such as connection checks. These disagreements may therefore reflect labeling noise or missing context rather than missed injection syntax.

The reported metrics retain the original dataset labels. The 11 cases have not been relabeled.

Refer to `example_data` directory to see the data that I used. 
- `example_data\dataset_sample_2000.csv`: The sampled data that I made and used for this experiment
- `example_data\jev_20260921T141424Z_27769efb.csv`: The result CSV that recorded Jev AI's decisionmaking.

## Limitations

This is an exploratory benchmark on one synthetic dataset sample, not a production security validation.

- Zero observed false positives does not guarantee a zero false-positive rate.
- Query text alone cannot establish authorization or attacker intent.
- Prompt and threshold changes should be evaluated on a separate held-out sample.
- No head-to-head comparison with other models or detection tools was performed.

## References

- [SuperviZ25-SQL dataset and labeling notes](https://zenodo.org/records/17086037)
- [TypeSafe / Jev documentation](https://docs.typesafe.ai/)