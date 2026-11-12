# IoT-23 Flow Classification Baseline

A Codex-assisted portfolio implementation inspired by a 2022 IoT botnet-detection project. It compares a random forest with a majority-class baseline using five Zeek connection features and reports per-class precision, recall and F1.

## Run locally

```bash
python -m pip install -r requirements.txt
python evaluate.py
```

The default run uses seeded synthetic data to check that the pipeline runs. For a dataset evaluation, download labeled connection logs from distinct scenarios in the [official IoT-23 dataset](https://www.stratosphereips.org/datasets-iot23) and run:

```bash
python evaluate.py --train data/train-a/conn.log.labeled data/train-b/conn.log.labeled --test data/test-a/conn.log.labeled data/test-b/conn.log.labeled
```

Use different capture scenarios in each split and ensure both classes appear in each split. The default reads the first 20,000 records per capture. Adjust with `--limit` and document the scenario IDs, row caps and class supports when reporting results. The time-ordered row cap can skew class coverage. Missing numeric values are encoded as -1.

Features summarize completed connections. The historical three-packet F1 figure requires packet-prefix features and a documented evaluation protocol. This implementation has no measured IoT-23 benchmark yet.
