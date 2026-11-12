import argparse
from pathlib import Path
from random import Random

from sklearn.dummy import DummyClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

FIELDS = ("duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts")


def read_flows(path, limit):
    with path.open(encoding="utf-8") as stream:
        fields = None
        count = 0
        for line in stream:
            if line.startswith("#fields"):
                fields = line.split()[1:]
            elif line.strip() and not line.startswith("#"):
                if fields is None:
                    raise ValueError(f"{path}: missing #fields header")
                # The last tab-separated field may contain the three space-separated labels.
                row = dict(zip(fields, line.split()))
                label = row.get("label", "").lower()
                if label not in {"benign", "malicious"}:
                    raise ValueError(f"{path}: unexpected label {label!r}")
                values = [float(row[key]) if row[key] != "-" else -1.0 for key in FIELDS]
                yield values, int(label == "malicious")
                count += 1
                if count >= limit:
                    break


def demo_capture(seed):
    rng = Random(seed)
    for _ in range(500):
        label = rng.randrange(2)
        origin = rng.randrange(1, 30)
        reply = rng.randrange(1, 20 if label else 50)
        yield [rng.uniform(0, 10), origin * 60, reply * 60, origin, reply], label


def main():
    parser = argparse.ArgumentParser(description="Evaluate a binary IoT flow classifier.")
    parser.add_argument("--train", nargs="+", type=Path)
    parser.add_argument("--test", nargs="+", type=Path)
    parser.add_argument("--limit", type=int, default=20000, help="Maximum rows per capture")
    args = parser.parse_args()

    if args.limit < 1:
        parser.error("--limit must be positive")
    if bool(args.train) != bool(args.test):
        parser.error("provide both --train and --test, or omit both for the synthetic demo")
    if args.train:
        if set(path.resolve() for path in args.train) & set(path.resolve() for path in args.test):
            parser.error("training and test files must come from different captures")
        train = [row for path in args.train for row in read_flows(path, args.limit)]
        test = [row for path in args.test for row in read_flows(path, args.limit)]
        print("IoT-23 flow evaluation")
    else:
        train, test = list(demo_capture(42)), list(demo_capture(43))
        print("Synthetic smoke test")

    if any({label for _, label in split} != {0, 1} for split in (train, test)):
        parser.error("each split must contain both benign and malicious flows")

    train_x, train_y = zip(*train)
    test_x, test_y = zip(*test)
    for model in (
        DummyClassifier(strategy="most_frequent"),
        RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42),
    ):
        model.fit(train_x, train_y)
        print(type(model).__name__)
        print(classification_report(test_y, model.predict(test_x), labels=[0, 1],
                                    target_names=["benign", "malicious"], zero_division=0))


if __name__ == "__main__":
    main()
