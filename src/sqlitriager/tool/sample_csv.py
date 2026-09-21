"""Extract a uniform random sample from a large CSV file."""

from __future__ import annotations

import argparse
import csv
import random
import secrets
from pathlib import Path
from typing import TextIO


PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_INPUT = PROJECT_ROOT / "data" / "dataset.csv"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "dataset_sample_2000.csv"

# Prevent errors if a SQL query or payload is unusually long.
csv.field_size_limit(16 * 1024 * 1024)


def sample_csv(
    input_path: Path,
    output_path: Path,
    sample_size: int,
    seed: int,
) -> tuple[int, int]:
    """
    Uniformly sample rows using Algorithm R reservoir sampling.

    Returns:
        A tuple containing:
        - total number of source rows
        - number of sampled rows
    """
    rng = random.Random(seed)
    reservoir: list[dict[str, str]] = []

    with input_path.open("r", encoding="utf-8", newline="") as source_file:
        reader = csv.DictReader(source_file)

        if reader.fieldnames is None:
            raise ValueError("The input CSV does not contain a header.")

        total_rows = 0

        for total_rows, row in enumerate(reader, start=1):
            if total_rows <= sample_size:
                reservoir.append(row)
            else:
                replacement_index = rng.randrange(total_rows)

                if replacement_index < sample_size:
                    reservoir[replacement_index] = row

            if total_rows % 250_000 == 0:
                print(f"Read {total_rows:,} rows...")

    if total_rows < sample_size:
        raise ValueError(
            f"The dataset contains only {total_rows:,} rows, "
            f"but {sample_size:,} rows were requested."
        )

    # Avoid preserving the source-file order of the selected records.
    rng.shuffle(reservoir)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8", newline="") as output_file:
        writer = csv.DictWriter(
            output_file,
            fieldnames=reader.fieldnames,
        )
        writer.writeheader()
        writer.writerows(reservoir)

    return total_rows, len(reservoir)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract a uniform random sample from a large CSV file."
    )

    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_INPUT,
        help=f"Input CSV path. Default: {DEFAULT_INPUT}",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output CSV path. Default: {DEFAULT_OUTPUT}",
    )
    parser.add_argument(
        "--size",
        type=int,
        default=2_000,
        help="Number of rows to extract. Default: 2000",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional random seed for reproducible sampling.",
    )

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.size <= 0:
        raise ValueError("--size must be greater than zero.")

    if not args.input.is_file():
        raise FileNotFoundError(f"Input CSV not found: {args.input}")

    # Generate a fresh seed unless the user supplies one.
    seed = args.seed if args.seed is not None else secrets.randbits(64)

    print(f"Input:  {args.input}")
    print(f"Output: {args.output}")
    print(f"Size:   {args.size:,}")
    print(f"Seed:   {seed}")

    total_rows, sampled_rows = sample_csv(
        input_path=args.input,
        output_path=args.output,
        sample_size=args.size,
        seed=seed,
    )

    print()
    print("Sampling completed.")
    print(f"Source rows:  {total_rows:,}")
    print(f"Sampled rows: {sampled_rows:,}")
    print(f"Saved to:     {args.output}")


if __name__ == "__main__":
    main()