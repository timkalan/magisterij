import os
import re
import sys

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


def parse_go_benchmarks_from_dir(directory: str) -> pd.DataFrame:
    """
    Parses Go benchmark results from text files in the specified directory.
    Args:
        directory (str): Path to the directory containing benchmark result files.
    Returns:
        pd.DataFrame: DataFrame containing parsed benchmark results.
    """
    benchmark_pattern = re.compile(
        r"^(Benchmark\w+?)/nSigners=(\d+)-\d+\s+(\d+)\s+(\d+)\s+ns/op"
    )

    all_data = []

    for filename in os.listdir(directory):
        if not filename.endswith(".txt"):
            continue
        scheme = os.path.splitext(filename)[0].split("_")[
            1
        ]  # Extract scheme from filename
        filepath = os.path.join(directory, filename)

        with open(filepath, "r") as f:
            for line in f:
                match = benchmark_pattern.match(line.strip())
                if match:
                    benchmark, n_signers, _, time_ns = match.groups()
                    all_data.append(
                        {
                            "scheme": scheme,
                            "benchmark": benchmark.replace("Benchmark", ""),
                            "n_signers": int(n_signers),
                            "time_ns_per_op": int(time_ns),
                        }
                    )

    df = pd.DataFrame(all_data)

    # Aggregate statistics
    agg_df = (
        df.groupby(["scheme", "benchmark", "n_signers"])["time_ns_per_op"]
        .agg(["mean", "std", "min", "max"])
        .reset_index()
        .rename(
            columns={
                "mean": "mean_time_ns",
                "std": "stddev_time_ns",
                "min": "min_time_ns",
                "max": "max_time_ns",
            }
        )
    )

    return agg_df


def plot_benchmark_results(df: pd.DataFrame, benchmark: str):
    """
    Plots benchmark results from the DataFrame.
    Args:
        df (pd.DataFrame): DataFrame containing benchmark results.
        benchmark (str): Name of the benchmark to plot.
    """
    # Convert ns to ms for easier interpretation
    df["mean_time_ms"] = df["mean_time_ns"] / 1e6
    df["stddev_time_ms"] = df["stddev_time_ns"] / 1e6

    benchmark_df = df[df["benchmark"] == benchmark]
    assert isinstance(benchmark_df, pd.DataFrame)

    plt.figure(figsize=(10, 6))
    sns.lineplot(
        data=benchmark_df,
        x="n_signers",
        y="mean_time_ms",
        hue="scheme",
        marker="o",
        err_style="bars",
        err_kws={"capsize": 3},
    )

    for scheme in benchmark_df["scheme"].unique():
        subset = benchmark_df[benchmark_df["scheme"] == scheme]
        plt.fill_between(
            subset["n_signers"],
            subset["mean_time_ms"] - subset["stddev_time_ms"],
            subset["mean_time_ms"] + subset["stddev_time_ms"],
            alpha=0.2,
            label=f"{scheme} standardni odklon",
        )

    plt.title(_translate_benchmark(benchmark))
    plt.xlabel("Število podpisnikov")
    plt.ylabel("Povprečen čas (ms)")
    plt.legend()
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(
        f"../naloga/images/benchmark_{benchmark}.pdf", format="pdf", bbox_inches="tight"
    )
    plt.show()


def _translate_benchmark(benchmark: str) -> str:
    translations = {
        "KeyGeneration": "Primerjava hitrosti generiranja ključev",
        "Signing": "Primerjava hitrosti podpisovanja",
        "Verification": "Primerjava hitrosti preverjanja",
        "All": "Primerjava hitrosti vseh operacij",
        "SigningVerification": "Primerjava hitrosti podpisovanja in preverjanja",
    }

    return translations.get(benchmark, benchmark)


if __name__ == "__main__":
    # Check if a benchmark name is provided as a command-line argument
    if len(sys.argv) < 2:
        print("Usage: python visualize.py BENCHNAME")
        sys.exit(1)

    benchmark_name = sys.argv[1]

    # Assuming the benchmark results are in a directory named "results"
    df = parse_go_benchmarks_from_dir("results/")

    # Plot results for the specified benchmark
    plot_benchmark_results(df, benchmark_name)
