import pandas as pd
import matplotlib.pyplot as plt
import glob
import os

# === 1. Benchmark results: runtime & memory vs poly_modulus_degree ===
if os.path.exists("benchmark_results.csv"):
    df = pd.read_csv("benchmark_results.csv")

    # Runtime vs polynomial degree
    plt.figure()
    plt.plot(df["poly_degree"], df["time_encrypt_ms"], marker="o", label="Encryption Time (ms)")
    plt.xlabel("Polynomial Degree")
    plt.ylabel("Time (ms)")
    plt.title("Encryption Time vs Polynomial Degree")
    plt.grid(True)
    plt.legend()
    plt.savefig("plot_runtime_vs_degree.png")

    # Memory usage vs dataset size
    df_grouped = df.groupby("entries").mean().reset_index()  # ✅ average per dataset size
    plt.figure()
    plt.plot(df_grouped["entries"], df_grouped["x_size_kb"], marker="o", label="Encrypted X Size (KB)")
    plt.plot(df_grouped["entries"], df_grouped["y_size_kb"], marker="o", label="Encrypted Y Size (KB)")
    plt.xlabel("Entries")
    plt.ylabel("Size (KB)")
    plt.title("Memory Usage vs Dataset Size")
    plt.grid(True)
    plt.legend()
    plt.savefig("plot_memory_vs_entries.png")

# === 2. Operation-level benchmarking ===
for fname in glob.glob("operation_*.csv"):
    df = pd.read_csv(fname)
    plt.figure()
    plt.bar(df["operation"], df["time_us"])
    plt.xticks(rotation=45)
    plt.ylabel("Time (μs)")
    plt.title(f"Operation-Level Benchmarking ({fname})")
    plt.tight_layout()
    plt.savefig(fname.replace(".csv", "_plot.png"))

# === 3. Prediction accuracy (optimized vs unoptimized) ===
for fname in ["prediction_unoptimized_output.csv", "prediction_optimized.csv"]:
    if os.path.exists(fname):
        df = pd.read_csv(fname)

        # ✅ Drop non-numeric rows like SUMMARY
        df = df[pd.to_numeric(df["input_x"], errors="coerce").notnull()]
        df = df.astype({"input_x": float, "actual_y": float, "predicted_ckks": float})

        plt.figure()
        plt.plot(df["input_x"], df["actual_y"], label="Actual Y")
        plt.plot(df["input_x"], df["predicted_ckks"], label="Predicted CKKS")
        plt.xlabel("Input X")
        plt.ylabel("Output Y")
        plt.title(f"Predicted vs Actual ({fname})")
        plt.legend()
        plt.grid(True)
        plt.savefig(fname.replace(".csv", "_prediction_plot.png"))

# === 4. Parameter variation benchmarking ===
if os.path.exists("benchmark_param_variation.csv"):
    df = pd.read_csv("benchmark_param_variation.csv")

    # MAE vs Scale
    plt.figure()
    for coeff in df["coeff_modulus_bits"].unique():
        subset = df[df["coeff_modulus_bits"] == coeff]
        plt.plot(subset["scale"], subset["mae"], marker="o", label=f"MAE {coeff}")
    plt.xlabel("Scale")
    plt.ylabel("MAE")
    plt.title("MAE vs Scale (per coeff_modulus_bits)")
    plt.legend()
    plt.grid(True)
    plt.savefig("plot_mae_vs_scale.png")

    # RMSE vs Scale
    plt.figure()
    for coeff in df["coeff_modulus_bits"].unique():
        subset = df[df["coeff_modulus_bits"] == coeff]
        plt.plot(subset["scale"], subset["rmse"], marker="o", label=f"RMSE {coeff}")
    plt.xlabel("Scale")
    plt.ylabel("RMSE")
    plt.title("RMSE vs Scale (per coeff_modulus_bits)")
    plt.legend()
    plt.grid(True)
    plt.savefig("plot_rmse_vs_scale.png")

