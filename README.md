# Privacy-Preserving Insurance Regression with CKKS

## Overview

This project utilizes the CKKS scheme from Microsoft SEAL to perform linear regression while maintaining data privacy. It tests how well the method performs on encrypted insurance data, measuring time, memory usage, and prediction accuracy.

All operations, including encoding, encryption, regression, and decryption, are performed within the encrypted domain. The system then compares the encrypted results with their plaintext equivalents to measure overhead and performance.

-------

## Microsoft SEAL Setup

Before running the C++ demo, Microsoft SEAL must be installed and configured:

### Step 1: Clone SEAL from GitHub
```bash
git clone https://github.com/microsoft/SEAL.git
cd SEAL
```

### Step 2: Build with CMake
```bash
cmake -S . -B build
cmake --build build
```

### Step 3: Add the File
Add the C++ file (`ckks_insurance_regression.cpp`) in `native/examples/`.

### Step 4: Edit examples.cpp
Inside `examples.cpp`, include:

```
void ckks_insurance_regression();
```
And call the function in `main()`:
```
ckks_insurance_regression();
```

### Step 5: Rebuild and Run
```bash
cmake --build build
cd native/examples (move to the folder where build is present)
make -j
./SEALExamples
```

##### ./SEALExamples (it may be different as sometimes it will be as ./bin/sealexamples check before run)
---

## How This Code Works

### What This Code Does

The function `ckks_insurance_regression()` performs the following:

- Loads insurance data from `insurance.csv` (age vs. charges)  
- Encrypts both columns using the CKKS scheme  
- Performs homomorphic linear regression (x*x, x*y)  
- Uses vector rotation to sum slots in ciphertext  
- Decrypts to get slope and intercept  
- Calculates plaintext regression for comparison  
- Logs error metrics: MAE, RMSE, MAPE 
- logs the runtime of the operatin(multiplication,addition,rotation..etc)
 

Performs:
- Unoptimised predictions (new context per loop)
- Optimised predictions (shared context and encoded values)
  

Benchmarks operation-level timings and memory usage  
- Explores parameter variation across:
- `coeff_modulus`
- `scale`
- `poly_modulus_degree`

---

## Inputs Required During Execution

When the program runs, it will ask:

1. **Number of entries** (e.g., 200, max 1338)  

2. **Polynomial degree** (choose from 4096, 8192, or 16384)  

3. **Operation mode:**
- `1` Encrypted Regression
- `2` Vector Rotation Test
- `3` Both

---

## Output Files and Their Purpose

- **`benchmark_results.csv`**  
  Logs slope, intercept, encryption time, ciphertext size  

- **`runtime_vs_degree.csv`**  
  Records full pipeline runtime against `poly_modulus_degree`  

- **`operation_<entries>.csv`**  
  Tracks microsecond timing and memory per operation (encode, encrypt, add, etc.)  

- **`memory_vs_entries.csv`**  
  Memory (in MB) as dataset size increases  

- **`prediction_unoptimised_output.csv`**  
  Unoptimised predictions and their errors (CKKS vs. Plaintext)  

- **`prediction_optimised.csv`**  
  Optimised version with shared setup for better performance  

- **`benchmark_param_variation.csv`**  
  Parameter sweep over modulus and scale, logging slope, intercept, MAE, RMSE, MAPE  

---

## Key Concepts in the Code

- **CKKS Homomorphic Encryption**  
  Enables arithmetic on encrypted floating-point vectors  

- **SEALContext**  
  Initializes all encryption parameters  

- **Slot Summation using Rotation**  
  Adds up encrypted values using rotate-and-add logic  

- **Benchmarking**  
  Measures time (µs), memory (KB/MB), and accuracy impact of encrypted computation  

---

## Notes

- You must have `insurance.csv` with numeric fields `age` and `charges` in the same directory.  
- The benchmarking logs are essential for analysis and should be saved for the report.  
- Run in all three modes (1, 2, and 3) to generate a complete evaluation.  

Everything runs inside encrypted space—there’s no exposure of raw data.

------
## Repository Structure

| File/Folder               | Description                                                                 |
|----------------------------|-----------------------------------------------------------------------------|
| **`/data`**               | Contains input data files (e.g., insurance dataset) used for regression and benchmarking. |
| **`/docs`**               | Supporting documentation such as dissertation drafts and slides.            |
| **`/results`**            | Benchmarking outputs including CSV logs and graphs.                         |
| **`/src`**                | Source code directory containing C++ implementations for CKKS experiments.  |
| **`README.md`**           | Main project documentation with overview, setup, and usage instructions.    |
| **`ckks_insurance_regression.cpp`** | Core C++ implementation of encrypted regression using CKKS on insurance data. |
| **`examples.cpp`**        | Modified SEAL driver file that integrates and runs your CKKS regression code. |
| **`insurance.csv`**       | Sample dataset with attributes like age, BMI, smoker, region, and charges.   |
| **`plot_ckks_results.py`**| Python script for visualising benchmarking outputs and prediction results.   |

---
