#include "seal/seal.h"
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <iostream>
#include <cmath>
#include <map>
#include <iomanip>
#include <chrono>

using namespace std;
using namespace seal;

// === [CUSTOM] CSV loader,trim function & numeric auto-detect ===
// === Utility: Trim string ===
string trim_i(const string &s) {
    size_t start = s.find_first_not_of(" \r\n\t");
    size_t end = s.find_last_not_of(" \r\n\t");
    return (start == string::npos || end == string::npos) ? "" : s.substr(start, end - start + 1);
}

// === CSV Loader: Auto-detect numeric columns ===
map<string, vector<double>> read_csv_numeric_columns_i(const string &filename) {
    ifstream file(filename);
    string line, cell;
    vector<string> headers;
    map<string, vector<double>> numeric_columns;

    if (!getline(file, line)) {
        cerr << "[Error] Could not read CSV header.\n";
        throw runtime_error("CSV header missing.");
    }

    stringstream header_stream(line);
    while (getline(header_stream, cell, ',')) {
        headers.push_back(trim_51(cell));
    }

    cout << "\n[Info] Detected Columns:\n";
    for (const auto &h : headers) {
        cout << "  [" << h << "]\n";
    }

    while (getline(file, line)) {
        stringstream line_stream(line);
        int col_index = 0;
        while (getline(line_stream, cell, ',')) {
            if (col_index >= headers.size()) break;
            try {
                double val = stod(cell);
                numeric_columns[headers[col_index]].push_back(val);
            } catch (...) {}
            col_index++;
        }
    }

    return numeric_columns;
}

// === [CUSTOM] Main entry for insurance regression benchmarking (Phase 5) ===
void ckks_insurance_regression()
{
    int n_entries = 0;
    int poly_deg = 0;
    int op_mode = 0;

    auto now = chrono::high_resolution_clock::now;
    auto t_global_start = chrono::high_resolution_clock::now();
    auto time_ms = [](chrono::high_resolution_clock::time_point start) {
        return chrono::duration_cast<chrono::milliseconds>(chrono::high_resolution_clock::now() - start).count();
    };

    auto time_us = [](chrono::high_resolution_clock::time_point start) {
        return chrono::duration_cast<chrono::microseconds>(chrono::high_resolution_clock::now() - start).count();
    };

// === [CUSTOM] User inputs and run banner ===
    cout << "\n=== CKKS Encrypted Insurance Regression ===\n";

// === [CUSTOM] Command-line inputs: entries, poly degree, and mode ===
    cout << "Enter number of entries to use: ";
    cin >> n_entries;
    cout << "Enter poly_modulus_degree (4096, 8192, or 16384): ";
    cin >> poly_deg;
    if (poly_deg != 4096 && poly_deg != 8192 && poly_deg != 16384) {
        cerr << "[Error] Invalid poly_modulus_degree.\n";
        return;
    }
    cout << "Select mode: 1 = regression only, 2 = rotation only, 3 = both: ";
    cin >> op_mode;
    
    
    string filename = "insurance.csv";

// === [CUSTOM] Feature/target columns for insurance regression ===
    auto data = read_csv_numeric_columns_i(filename);
    string x_col = "age", y_col = "charges";

    if (data.find(x_col) == data.end() || data.find(y_col) == data.end()) {
        cerr << "[Error] Required columns not found.\n";
        return;
    }

    vector<double> x = data[x_col], y = data[y_col];
    size_t usable = min({ x.size(), y.size(), static_cast<size_t>(n_entries) });
    x.resize(usable); y.resize(usable);

    auto t0 = now();

 // === [SEAL PATTERN] CKKS parameter & context setup ===
    EncryptionParameters parms(scheme_type::ckks);
    parms.set_poly_modulus_degree(poly_deg);
    if (poly_deg == 4096)
        parms.set_coeff_modulus(CoeffModulus::Create(4096, { 36,36,36 }));
    else if (poly_deg == 8192)
        parms.set_coeff_modulus(CoeffModulus::Create(8192, { 60, 40, 40, 60 }));
    else
        parms.set_coeff_modulus(CoeffModulus::Create(16384, { 60, 40, 40, 60 }));

    SEALContext context(parms);
    cout << "[Timing] SEALContext setup: " << time_ms(t0) << " ms\n";

    // === [SEAL PATTERN] Keys & actors (KeyGenerator/Encryptor/Evaluator/...) ===
    KeyGenerator keygen(context);
    PublicKey public_key;
    keygen.create_public_key(public_key);
    SecretKey secret_key = keygen.secret_key();
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys galois_keys;
    keygen.create_galois_keys(galois_keys);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);
    CKKSEncoder encoder(context);

    double scale = (poly_deg == 4096) ? pow(2.0, 30) : pow(2.0, 40);

    Plaintext plain_x, plain_y;
    
// === [CUSTOM] Encode insurance vectors and encrypt them for regression ===
    auto t1 = now(); encoder.encode(x, scale, plain_x); encoder.encode(y, scale, plain_y);
    cout << "[Timing] Encoding done: " << time_ms(t1) << " ms\n";

    Ciphertext enc_x, enc_y;

    // === [SEAL PATTERN] Basic encryption of plaintext vectors ===
    t1 = now(); encryptor.encrypt(plain_x, enc_x); encryptor.encrypt(plain_y, enc_y);
    auto enc_time = time_ms(t1);
    cout << "[Timing] Encryption done: " << enc_time << " ms\n";

    double x_size_kb = enc_x.save_size(compr_mode_type::none) / 1024.0;
    double y_size_kb = enc_y.save_size(compr_mode_type::none) / 1024.0;
    cout << "[Memory] Encrypted x size: " << x_size_kb << " KB\n";
    cout << "[Memory] Encrypted y size: " << y_size_kb << " KB\n";

    cout << "\n--- Data Encrypted with CKKS ---\n";
    cout << "  • Encrypted column '" << x_col << "' with " << usable << " values.\n";
    cout << "  • Encrypted column '" << y_col << "' with " << usable << " values.\n";

    Ciphertext sum_x, sum_y, sum_xy, sum_x_sq;
    double slope = 0.0, intercept = 0.0;

// === [CUSTOM] Rotation timing used later for slot-sum reductions ===
    if (op_mode == 2 || op_mode == 3) {
        cout << "\n--- Rotation Test(for slot-sum)---\n";
        Ciphertext rotated_x;
        auto t_rot = now();
        evaluator.rotate_vector(enc_x, 1, galois_keys, rotated_x);
        cout << "[Timing] Vector rotation: " << time_ms(t_rot) << " ms\n";
    }

// === [CUSTOM] Homomorphic regression: x*x, x*y, then slot-sum by rotations ===
    if (op_mode == 1 || op_mode == 3) {
        cout << "\n--- Homomorphic Regression Computation ---\n";

        Ciphertext enc_x_sq, enc_xy;
        t1 = now();
        evaluator.multiply(enc_x, enc_x, enc_x_sq);
        evaluator.relinearize_inplace(enc_x_sq, relin_keys);
        evaluator.rescale_to_next_inplace(enc_x_sq);
        cout << "[Timing] x*x operations: " << time_ms(t1) << " ms\n";

        t1 = now();
        evaluator.multiply(enc_x, enc_y, enc_xy);
        evaluator.relinearize_inplace(enc_xy, relin_keys);
        evaluator.rescale_to_next_inplace(enc_xy);
        cout << "[Timing] x*y operations: " << time_ms(t1) << " ms\n";


// === [CUSTOM] Slot-sum via rotate+add (instrumented with timing) ===
        auto sum_slots = [&](Ciphertext &ct) {
            Ciphertext sum = ct;
            auto tsum = now();
            for (int i = 1; i < static_cast<int>(usable); i <<= 1) {
                Ciphertext rotated;
                evaluator.rotate_vector(sum, i, galois_keys, rotated);
                evaluator.add_inplace(sum, rotated);
            }
            cout << "[Timing] Sum-slots via rotations: " << time_ms(tsum) << " ms\n";
            return sum;
        };

        sum_x = sum_slots(enc_x);
        sum_y = sum_slots(enc_y);
        sum_xy = sum_slots(enc_xy);
        sum_x_sq = sum_slots(enc_x_sq);
    }

// === [SEAL PATTERN] Decrypt & decode sums; [CUSTOM] print human-readable outputs ===
    if (op_mode == 1 || op_mode == 3) {
        cout << "\n--- Decryption and Final Output ---\n";
        auto tdec = now();
        Plaintext dec_sum_x, dec_sum_y, dec_sum_xy, dec_sum_x_sq;
        decryptor.decrypt(sum_x, dec_sum_x);
        decryptor.decrypt(sum_y, dec_sum_y);
        decryptor.decrypt(sum_xy, dec_sum_xy);
        decryptor.decrypt(sum_x_sq, dec_sum_x_sq);

        vector<double> res_x, res_y, res_xy, res_x_sq;
        encoder.decode(dec_sum_x, res_x);
        encoder.decode(dec_sum_y, res_y);
        encoder.decode(dec_sum_xy, res_xy);
        encoder.decode(dec_sum_x_sq, res_x_sq);
        cout << "[Timing] Decryption + Decoding: " << time_ms(tdec) << " ms\n";

        double mean_x = res_x[0] / usable;
        double mean_y = res_y[0] / usable;
        double mean_xy = res_xy[0] / usable;
        double mean_x_sq = res_x_sq[0] / usable;

        slope = (mean_xy - mean_x * mean_y) / (mean_x_sq - mean_x * mean_x);
        intercept = mean_y - slope * mean_x;

        cout << fixed << setprecision(4);
        cout << "\n[Output] Decrypted Linear Regression Coefficients:\n";
        cout << "  • Slope (age → charges): " << slope << endl;
        cout << "  • Intercept: " << intercept << endl;
   

// === [CUSTOM] Plaintext regression baseline and accuracy metrics (MAE/RMSE/MAPE) === 
    // === Plaintext Regression for Comparison ===
{
    double slope_plain = 0.0, intercept_plain = 0.0;
    double sum_x_plain = 0.0, sum_y_plain = 0.0, sum_xy_plain = 0.0, sum_x_sq_plain = 0.0;

    for (size_t i = 0; i < usable; i++) {
        sum_x_plain += x[i];
        sum_y_plain += y[i];
        sum_xy_plain += x[i] * y[i];
        sum_x_sq_plain += x[i] * x[i];
    }

    double mean_x_plain = sum_x_plain / usable;
    double mean_y_plain = sum_y_plain / usable;
    double mean_xy_plain = sum_xy_plain / usable;
    double mean_x_sq_plain = sum_x_sq_plain / usable;

    slope_plain = (mean_xy_plain - mean_x_plain * mean_y_plain) /
                  (mean_x_sq_plain - mean_x_plain * mean_x_plain);
    intercept_plain = mean_y_plain - slope_plain * mean_x_plain;

    // Accuracy metrics
    double mae_plain = 0.0, rmse_plain = 0.0, mape_plain = 0.0;
    for (size_t i = 0; i < usable; i++) {
        double pred = slope_plain * x[i] + intercept_plain;
        double err = pred - y[i];
        mae_plain += fabs(err);
        rmse_plain += err * err;
        if (y[i] != 0) mape_plain += fabs(err / y[i]);
    }
    mae_plain /= usable;
    rmse_plain = sqrt(rmse_plain / usable);
    mape_plain = (mape_plain / usable) * 100.0;

    cout << "\n[Output] Plaintext Linear Regression Coefficients:\n";
    cout << "  • Slope (age → charges): " << slope_plain << endl;
    cout << "  • Intercept: " << intercept_plain << endl;
    cout << "  • MAE: " << mae_plain
         << " | RMSE: " << rmse_plain
         << " | MAPE%: " << mape_plain << endl;
}


    }
// === [CUSTOM] Save headline Phase 5 results to CSV (time, sizes, slope, intercept) ===
    // Save Phase 5 results
    ifstream test("benchmark_results.csv");
    bool file_exists = test.good(); test.close();
    ofstream log("benchmark_results.csv", ios::app);
    if (!file_exists) log << "entries,poly_degree,time_encrypt_ms,x_size_kb,y_size_kb,slope,intercept\n";
    log << n_entries << "," << poly_deg << "," << enc_time << "," << fixed << setprecision(2)
        << x_size_kb << "," << y_size_kb << "," << setprecision(4) << slope << "," << intercept << endl;
    log.close();


// === [CUSTOM] End of regression run (human-readable banner) ===
    cout << "\n--- CKKS Regression Process Complete. ---\n";
    {
        ofstream rt_out("runtime_vs_degree.csv", ios::app);
        if (rt_out.tellp() == 0) {
            rt_out << "Poly_Degree,Runtime_ms\n";
        }

        // Measure total runtime of this run
        auto t_global_end = chrono::high_resolution_clock::now();
        double total_runtime_ms = chrono::duration_cast<chrono::milliseconds>(t_global_end - t_global_start).count();

        rt_out << poly_deg << "," << total_runtime_ms << "\n";
    }

// === [CUSTOM] Operation-level timings (encode, encrypt, add, mul+relin+rescale, rotate, decrypt, decode) ===
    // ===  Operation-Level Benchmarking ===
    cout << "\n---  Operation-Level Benchmarking ---\n";
    string opfilename = "operation_" + to_string(n_entries) + ".csv";
    ofstream opfile(opfilename);
    opfile << "operation,time_us,mem_kb\n";

    auto t_op = now(); 
    encoder.encode(x, scale, plain_x); 
    opfile << "encode," << time_us(t_op) << ","
           << (MemoryManager::GetPool().alloc_byte_count() >> 10) << "\n";
    
    t_op = now(); 
    encryptor.encrypt(plain_x, enc_x); 
    opfile << "encrypt," << time_us(t_op) << ","
          << (MemoryManager::GetPool().alloc_byte_count() >> 10) << "\n";

    t_op = now(); evaluator.add(enc_x, enc_y, enc_x); 
    opfile << "add," << time_us(t_op) << ","
           << (MemoryManager::GetPool().alloc_byte_count() >> 10) << "\n";

    t_op = now();
    Ciphertext mul;
    evaluator.multiply(enc_x, enc_y, mul);
    evaluator.relinearize_inplace(mul, relin_keys);
    evaluator.rescale_to_next_inplace(mul);
    opfile << "multiply+relin+rescale," << time_us(t_op) << ","
           << (MemoryManager::GetPool().alloc_byte_count() >> 10) << "\n";
    
    t_op = now(); 
    evaluator.rotate_vector(enc_x, 1, galois_keys, mul); 
    opfile << "rotate," << time_us(t_op) << ","
           << (MemoryManager::GetPool().alloc_byte_count() >> 10) << "\n";
    Plaintext pt;
    t_op = now(); 
    decryptor.decrypt(enc_x, pt); 
    opfile << "decrypt," << time_us(t_op) << ","
           << (MemoryManager::GetPool().alloc_byte_count() >> 10) << "\n";

    t_op = now(); 
    encoder.decode(pt, x); 
    opfile << "decode," << time_us(t_op) << ","
           << (MemoryManager::GetPool().alloc_byte_count() >> 10) << "\n";
  
    opfile.close();

    cout << " Operation-Level Benchmarking Complete. Results saved to 'operation*.csv'\n";

// === [CUSTOM] Memory usage vs dataset size (CSV) ===
    // === Memory Usage vs Dataset Size Logging ===
    {
       ofstream mem_out("memory_vs_entries.csv", ios::app);
       if (mem_out.tellp() == 0) {
          // Write header if file is empty
           mem_out << "Entries,Memory_MB\n";
    }
        double memory_mb = static_cast<double>(
           MemoryManager::GetPool().alloc_byte_count()
        )    / (1024.0 * 1024.0);
        mem_out << n_entries << "," << memory_mb << "\n";
     }   

// === [CUSTOM] Bulk prediction (unoptimised): recreate context & keys per input to expose full overhead ===
   cout << "\n===Unoptimised Bulk Prediction ===\n";
auto t_start_unopt = chrono::high_resolution_clock::now();

int max_input = 700;
ofstream p9out("prediction_unoptimised_output.csv", ios::trunc);
p9out << "input_x,actual_y,predicted_plain,predicted_ckks,error_plain,error_ckks,mem_kb\n";

for (int input_x = 1; input_x <= max_input; input_x++) {
    double actual_y = slope * input_x + intercept;
    double predicted_plain = actual_y;

    EncryptionParameters parms9(scheme_type::ckks);
    parms9.set_poly_modulus_degree(poly_deg);
    if (poly_deg == 4096)
        parms9.set_coeff_modulus(CoeffModulus::Create(4096, {36, 36, 36}));
    else if (poly_deg == 8192)
        parms9.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
    else
        parms9.set_coeff_modulus(CoeffModulus::Create(16384, {60, 40, 40, 60}));

    SEALContext context9(parms9);
    KeyGenerator keygen9(context9);
    PublicKey pub_key9; keygen9.create_public_key(pub_key9);
    SecretKey sec_key9 = keygen9.secret_key();
    Encryptor encryptor9(context9, pub_key9);
    Decryptor decryptor9(context9, sec_key9);
    Evaluator evaluator9(context9);
    CKKSEncoder encoder9(context9);

    double scale9 = (poly_deg == 4096) ? pow(2.0, 30) : pow(2.0, 40);

    Plaintext pt_x9, pt_slope9, pt_intercept9;
    encoder9.encode(static_cast<double>(input_x), scale9, pt_x9);
    encoder9.encode(slope, scale9, pt_slope9);
    encoder9.encode(intercept, scale9, pt_intercept9);

    Ciphertext enc_x9;
    encryptor9.encrypt(pt_x9, enc_x9);

    Ciphertext enc_mul;
    evaluator9.multiply_plain(enc_x9, pt_slope9, enc_mul);
    evaluator9.rescale_to_next_inplace(enc_mul);

    pt_intercept9.scale() = enc_mul.scale();
    encoder9.encode(intercept, enc_mul.scale(), pt_intercept9);
    evaluator9.mod_switch_to_inplace(pt_intercept9, enc_mul.parms_id());
    evaluator9.add_plain_inplace(enc_mul, pt_intercept9);

    Plaintext pt_result9;
    decryptor9.decrypt(enc_mul, pt_result9);
    vector<double> decoded_result;
    encoder9.decode(pt_result9, decoded_result);
    double predicted_ckks = decoded_result[0];

    p9out << fixed << setprecision(2)
      << input_x << "," << actual_y << "," << predicted_plain << "," 
      << predicted_ckks << "," << (predicted_plain - actual_y) << "," 
      << (predicted_ckks - actual_y) << "," 
      << (MemoryManager::GetPool().alloc_byte_count() >> 10) << "\n";

}

p9out.close();
auto t_end_unopt = chrono::high_resolution_clock::now();
auto duration_unopt = chrono::duration_cast<chrono::milliseconds>(t_end_unopt - t_start_unopt).count();
cout << "⏱️ Unoptimesed Runtime: " << duration_unopt << " ms\n";

// === Calculate aggregated accuracy metrics for Unoptimised run ===
{
    ifstream in_file("prediction_unoptimised_output.csv");
    string line;
    getline(in_file, line); // skip header
    double mae = 0.0, rmse = 0.0, mape = 0.0;
    int count = 0;

    while (getline(in_file, line)) {
        stringstream ss(line);
        string token;
        vector<string> cols;
        while (getline(ss, token, ',')) cols.push_back(token);
        if (cols.size() >= 6) {
            double actual_y = stod(cols[1]);
            double pred_ckks = stod(cols[3]);
            double err = pred_ckks - actual_y;
            mae += fabs(err);
            rmse += err * err;
            if (actual_y != 0) mape += fabs(err / actual_y);
            count++;
        }
    }
    in_file.close();

    if (count > 0) {
        mae /= count;
        rmse = sqrt(rmse / count);
        mape = (mape / count) * 100.0;

        ofstream out_file("prediction_unoptimised_output.csv", ios::app);
        out_file << "SUMMARY(MAE,RMSE,MAPE%),"
                 << mae << "," << rmse << "," << mape << "\n";
        out_file.close();

        cout << "[Unoptimised Metrics] MAE: " << mae
             << " | RMSE: " << rmse
             << " | MAPE%: " << mape << "\n";
    }
}


// === [CUSTOM] Bulk prediction (optimised): reuse context, keys, and encoded coefficients ===
	cout << "\n=== Optimised Bulk Prediction ===\n";
	auto t_start_opt = chrono::high_resolution_clock::now();

ofstream p9out_opt("prediction_optimised.csv", ios::trunc);
p9out_opt << "input_x,actual_y,predicted_plain,predicted_ckks,error_plain,error_ckks,mem_kbs\n";

// Shared setup
EncryptionParameters parms9(scheme_type::ckks);
parms9.set_poly_modulus_degree(poly_deg);
if (poly_deg == 4096)
    parms9.set_coeff_modulus(CoeffModulus::Create(4096, {36, 36, 36}));
else if (poly_deg == 8192)
    parms9.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 40, 60}));
else
    parms9.set_coeff_modulus(CoeffModulus::Create(16384, {60, 40, 40, 60}));

SEALContext context9(parms9);
KeyGenerator keygen9(context9);
PublicKey pub_key9; keygen9.create_public_key(pub_key9);
SecretKey sec_key9 = keygen9.secret_key();
Encryptor encryptor9(context9, pub_key9);
Decryptor decryptor9(context9, sec_key9);
Evaluator evaluator9(context9);
CKKSEncoder encoder9(context9);
double scale9 = (poly_deg == 4096) ? pow(2.0, 30) : pow(2.0, 40);

// Encode slope and intercept once
Plaintext pt_slope9, pt_intercept9;
encoder9.encode(slope, scale9, pt_slope9);
encoder9.encode(intercept, scale9, pt_intercept9);

for (int input_x = 1; input_x <= max_input; input_x++) {
    double actual_y = slope * input_x + intercept;
    double predicted_plain = actual_y;

    Plaintext pt_x9;
    encoder9.encode(static_cast<double>(input_x), scale9, pt_x9);

    Ciphertext enc_x9(MemoryPoolHandle::Global());
    encryptor9.encrypt(pt_x9, enc_x9);

    Ciphertext enc_mul(MemoryPoolHandle::Global());
    evaluator9.multiply_plain(enc_x9, pt_slope9, enc_mul);
    evaluator9.rescale_to_next_inplace(enc_mul);

    Plaintext pt_intercept_rescaled = pt_intercept9;
    if (abs(pt_intercept_rescaled.scale() - enc_mul.scale()) > 1e-3) {
        encoder9.encode(intercept, enc_mul.scale(), pt_intercept_rescaled);
    }
    evaluator9.mod_switch_to_inplace(pt_intercept_rescaled, enc_mul.parms_id());
    evaluator9.add_plain_inplace(enc_mul, pt_intercept_rescaled);

    Plaintext pt_result9;
    decryptor9.decrypt(enc_mul, pt_result9);
    vector<double> decoded_result;
    encoder9.decode(pt_result9, decoded_result);
    double predicted_ckks = decoded_result[0];

    p9out_opt << fixed << setprecision(2)
              << input_x << "," << actual_y << "," << predicted_plain << "," << predicted_ckks << ","
              << (predicted_plain - actual_y) << "," << (predicted_ckks - actual_y) << ","
	      << (MemoryManager::GetPool().alloc_byte_count() >> 10) << "\n";
		
}


p9out_opt.close();
auto t_end_opt = chrono::high_resolution_clock::now();
auto duration_opt = chrono::duration_cast<chrono::milliseconds>(t_end_opt - t_start_opt).count();
cout << "⏱️ Optimized Runtime: " << duration_opt << " ms\n";

// === Calculate aggregated accuracy metrics for Optimized run ===
{
    ifstream in_file("prediction_optimised.csv");
    string line;
    getline(in_file, line); // skip header
    double mae = 0.0, rmse = 0.0, mape = 0.0;
    int count = 0;

    while (getline(in_file, line)) {
        stringstream ss(line);
        string token;
        vector<string> cols;
        while (getline(ss, token, ',')) cols.push_back(token);
        if (cols.size() >= 6) {
            double actual_y = stod(cols[1]);
            double pred_ckks = stod(cols[3]);
            double err = pred_ckks - actual_y;
            mae += fabs(err);
            rmse += err * err;
            if (actual_y != 0) mape += fabs(err / actual_y);
            count++;
        }
    }
    in_file.close();

    if (count > 0) {
        mae /= count;
        rmse = sqrt(rmse / count);
        mape = (mape / count) * 100.0;

        ofstream out_file("prediction_optimised.csv", ios::app);
        out_file << "SUMMARY(MAE,RMSE,MAPE%),"
                 << mae << "," << rmse << "," << mape << "\n";
        out_file.close();

        cout << "[Optimised Metrics] MAE: " << mae
             << " | RMSE: " << rmse
             << " | MAPE%: " << mape << "\n";
    }
}

// === [CUSTOM] Parameter variation (coeff_modulus & scale) with slope/intercept + metrics to CSV ===
// === Parameter Variation Benchmarking (coeff_modulus + scale) ===
{
    cout << "\n=== Parameter Variation Benchmarking (poly_modulus_degree = " << poly_deg << ") ===\n";
         cout << " Values are saved in benchmark_param_variation.csv \n";

    // Take first N rows for reproducibility
    size_t subset_size = min(static_cast<size_t>(20), usable);
    vector<double> x_sub(x.begin(), x.begin() + subset_size);
    vector<double> y_sub(y.begin(), y.begin() + subset_size);

    // Define coeff_modulus bit configurations for the chosen poly_deg
    vector<vector<int>> coeff_mod_variants;
    if (poly_deg == 4096) {
        coeff_mod_variants = {
            {30, 30, 30},
            {36, 36, 36},
            {40, 40, 40}
        };
    } else if (poly_deg == 8192) {
        coeff_mod_variants = {
            {50, 30, 30, 50},
            {60, 40, 40, 60},
            {50, 40, 40, 50}
        };
    } else if (poly_deg == 16384) {
        coeff_mod_variants = {
            {50, 30, 30, 50},
            {60, 40, 40, 60},
            {54, 38, 38, 54}
        };
    }

    // Define scale factors to test
    vector<double> scales = { pow(2.0, 20), pow(2.0, 30), pow(2.0, 40) };

    // Open CSV log file
    ofstream pv_log("benchmark_param_variation.csv", ios::trunc);
    pv_log << "poly_deg,coeff_modulus_bits,scale,enc_time_ms,mem_kb,slope,intercept,mae,rmse,mape\n";

    // Loop over parameter combinations
    for (auto &cm_bits : coeff_mod_variants) {
        for (auto &sc : scales) {

            auto t_start = chrono::high_resolution_clock::now();

            // Setup parameters
            EncryptionParameters parms_var(scheme_type::ckks);
            parms_var.set_poly_modulus_degree(poly_deg);
            parms_var.set_coeff_modulus(CoeffModulus::Create(poly_deg, cm_bits));

            SEALContext context_var(parms_var);
            KeyGenerator keygen_var(context_var);
            PublicKey pub_key_var;
            keygen_var.create_public_key(pub_key_var);
            SecretKey sec_key_var = keygen_var.secret_key();
            RelinKeys relin_keys_var;
            keygen_var.create_relin_keys(relin_keys_var);
            GaloisKeys galois_keys_var;
            keygen_var.create_galois_keys(galois_keys_var);

            Encryptor encryptor_var(context_var, pub_key_var);
            Decryptor decryptor_var(context_var, sec_key_var);
            Evaluator evaluator_var(context_var);
            CKKSEncoder encoder_var(context_var);

            // Encode and encrypt
            Plaintext plain_x_var, plain_y_var;
            encoder_var.encode(x_sub, sc, plain_x_var);
            encoder_var.encode(y_sub, sc, plain_y_var);

            Ciphertext enc_x_var, enc_y_var;
            encryptor_var.encrypt(plain_x_var, enc_x_var);
            encryptor_var.encrypt(plain_y_var, enc_y_var);

            // Multiply x*x
            Ciphertext enc_x_sq_var;
            evaluator_var.multiply(enc_x_var, enc_x_var, enc_x_sq_var);
            evaluator_var.relinearize_inplace(enc_x_sq_var, relin_keys_var);
            evaluator_var.rescale_to_next_inplace(enc_x_sq_var);

            // Multiply x*y
            Ciphertext enc_xy_var;
            evaluator_var.multiply(enc_x_var, enc_y_var, enc_xy_var);
            evaluator_var.relinearize_inplace(enc_xy_var, relin_keys_var);
            evaluator_var.rescale_to_next_inplace(enc_xy_var);

            // Sum slots
            auto sum_slots_var = [&](Ciphertext &ct) {
                Ciphertext sum = ct;
                for (int i = 1; i < static_cast<int>(subset_size); i <<= 1) {
                    Ciphertext rotated;
                    evaluator_var.rotate_vector(sum, i, galois_keys_var, rotated);
                    evaluator_var.add_inplace(sum, rotated);
                }
                return sum;
            };

            Ciphertext sum_x_var = sum_slots_var(enc_x_var);
            Ciphertext sum_y_var = sum_slots_var(enc_y_var);
            Ciphertext sum_xy_var = sum_slots_var(enc_xy_var);
            Ciphertext sum_x_sq_var = sum_slots_var(enc_x_sq_var);

            // Decrypt & decode
            Plaintext dec_sum_x_var, dec_sum_y_var, dec_sum_xy_var, dec_sum_x_sq_var;
            decryptor_var.decrypt(sum_x_var, dec_sum_x_var);
            decryptor_var.decrypt(sum_y_var, dec_sum_y_var);
            decryptor_var.decrypt(sum_xy_var, dec_sum_xy_var);
            decryptor_var.decrypt(sum_x_sq_var, dec_sum_x_sq_var);

            vector<double> res_x_var, res_y_var, res_xy_var, res_x_sq_var;
            encoder_var.decode(dec_sum_x_var, res_x_var);
            encoder_var.decode(dec_sum_y_var, res_y_var);
            encoder_var.decode(dec_sum_xy_var, res_xy_var);
            encoder_var.decode(dec_sum_x_sq_var, res_x_sq_var);

            // Compute slope & intercept
            double mean_x = res_x_var[0] / subset_size;
            double mean_y = res_y_var[0] / subset_size;
            double mean_xy = res_xy_var[0] / subset_size;
            double mean_x_sq = res_x_sq_var[0] / subset_size;

            double slope_var = (mean_xy - mean_x * mean_y) / (mean_x_sq - mean_x * mean_x);
            double intercept_var = mean_y - slope_var * mean_x;

            // Accuracy metrics
            double mae = 0.0, rmse = 0.0, mape = 0.0;
            for (size_t i = 0; i < subset_size; i++) {
                double actual_y = slope_var * x_sub[i] + intercept_var;
                double err = actual_y - y_sub[i];
                mae += fabs(err);
                rmse += err * err;
                if (y_sub[i] != 0) mape += fabs(err / y_sub[i]);
            }
            mae /= subset_size;
            rmse = sqrt(rmse / subset_size);
            mape = (mape / subset_size) * 100.0;

            auto t_end = chrono::high_resolution_clock::now();
            auto enc_time_ms = chrono::duration_cast<chrono::milliseconds>(t_end - t_start).count();
            size_t mem_kb = MemoryManager::GetPool().alloc_byte_count() >> 10;
         
                     // Log to CSV (formatted numbers)
            string coeff_bits_str;
            for (size_t i = 0; i < cm_bits.size(); i++) {
                coeff_bits_str += to_string(cm_bits[i]);
                if (i != cm_bits.size() - 1) coeff_bits_str += "-";
            }
            

             // Convert scale to integer for clean CSV output
            uint64_t scale_int = static_cast<uint64_t>(sc + 0.5); // round to nearest integer

            pv_log << poly_deg << "," 
               << coeff_bits_str << "," 
               << scale_int << ","  // ✅ No formatting issues here
               << enc_time_ms << "," 
               << mem_kb << "," 
               << fixed << setprecision(6) << slope_var << "," 
               << intercept_var << "," 
               << mae << "," 
               << rmse << "," 
               << mape << "\n";
        
       }
    }
    pv_log.close();
}

}




