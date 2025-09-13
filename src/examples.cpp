#include "seal/seal.h"
#include <iostream>
#include "ckks_health_csv_encrypt.cpp"
#include "ckks_encrypted_regression_health.cpp"
#include "ckks_health_regression_pipeline.cpp"
#include "ckks_health_regression_pipeline_phase4.cpp"
#include "ckks_health_regression_pipeline_phase5.cpp"
#include "ckks_health_regression_pipeline_phase7.cpp"
#include "ckks_health_regression_pipeline_phase5_optimized.cpp"
#include "ckks_insurance_regression.cpp"

int main()
{
    cout << "\nRunning CKKS Health Regression Pipeline..." << endl;
    ckks_insurance_regression();
    return 0;
}
