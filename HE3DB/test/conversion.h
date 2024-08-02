#ifndef _CONVERSION_H_
#define _CONVERSION_H_

#include "HEDB/comparison/comparison.h"
#include "HEDB/conversion/repack.h"
#include "HEDB/utils/utils.h"
#include "rlwe.hpp"

using namespace HEDB;
using namespace std;

template <typename T = Lvl1>
void conversion(std::vector<seal::Ciphertext> &results,
                std::vector<std::vector<TLWELvl1>> &pred_cres,
                std::vector<std::vector<uint32_t>> &pred_res, RLWE<T> &rlwe,
                double &conversion_time) {
  size_t groupby_num = pred_cres.size();
  size_t slots_count = pred_cres[0].size();

  // conversion
  std::cout << "Starting Conversion..." << std::endl;
  results.resize(groupby_num);
  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();

  for (size_t i = 0; i < groupby_num; i++) {
    LWEsToRLWE(results[i], pred_cres[i], rlwe.pre_key, rlwe.scale,
               std::pow(2., rlwe.modq_bits),
               std::pow(2., rlwe.modulus_bits - rlwe.modq_bits),
               *rlwe.p_ckks_encoder, rlwe.galois_keys, rlwe.relin_keys,
               *rlwe.p_evaluator, *rlwe.p_context);
    HomRound(results[i], results[i].scale(), *rlwe.p_ckks_encoder,
             rlwe.relin_keys, *rlwe.p_evaluator, *rlwe.p_decryptor,
             *rlwe.p_context);
  }
  end = std::chrono::system_clock::now();

  conversion_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
          .count();

  std::cout << "[LWEsToRLWE] " << conversion_time / 1000 << std::endl;

#ifndef NOCHECK
  std::vector<seal::Plaintext> plain(groupby_num);
  std::vector<std::vector<double>> computed(groupby_num,
                                            std::vector<double>(slots_count));
  for (size_t i = 0; i < groupby_num; i++) {
    (*rlwe.p_decryptor).decrypt(results[i], plain[i]);
    seal::pack_decode(computed[i], plain[i], *rlwe.p_ckks_encoder);
  }

  std::vector<double> err(groupby_num, 0.);
  for (size_t i = 0; i < groupby_num; i++) {
    for (size_t j = 0; j < slots_count; ++j) {
      err[i] += std::abs(computed[i][j] - pred_res[i][j]);
    }

    printf("Repack average error in %02ld = %f ~ 2^%.1f\n", i,
           err[i] / slots_count, std::log2(err[i] / slots_count));
  }
#endif
}

/* only for throughput evaluation */
template <typename T = Lvl1>
void conversion(std::vector<seal::Ciphertext> &results,
                std::vector<std::vector<TLWELvl1>> &pred_cres, RLWE<T> &rlwe) {
  size_t groupby_num = pred_cres.size();
  size_t slots_count = pred_cres[0].size();

  // conversion
  std::cout << "Starting Conversion..." << std::endl;
  results.resize(groupby_num);

  for (size_t i = 0; i < groupby_num; i++) {
    LWEsToRLWE(results[i], pred_cres[i], rlwe.pre_key, rlwe.scale,
               std::pow(2., rlwe.modq_bits),
               std::pow(2., rlwe.modulus_bits - rlwe.modq_bits),
               *rlwe.p_ckks_encoder, rlwe.galois_keys, rlwe.relin_keys,
               *rlwe.p_evaluator, *rlwe.p_context);
    HomRound(results[i], results[i].scale(), *rlwe.p_ckks_encoder,
             rlwe.relin_keys, *rlwe.p_evaluator, *rlwe.p_decryptor,
             *rlwe.p_context);
  }
}

#endif
