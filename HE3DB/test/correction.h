#ifndef _CORRECTION_H_
#define _CORRECTION_H_

#include "HEDB/comparison/comparison.h"
#include "HEDB/conversion/repack.h"
#include "HEDB/utils/utils.h"
#include "cache_filter.hpp"
#include "rlwe.hpp"

using namespace HEDB;
using namespace std;

template <typename Lvl = Lvl1, typename T = Lvl::T>
void filter_correction(std::vector<seal::Ciphertext> &results,
                       std::vector<std::vector<uint32_t>> &pred_res,
                       RLWE<Lvl> &rlwe,
                       std::vector<std::vector<CacheFilter>> &filters,
                       /* group */
                       std::vector<std::vector<CacheFilter>> &gfilters,
                       double &correction_time) {
  assert(gfilters.empty() ||
         (std::accumulate(gfilters.begin(), gfilters.end(), 1,
                          [](size_t product, const auto &vec) {
                            return product * vec.size();
                          }) == results.size()) &&
             "Invalid size");

  std::cout << "Start Correction.." << std::endl;
  std::vector<seal::Ciphertext> correct_filters;
  std::vector<std::vector<seal::Ciphertext>> correct_gfilters(results.size());
  auto start = std::chrono::high_resolution_clock::now();
  // correction, first predicates
  seal::Ciphertext res;
  bool res_init = false;
  for (size_t i = 0; i < filters.size(); ++i) {
    // check each filter, find ckks filter
    for (size_t j = 0; j < filters[i].size(); ++j) {
      auto &filter = filters[i][j];
      if (filter.is_ckks()) {
        if (filter.is_and()) {
          auto ckks_filter = filter.get_ckks_filter();
          correct_filters.push_back(ckks_filter);
          if (!res_init) {
            res = ckks_filter;
            res_init = true;
          } else {
            seal::multiply_and_relinearize(ckks_filter, res, res,
                                           *rlwe.p_evaluator, rlwe.relin_keys);
          }
        } else
          assert("Not implemented.");
      }
    }
  }

  // gfilters
  if (gfilters.empty()) {
    assert(results.size() == 1);
    if (res_init) {
      seal::multiply_and_relinearize(res, results[0], results[0],
                                     *rlwe.p_evaluator, rlwe.relin_keys);
      rlwe.p_evaluator->rescale_to_next_inplace(results[0]);
    }
  } else {
    size_t grp_num = results.size();
    std::vector<size_t> indices(gfilters.size(), 0);
    for (size_t i = 0; i < grp_num; i++) {
      seal::Ciphertext gres;
      bool gres_init = false;
      for (size_t j = 0; j < gfilters.size(); ++j) {
        auto gfilter = gfilters[j][indices[j]];
        if (gfilter.is_invalid()) continue;
        assert(gfilter.is_and() && "Not implemented.");
        if (gfilter.is_ckks()) {
          auto _filter = gfilter.get_ckks_filter();
          correct_gfilters[i].push_back(_filter);
          if (!gres_init) {
            gres = _filter;
            gres_init = true;
          } else
            seal::multiply_and_relinearize(gres, _filter, gres,
                                           *rlwe.p_evaluator, rlwe.relin_keys);
        }
      }
      if (!gres_init) {
        if (res_init) {
          seal::multiply_and_relinearize(res, results[i], results[i],
                                         *rlwe.p_evaluator, rlwe.relin_keys);
          rlwe.p_evaluator->rescale_to_next_inplace(results[i]);
        }
      } else {
        if (res_init) {
          seal::multiply_and_relinearize(gres, res, gres, *rlwe.p_evaluator,
                                         rlwe.relin_keys);
        }
        seal::multiply_and_relinearize(gres, results[i], results[i],
                                       *rlwe.p_evaluator, rlwe.relin_keys);
        rlwe.p_evaluator->rescale_to_next_inplace(results[i]);
      }
      // Move to next
      for (size_t k = gfilters.size(); k-- > 0;) {
        if (++indices[k] < gfilters[k].size()) {
          break;
        }
        indices[k] = 0;
      }
    }
  }

  auto end = std::chrono::high_resolution_clock::now();
  correction_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
          .count();
  std::cout << "[Correction] " << correction_time / 1000 << std::endl;

#ifndef NOCHECK
  size_t groupby_num = pred_res.size();
  size_t slots_count = pred_res[0].size();
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

    printf("Correction average error in %02ld = %f ~ 2^%.1f\n", i,
           err[i] / slots_count, std::log2(err[i] / slots_count));
  }
#endif
}

/* only used for thoughput evaluation */
template <typename Lvl = Lvl1, typename T = Lvl::T>
void filter_correction(std::vector<seal::Ciphertext> &results,
                       RLWE<Lvl> &rlwe,
                       std::vector<std::vector<CacheFilter>> &filters,
                       /* group */
                       std::vector<std::vector<CacheFilter>> &gfilters) {

  std::vector<seal::Ciphertext> correct_filters;
  std::vector<std::vector<seal::Ciphertext>> correct_gfilters(results.size());
  auto start = std::chrono::high_resolution_clock::now();
  // correction, first predicates
  seal::Ciphertext res;
  bool res_init = false;
  for (size_t i = 0; i < filters.size(); ++i) {
    // check each filter, find ckks filter
    for (size_t j = 0; j < filters[i].size(); ++j) {
      auto &filter = filters[i][j];
      if (filter.is_ckks()) {
        if (filter.is_and()) {
          auto ckks_filter = filter.get_ckks_filter();
          correct_filters.push_back(ckks_filter);
          if (!res_init) {
            res = ckks_filter;
            res_init = true;
          } else {
            seal::multiply_and_relinearize(ckks_filter, res, res,
                                           *rlwe.p_evaluator, rlwe.relin_keys);
          }
        } else
          assert("Not implemented.");
      }
    }
  }

  // gfilters
  if (gfilters.empty()) {
    assert(results.size() == 1);
    if (res_init) {
      seal::multiply_and_relinearize(res, results[0], results[0],
                                     *rlwe.p_evaluator, rlwe.relin_keys);
      rlwe.p_evaluator->rescale_to_next_inplace(results[0]);
    }
  } else {
    size_t grp_num = results.size();
    std::vector<size_t> indices(gfilters.size(), 0);
    for (size_t i = 0; i < grp_num; i++) {
      seal::Ciphertext gres;
      bool gres_init = false;
      for (size_t j = 0; j < gfilters.size(); ++j) {
        auto gfilter = gfilters[j][indices[j]];
        if (gfilter.is_invalid()) continue;
        assert(gfilter.is_and() && "Not implemented.");
        if (gfilter.is_ckks()) {
          auto _filter = gfilter.get_ckks_filter();
          correct_gfilters[i].push_back(_filter);
          if (!gres_init) {
            gres = _filter;
            gres_init = true;
          } else
            seal::multiply_and_relinearize(gres, _filter, gres,
                                           *rlwe.p_evaluator, rlwe.relin_keys);
        }
      }
      if (!gres_init) {
        if (res_init) {
          seal::multiply_and_relinearize(res, results[i], results[i],
                                         *rlwe.p_evaluator, rlwe.relin_keys);
          rlwe.p_evaluator->rescale_to_next_inplace(results[i]);
        }
      } else {
        if (res_init) {
          seal::multiply_and_relinearize(gres, res, gres, *rlwe.p_evaluator,
                                         rlwe.relin_keys);
        }
        seal::multiply_and_relinearize(gres, results[i], results[i],
                                       *rlwe.p_evaluator, rlwe.relin_keys);
        rlwe.p_evaluator->rescale_to_next_inplace(results[i]);
      }
      // Move to next
      for (size_t k = gfilters.size(); k-- > 0;) {
        if (++indices[k] < gfilters[k].size()) {
          break;
        }
        indices[k] = 0;
      }
    }
  }
}

inline void tfhe_correction(CacheFilter &filter, TLWELvl1 &results,
                            TFHEEvalKey &ek, size_t i, bool &op) {
  bool _op = false;
  // hit!
  if (filter.is_tfhe()) {
    results = filter.get_tfhe_filter(i);
    _op = true;
  }
  op = op || _op;
  return;
}

inline void tfhe_correction(std::vector<CacheFilter> &filters,
                            TLWELvl1 &results, TFHEEvalKey &ek, size_t i,
                            bool &op) {
  bool _op = false;
  if (filters.size() == 1) {
    tfhe_correction(filters[0], results, ek, i, _op);
    op = op || _op;
    return;
  }
  for (size_t j = 0; j < filters.size(); j++) {
    auto &filter = filters[j];
    if (filter.is_tfhe()) {
      if (filter.is_or()) {
        HEDB::HomOR(results, results, filter.get_tfhe_filter(i), ek, LOGIC);
        _op = true;
      }
      if (filter.is_and()) {
        HEDB::HomAND(results, results, filter.get_tfhe_filter(i), ek, LOGIC);
        _op = true;
      }
    }
  }
  op = op || _op;
}

inline void tfhe_correction(std::vector<CacheFilter> &filters,
                            TLWELvl1 &results, TFHEEvalKey &ek, size_t i) {
  bool op = false;
  tfhe_correction(filters, results, ek, i, op);
}

#endif
