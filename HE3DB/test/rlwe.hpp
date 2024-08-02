#ifndef _RLWE_HPP_
#define _RLWE_HPP_

#include "HEDB/comparison/comparison.h"
#include "HEDB/conversion/repack.h"
#include "HEDB/utils/utils.h"

using namespace HEDB;
using namespace std;

template <typename T = Lvl1>
class RLWE {
 public:
  const uint64_t scale_bits = 29;
  const uint64_t modq_bits = 32;
  const uint64_t modulus_bits = 45;
  const uint64_t repack_scale_bits = modulus_bits + scale_bits - modq_bits;
  const size_t poly_modulus_degree = 65536;
  const double scale = std::pow(2.0, scale_bits);

  seal::EncryptionParameters parms;
  seal::SEALContext *p_context;

  // keys
  seal::RelinKeys relin_keys;
  seal::GaloisKeys galois_keys;
  LTPreKey pre_key;

  // utils
  seal::Encryptor *p_encryptor;
  seal::Evaluator *p_evaluator;
  seal::Decryptor *p_decryptor;
  seal::CKKSEncoder *p_ckks_encoder;

 private:
  std::vector<size_t> rows;
  // keys
  seal::SecretKey seal_secret_key;
  TFHESecretKey sk;

 public:
  RLWE() : parms(seal::scheme_type::ckks) {}
  RLWE(TFHESecretKey &sk, std::vector<size_t> &rows = {})
      : sk(sk), rows(rows), parms(seal::scheme_type::ckks) {
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(seal::CoeffModulus::Create(
        poly_modulus_degree,
        {59, 42, 42, 42, 42, 42, 42, 42, 45, 45, 45, 45, 45,
         45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 45, 59}));
    p_context = new seal::SEALContext(parms, true, seal::sec_level_type::none);
    // key generation
    seal::KeyGenerator keygen = seal::KeyGenerator(*p_context);
    ckks_key(keygen);
    // utils
    p_encryptor = new seal::Encryptor(*p_context, seal_secret_key);
    p_evaluator = new seal::Evaluator(*p_context);
    p_decryptor = new seal::Decryptor(*p_context, seal_secret_key);
    // encoder
    p_ckks_encoder = new seal::CKKSEncoder(*p_context);

    conversion_key();
  }
  ~RLWE() {
    delete p_context;
    delete p_encryptor;
    delete p_evaluator;
    delete p_decryptor;
    delete p_ckks_encoder;
  }

 private:
  inline void ckks_key(seal::KeyGenerator &keygen) {
    seal_secret_key = keygen.secret_key();
    std::cout << "Generating Parameters relin_keys..." << std::endl;
    keygen.create_relin_keys(relin_keys);
    std::cout << "Generating Parameters galois_keys..." << std::endl;
    if (rows.size()) {
      std::set<size_t> steps;
      std::vector<uint32_t> galois_elts;
      auto galois_tool = p_context->key_context_data()->galois_tool();
      for (auto row : rows) {
        size_t log_slots = ceil(log2(row));
        // Specify the rotations you want
        for (size_t j = 1; j < (1 << log_slots); j <<= 1) {
          steps.insert(j);
        }
        size_t min_len = std::min(row, (size_t)Lvl1::n);
        size_t g_tilde = CeilSqrt(min_len);
        size_t b_tilde = CeilDiv(min_len, g_tilde);
        for (size_t b = 1; b < b_tilde && g_tilde * b < min_len; ++b) {
          steps.insert(b * g_tilde);
        }
        if (row < (size_t)Lvl1::n) {
          size_t gama = std::log2((size_t)Lvl1::n / row);
          for (size_t j = 0; j < gama; j++) {
            steps.insert((1U << j) * row);
          }
        }
      }

      // convert to the elt step
      for (auto step : steps)
        galois_elts.push_back(galois_tool->get_elt_from_step(step));

      keygen.create_galois_keys(galois_elts, galois_keys);
    } else
      keygen.create_galois_keys(galois_keys);
  }

  inline void conversion_key() {
    // generate evaluation key
    std::cout << "Generating Conversion Key..." << std::endl;
    LWEsToRLWEKeyGen(pre_key, std::pow(2., modulus_bits), seal_secret_key, sk,
                     T::n, *p_ckks_encoder, *p_encryptor, *p_context);
  }
};

#endif
