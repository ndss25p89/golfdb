#include "conversion.h"
#include "basic_query6.h"
#include "serialize.h"

using namespace HEDB;
using namespace std;

/***
 * TPC-H Query 6
  select
    sum(l_extendedprice * l_discount) as revenue
  from
    lineitem
  where
    l_shipdate >= date ':1'
    and l_shipdate < date ':1' + interval '1' year
    and l_discount between :2 - 0.01 and :2 + 0.01
    and l_quantity < :3;

    consider data \in [20200101~20221231]
*/

void predicate_evaluation(std::vector<std::vector<TLWELvl1>> &pred_cres,
                          std::vector<std::vector<uint32_t>> &pred_res,
                          size_t rows, std::vector<DataRecord> &data,
                          QueryRequest &query_data, TFHESecretKey &sk,
                          TFHEEvalKey &ek, double &filter_time) {
  std::cout << "Predicate evaluation: " << std::endl;
  using P = Lvl2;

  // Encrypt database
  std::cout << "Encrypting Database..." << std::endl;
  std::vector<TLWELvl2> shipdate_ciphers(rows), discount_ciphers(rows),
      quantity_ciphers(rows);
  for (size_t i = 0; i < rows; i++) {
    auto row_data = data[i];
    shipdate_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
        row_data.shipdate().value, Lvl2::α,
        pow(2., row_data.shipdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
    discount_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
        row_data.discount().value, Lvl2::α,
        pow(2., row_data.discount().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
    quantity_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
        row_data.quantity().value, Lvl2::α,
        pow(2., row_data.quantity().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  }

  // Encrypt Predicate values
  std::cout << "Encrypting Predicate Values..." << std::endl;

  // check if the predicate is correct
  auto groupby_num = query_data.groupby_num();
  // pred_shipdate[rows]
  std::vector<uint32_t> pred_shipdate1_res(rows, 0);
  std::vector<uint32_t> pred_shipdate2_res(rows, 0);
  // pred_discount[rows]
  std::vector<uint32_t> pred_discount1_res(rows, 0);
  std::vector<uint32_t> pred_discount2_res(rows, 0);
  // pred_quantity[rows]
  std::vector<uint32_t> pred_quantity_res(rows, 0);
  // pred_res[groupby_num][rows]
  pred_res.resize(groupby_num, std::vector<uint32_t>(rows, 1));
  pred_cres.resize(groupby_num, std::vector<TLWELvl1>(rows));

  // pred_part
  for (size_t i = 0; i < rows; i++) {
    auto shipdate_low = query_data.shipdate1();
    auto shipdate_up = query_data.shipdate2();
    pred_shipdate1_res[i] = !!(data[i].shipdate().value >= shipdate_low.value);
    pred_shipdate2_res[i] = !!(data[i].shipdate().value < shipdate_up.value);
    auto discount_low = query_data.discount1();
    auto discount_up = query_data.discount2();
    pred_discount1_res[i] = !!(data[i].discount().value >= discount_low.value);
    pred_discount2_res[i] = !!(data[i].discount().value <= discount_up.value);

    pred_quantity_res[i] =
        !!((data[i].quantity().value < query_data.quantity().value));
    // pred_res
    pred_res[0][i] = !!(pred_shipdate1_res[i] & pred_shipdate2_res[i] &
                        pred_discount1_res[i] & pred_discount2_res[i] &
                        pred_quantity_res[i]);
  }

  // Encrypt Predicates
  TLWELvl2 pred_cipher_shipdate1, pred_cipher_shipdate2;
  TLWELvl2 pred_cipher_discount1, pred_cipher_discount2;
  TLWELvl2 pred_cipher_quantity;
  // encrypt predicate part
  pred_cipher_shipdate1 = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.shipdate1().value, Lvl2::α,
      pow(2., data[0].shipdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  pred_cipher_shipdate2 = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.shipdate2().value, Lvl2::α,
      pow(2., data[0].shipdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  pred_cipher_discount1 = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.discount1().value, Lvl2::α,
      pow(2., data[0].discount().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  pred_cipher_discount2 = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.discount2().value, Lvl2::α,
      pow(2., data[0].discount().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  pred_cipher_quantity = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.quantity().value, Lvl2::α,
      pow(2., data[0].quantity().scale_bits<Lvl2>()), sk.key.get<Lvl2>());

  // Predicate Evaluation
  std::cout << "Start Predicate Evaluation..." << std::endl;
  std::vector<TLWELvl1> pred_shipdate1_cres(rows), pred_shipdate2_cres(rows);
  std::vector<TLWELvl1> pred_discount1_cres(rows), pred_discount2_cres(rows);
  std::vector<TLWELvl1> pred_quantity_cres(rows);
  auto shipdate_bits = data[0].shipdate().bits;
  auto discount_bits = data[0].discount().bits;
  auto quantity_bits = data[0].quantity().bits;

  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();
  for (size_t i = 0; i < rows; i++) {
    greater_than_equal<Lvl2>(shipdate_ciphers[i], pred_cipher_shipdate1,
                             pred_shipdate1_cres[i], shipdate_bits, ek, LOGIC);
    less_than<Lvl2>(shipdate_ciphers[i], pred_cipher_shipdate2,
                    pred_shipdate2_cres[i], shipdate_bits, ek, LOGIC);
    greater_than_equal<Lvl2>(discount_ciphers[i], pred_cipher_discount1,
                             pred_discount1_cres[i], discount_bits, ek, LOGIC);
    less_than_equal<Lvl2>(discount_ciphers[i], pred_cipher_discount2,
                          pred_discount2_cres[i], discount_bits, ek, LOGIC);
    less_than<Lvl2>(quantity_ciphers[i], pred_cipher_quantity,
                    pred_quantity_cres[i], quantity_bits, ek, LOGIC);
    HomAND(pred_cres[0][i], pred_shipdate1_cres[i], pred_shipdate2_cres[i], ek,
           LOGIC);
    HomAND(pred_cres[0][i], pred_cres[0][i], pred_discount1_cres[i], ek, LOGIC);
    HomAND(pred_cres[0][i], pred_cres[0][i], pred_discount2_cres[i], ek, LOGIC);
    HomAND(pred_cres[0][i], pred_cres[0][i], pred_quantity_cres[i], ek,
           ARITHMETIC);
  }
  end = std::chrono::system_clock::now();

#ifndef NOCHECK
  // check the results
  std::vector<std::vector<uint32_t>> pred_cres_de(groupby_num,
                                                  std::vector<uint32_t>(rows));
  std::vector<uint32_t> pred_shipdate1_cres_de(rows),
      pred_shipdate2_cres_de(rows);
  std::vector<uint32_t> pred_discount1_cres_de(rows),
      pred_discount2_cres_de(rows);
  std::vector<uint32_t> pred_quantity_cres_de(rows);
  for (size_t i = 0; i < rows; i++) {
    pred_shipdate1_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_shipdate1_cres[i], sk.key.lvl1);
    pred_shipdate2_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_shipdate2_cres[i], sk.key.lvl1);
    pred_discount1_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_discount1_cres[i], sk.key.lvl1);
    pred_discount2_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_discount2_cres[i], sk.key.lvl1);
    pred_quantity_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_quantity_cres[i], sk.key.lvl1);
    if (pred_shipdate1_cres_de[i] != pred_shipdate1_res[i]) {
      std::cout << "Predicate shipdate1 Error: " << pred_shipdate1_cres_de[i]
                << " " << pred_shipdate1_res[i] << std::endl;
    }
    if (pred_shipdate2_cres_de[i] != pred_shipdate2_res[i]) {
      std::cout << "Predicate shipdate2 Error: " << pred_shipdate2_cres_de[i]
                << " " << pred_shipdate2_res[i] << std::endl;
    }
    if (pred_discount1_cres_de[i] != pred_discount1_res[i]) {
      std::cout << "Predicate discount1 Error: " << pred_discount1_cres_de[i]
                << " " << pred_discount1_res[i] << std::endl;
    }
    if (pred_discount2_cres_de[i] != pred_discount2_res[i]) {
      std::cout << "Predicate discount2 Error: " << pred_discount2_cres_de[i]
                << " " << pred_discount2_res[i] << std::endl;
    }
    if (pred_quantity_cres_de[i] != pred_quantity_res[i]) {
      std::cout << "Predicate quantity Error: " << pred_quantity_cres_de[i]
                << " " << pred_quantity_res[i] << std::endl;
    }
    pred_cres_de[0][i] = TFHEpp::tlweSymInt32Decrypt<Lvl1>(
        pred_cres[0][i], pow(2., 31), sk.key.get<Lvl1>());
  }

  size_t error_time = 0;

  uint32_t rlwe_scale_bits = 29;
  for (size_t i = 0; i < rows; i++)
    TFHEpp::ari_rescale(pred_cres[0][i], pred_cres[0][i], rlwe_scale_bits, ek);
  for (size_t i = 0; i < rows; i++)
    pred_cres_de[0][i] = TFHEpp::tlweSymInt32Decrypt<Lvl1>(
        pred_cres[0][i], pow(2., 29), sk.key.get<Lvl1>());
  for (size_t i = 0; i < rows; i++)
    error_time += (pred_cres_de[0][i] == pred_res[0][i]) ? 0 : 1;
  // cout << "Predicate Evaluaton Time (s): " <<
  // std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
  // / 1000 << std::endl;
  cout << "Predicate Error: " << error_time << std::endl;
#endif
  filter_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
          .count();
  std::cout << "[Evaluation] " << filter_time / 1000 << std::endl;
}

template <typename T = Lvl1>
void aggregation(std::vector<seal::Ciphertext> &result,
                 std::vector<std::vector<uint32_t>> &pred_res,
                 std::vector<DataRecord> &data, size_t rows, RLWE<T> &rlwe,
                 double &aggregation_time) {
  std::cout << "Aggregation :" << std::endl;
  size_t groupby_num = result.size();
  uint64_t slots_count = rows;

  // Table for data, ciphertext, and aggregation results
  struct DataPack {
    std::vector<double> &data;
    seal::Ciphertext &cipher;
    std::vector<seal::Ciphertext> &sum;
  };

  // Filter result * data
  // original data
  std::vector<double> count_data(rows);
  // packed ciphertext
  seal::Ciphertext count_cipher;
  // sum result ciphertext
  std::vector<seal::Ciphertext> order_count(groupby_num);
  std::vector<DataPack> table = {{count_data, count_cipher, order_count}};

  auto double_scale = data[0].double_scale;
  for (size_t i = 0; i < rows; i++) {
    count_data[i] =
        data[i].extendedprice().value * data[i].discount().value / double_scale;
  }

  // convert data to ciphertext
  seal::Plaintext t_plain;
  double qd =
      rlwe.parms.coeff_modulus()[result[0].coeff_modulus_size() - 1].value();
  for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
    seal::pack_encode(_data_plaintext, qd, t_plain, *rlwe.p_ckks_encoder);
    (*rlwe.p_encryptor).encrypt_symmetric(t_plain, _data_cipher);
  }

  std::cout << "Aggregating price and discount .." << std::endl;
  // filtering the data
  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();
  for (size_t i = 0; i < groupby_num; ++i) {
    for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
      seal::multiply_and_relinearize(result[i], _data_cipher, _sum_cipher[i],
                                     *rlwe.p_evaluator, rlwe.relin_keys);
      (*rlwe.p_evaluator).rescale_to_next_inplace(_sum_cipher[i]);
    }
  }
  end = std::chrono::system_clock::now();
  aggregation_time =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
          .count();

  // sum to aggregation
  int logrow = log2(rows);
  seal::Ciphertext temp;
  start = std::chrono::system_clock::now();
  for (size_t i = 0; i < groupby_num; ++i) {
    for (size_t j = 0; j < logrow; j++) {
      size_t step = 1 << (logrow - j - 1);
      for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
        temp = _sum_cipher[i];
        (*rlwe.p_evaluator).rotate_vector_inplace(temp, step, rlwe.galois_keys);
        (*rlwe.p_evaluator).add_inplace(_sum_cipher[i], temp);
      }
    }
  }
  end = std::chrono::system_clock::now();
  aggregation_time +=
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
          .count();
  std::cout << "[Aggregation] " << aggregation_time / 1000 << std::endl;
#ifndef NOCHECK
  // Decrypt and check the result
  std::vector<double> agg_result(slots_count);
  for (size_t i = 0; i < groupby_num; ++i) {
    for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
      (*rlwe.p_decryptor).decrypt(_sum_cipher[i], t_plain);
      seal::pack_decode(agg_result, t_plain, *rlwe.p_ckks_encoder);
      double plain_result = 0;
      for (size_t j = 0; j < rows; j++) {
        plain_result += _data_plaintext[j] * pred_res[i][j];
      }
      cout << "Plain_result/Encrypted query result: " << plain_result << "/"
           << agg_result[0] << endl;
    }
  }
#endif
}

template <typename Lvl = Lvl1>
void query_evaluation(size_t rows, TFHESecretKey &sk, TFHEEvalKey &ek,
                      RLWE<Lvl> &rlwe) {
  cout << "===== Query Evaluation: " << rows << " rows =====" << endl;
  // Generate database
  vector<DataRecord> data(rows);
  QueryRequest query_data;
  for (size_t i = 0; i < rows; i++) {
    data[i].init();
  }
  query_data.init();

  double filter_time, conversion_time, aggregation_time;
  std::vector<std::vector<TLWELvl1>> pred_cres;
  std::vector<std::vector<uint32_t>> pred_res;
  std::vector<seal::Ciphertext> results;
  predicate_evaluation(pred_cres, pred_res, rows, data, query_data, sk, ek,
                       filter_time);
  conversion(results, pred_cres, pred_res, rlwe, conversion_time);
  aggregation(results, pred_res, data, rows, rlwe, aggregation_time);
  cout << "End-to-End Time: "
       << (filter_time + conversion_time + aggregation_time) / 1000 << " s"
       << endl;
}

int main() {
  TFHESecretKey sk;
  TFHEEvalKey ek;
  generate_sk_ek(sk, ek);
  std::vector<size_t> rows = {1 << 8, 1 << 10, 1 << 12, 1 << 14};
  RLWE<Lvl1> rlwe(sk, rows);
  for (auto row : rows)
    query_evaluation<Lvl1>(row, sk, ek, rlwe);
}
