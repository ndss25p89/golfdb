#include "conversion.h"
#include "basic_query4.h"
#include "serialize.h"

using namespace HEDB;
using namespace std;

/***
 * TPC-H Query 4 modified
 select
    o_orderpriority,
    count(*) as order_count
  from
    orders
  where
    o_orderdate >= date '1996-07-01'
    and o_orderdate < date '1996-07-01' + interval '3' month
    and exists (
      select
        *
      from
        lineitem
      where
        l_orderkey = o_orderkey
        and l_commitdate < l_receiptdate
    )
  group by
    o_orderpriority

    consider data encode by [yyyymmdd], 26 bits,
    group by $m$ types of o_orderpriority,
    l_orderkey and o_orderkey are in plaintext, so the exists part
    can be convert into a predicate `l_commitdate < l_receiptdate`
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
  std::vector<TLWELvl2> orderdate_ciphers(rows), commitdate_ciphers(rows),
      receiptdate_ciphers(rows);
  std::vector<TLWELvl1> orderpriority_ciphers(rows);
  for (size_t i = 0; i < rows; i++) {
    auto row_data = data[i];
    orderdate_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
        row_data.orderdate().value, Lvl2::α,
        pow(2., row_data.orderdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
    commitdate_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
        row_data.commitdate().value, Lvl2::α,
        pow(2., row_data.commitdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
    receiptdate_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
        row_data.receiptdate().value, Lvl2::α,
        pow(2., row_data.receiptdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
    orderpriority_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl1>(
        row_data.orderpriority().value, Lvl1::α,
        pow(2., row_data.orderpriority().scale_bits<Lvl1>()),
        sk.key.get<Lvl1>());
  }

  // Encrypt Predicate values
  std::cout << "Encrypting Predicate Values..." << std::endl;

  // check if the predicate is correct
  auto groupby_num = query_data.groupby_num();
  // pred_orderdate[rows]
  std::vector<uint32_t> pred_orderdate1_res(rows, 0);
  std::vector<uint32_t> pred_orderdate2_res(rows, 0);
  // pred_exsits[rows]
  std::vector<uint32_t> pred_exsits_res(rows, 0);
  // pred_result
  std::vector<uint32_t> pred_pred_res(rows, 0);
  // pred_group[rows][groupby_num]
  std::vector<std::vector<uint32_t>> pred_group_res(
      rows, std::vector<uint32_t>(groupby_num, 0));
  // pred_res[groupby_num][rows]
  pred_res.resize(groupby_num, std::vector<uint32_t>(rows, 1));
  pred_cres.resize(groupby_num, std::vector<TLWELvl1>(rows));

  // pred_part & pred_group
  for (size_t i = 0; i < rows; i++) {
    auto orderdate_low = query_data.orderdate1();
    auto orderdate_up = query_data.orderdate2();
    pred_orderdate1_res[i] =
        !!(data[i].orderdate().value >= orderdate_low.value);
    pred_orderdate2_res[i] = !!(data[i].orderdate().value < orderdate_up.value);
    pred_exsits_res[i] =
        !!((data[i].commitdate().value < data[i].receiptdate().value));
    pred_pred_res[i] = !!(pred_orderdate1_res[i] & pred_orderdate2_res[i] &
                          pred_exsits_res[i]);
    for (size_t j = 0; j < groupby_num; j++) {
      auto index = query_data.group_index(j);
      pred_group_res[i][j] = !!(data[i].orderpriority().value ==
                                query_data.orderpriority()[index[0]].value);
    }
  }
  // pred_res
  for (size_t i = 0; i < groupby_num; i++) {
    for (size_t j = 0; j < rows; j++) {
      pred_res[i][j] = pred_group_res[j][i] & pred_pred_res[j];
    }
  }

  // Encrypt Predicates
  TLWELvl2 pred_cipher_orderdate1, pred_cipher_orderdate2;
  // pred_cipher_group
  std::vector<TLWELvl1> pred_cipher_orderpriority;
  // encrypt predicate part
  pred_cipher_orderdate1 = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.orderdate1().value, Lvl2::α,
      pow(2., data[0].orderdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  pred_cipher_orderdate2 = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.orderdate2().value, Lvl2::α,
      pow(2., data[0].orderdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  // encrypt group by part
  double orderpriority_scale =
      pow(2., data[0].orderpriority().scale_bits<Lvl1>());
  auto orderpriority_group = query_data.orderpriority();
  pred_cipher_orderpriority.resize(orderpriority_group.size());
  for (size_t i = 0; i < orderpriority_group.size(); i++) {
    pred_cipher_orderpriority[i] = TFHEpp::tlweSymInt32Encrypt<Lvl1>(
        orderpriority_group[i].value, Lvl1::α, orderpriority_scale,
        sk.key.get<Lvl1>());
  }

  // Predicate Evaluation
  std::cout << "Start Predicate Evaluation..." << std::endl;
  std::vector<TLWELvl1> pred_orderdate1_cres(rows), pred_orderdate2_cres(rows);
  std::vector<TLWELvl1> pred_exsits_cres(rows);
  std::vector<TLWELvl1> pred_pred_cres(rows);
  auto orderdate_bits = data[0].orderdate().bits;
  auto exsits_bits = data[0].commitdate().bits;
  assert(data[0].commitdate().bits == data[0].receiptdate().bits);
  std::vector<std::vector<TLWELvl1>> pred_group_cres(
      rows, std::vector<TLWELvl1>(groupby_num));
  auto orderpriority_bits = data[0].orderpriority().bits;
  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();
  for (size_t i = 0; i < rows; i++) {
    greater_than_equal<Lvl2>(orderdate_ciphers[i], pred_cipher_orderdate1,
                             pred_orderdate1_cres[i], orderdate_bits, ek,
                             LOGIC);
    less_than<Lvl2>(orderdate_ciphers[i], pred_cipher_orderdate2,
                    pred_orderdate2_cres[i], orderdate_bits, ek, LOGIC);

    less_than<Lvl2>(commitdate_ciphers[i], receiptdate_ciphers[i],
                    pred_exsits_cres[i], exsits_bits, ek, LOGIC);
    HomAND(pred_pred_cres[i], pred_orderdate1_cres[i], pred_orderdate2_cres[i],
           ek, LOGIC);
    HomAND(pred_pred_cres[i], pred_pred_cres[i], pred_exsits_cres[i], ek,
           LOGIC);
    for (size_t j = 0; j < groupby_num; j++) {
      auto index = query_data.group_index(j);
      equal<Lvl1>(pred_cipher_orderpriority[index[0]], orderpriority_ciphers[i],
                  pred_group_cres[i][j], orderpriority_bits, ek, LOGIC);
      HomAND(pred_cres[j][i], pred_group_cres[i][j], pred_pred_cres[i], ek,
             ARITHMETIC);
    }
  }
  end = std::chrono::system_clock::now();

#ifndef NOCHECK
  // check the results
  std::vector<std::vector<uint32_t>> pred_cres_de(groupby_num,
                                                  std::vector<uint32_t>(rows));
  std::vector<uint32_t> pred_orderdate1_cres_de(rows),
      pred_orderdate2_cres_de(rows);
  std::vector<uint32_t> pred_exsits_cres_de(rows);
  std::vector<uint32_t> pred_pred_cres_de(rows);
  std::vector<std::vector<uint32_t>> pred_group_cres_de(
      rows, std::vector<uint32_t>(groupby_num));
  for (size_t i = 0; i < rows; i++) {
    pred_orderdate1_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_orderdate1_cres[i], sk.key.lvl1);
    pred_orderdate2_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_orderdate2_cres[i], sk.key.lvl1);
    pred_exsits_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_exsits_cres[i], sk.key.lvl1);
    pred_pred_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_pred_cres[i], sk.key.lvl1);
    for (size_t j = 0; j < groupby_num; j++) {
      pred_cres_de[j][i] = TFHEpp::tlweSymInt32Decrypt<Lvl1>(
          pred_cres[j][i], pow(2., 31), sk.key.get<Lvl1>());
      pred_group_cres_de[i][j] =
          TFHEpp::tlweSymDecrypt<Lvl1>(pred_group_cres[i][j], sk.key.lvl1);
    }
  }

  size_t error_time = 0;

  uint32_t rlwe_scale_bits = 29;
  for (size_t i = 0; i < rows; i++)
    for (size_t j = 0; j < groupby_num; j++) {
      TFHEpp::ari_rescale(pred_cres[j][i], pred_cres[j][i], rlwe_scale_bits,
                          ek);
    }
  for (size_t i = 0; i < rows; i++)
    for (size_t j = 0; j < groupby_num; j++) {
      pred_cres_de[j][i] = TFHEpp::tlweSymInt32Decrypt<Lvl1>(
          pred_cres[j][i], pow(2., 29), sk.key.get<Lvl1>());
    }
  for (size_t i = 0; i < rows; i++)
    for (size_t j = 0; j < groupby_num; j++)
      error_time += (pred_cres_de[j][i] == pred_res[j][i]) ? 0 : 1;
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

  for (size_t i = 0; i < rows; i++) {
    count_data[i] = 1.0;
  }

  // convert data to ciphertext
  seal::Plaintext t_plain;
  double qd =
      rlwe.parms.coeff_modulus()[result[0].coeff_modulus_size() - 1].value();
  for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
    seal::pack_encode(_data_plaintext, qd, t_plain, *rlwe.p_ckks_encoder);
    (*rlwe.p_encryptor).encrypt_symmetric(t_plain, _data_cipher);
  }

  std::cout << "Aggregating count .." << std::endl;
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
  int orderpriority_size = 3;
  for (size_t i = 0; i < rows; i++) {
    data[i].init(orderpriority_size);
  }
  query_data.init(orderpriority_size);

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
