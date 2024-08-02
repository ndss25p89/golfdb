#include <golfdb.h>
#include <phantom.h>
#include <chrono>
#include <thread>
#include "data_q4.h"

using namespace cuTFHEpp;
using namespace GolfDB;
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
                          std::vector<DataRecord> &data,
                          QueryRequest &query_data,
                          TFHESecretKey &sk,
                          TFHEEvalKey &ek,
                          size_t rows,
                          double &filter_time)
{
  cout << "copy eval key to GPU" << endl;
  Pointer<Context> context(ek);
  Context &ctx = context.get();
  cout << "eval key is copied to GPU" << endl;

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
      groupby_num, std::vector<uint32_t>(rows, 0));
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
      pred_group_res[j][i] = !!(data[i].orderpriority().value ==
                                query_data.orderpriority()[index[0]].value);
    }
  }

  // pred_res
  for (size_t i = 0; i < groupby_num; i++) {
    for (size_t j = 0; j < rows; j++) {
      pred_res[i][j] = pred_group_res[i][j] & pred_pred_res[j];
    }
  }

  // Encrypt Predicates
  std::vector<TLWELvl2> pred_cipher_orderdate1(rows), pred_cipher_orderdate2(rows);
  // pred_cipher_group
  std::vector<std::vector<TLWELvl1>> pred_cipher_orderpriority;
  // encrypt predicate part
  auto pred_cipher_orderdate1_temp = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.orderdate1().value, Lvl2::α,
      pow(2., data[0].orderdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  for (size_t i = 0; i < rows; i++)
    pred_cipher_orderdate1[i] = pred_cipher_orderdate1_temp;

  auto pred_cipher_orderdate2_temp = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.orderdate2().value, Lvl2::α,
      pow(2., data[0].orderdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  for (size_t i = 0; i < rows; i++)
    pred_cipher_orderdate2[i] = pred_cipher_orderdate2_temp;

  // encrypt group by part
  double orderpriority_scale =
      pow(2., data[0].orderpriority().scale_bits<Lvl1>());
  auto orderpriority_group = query_data.orderpriority();
  pred_cipher_orderpriority.resize(orderpriority_group.size());
  for (size_t i = 0; i < orderpriority_group.size(); i++) {
    auto pred_cipher_orderpriority_temp = TFHEpp::tlweSymInt32Encrypt<Lvl1>(
        orderpriority_group[i].value, Lvl1::α, orderpriority_scale,
        sk.key.get<Lvl1>());
    for (size_t j = 0; j < rows; j++)
      pred_cipher_orderpriority[i].push_back(pred_cipher_orderpriority_temp);
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
      groupby_num, std::vector<TLWELvl1>(rows));
  auto orderpriority_bits = data[0].orderpriority().bits;

  Pointer<BootstrappingData<Lvl02>> pt_bs_data(rows);
  auto &pt_bs_data_lvl1 = pt_bs_data.template safe_cast<BootstrappingData<Lvl01>>();

  std::vector<Pointer<cuTLWE<Lvl2>>> tlwe_data;
  tlwe_data.reserve(4);
  for (size_t i = 0; i < 4; ++i) tlwe_data.emplace_back(rows);

  Pointer<cuTLWE<Lvl2>> *pt_tlwe_data = tlwe_data.data();
  Pointer<cuTLWE<Lvl1>> *pt_tlwe_data_lvl1 = &pt_tlwe_data->template safe_cast<cuTLWE<Lvl1>>();

  filter_time = 0;

  HomComp<Lvl02, GE, LOGIC>(ctx, pt_bs_data, pt_tlwe_data,
      pred_orderdate1_cres.data(), orderdate_ciphers.data(), pred_cipher_orderdate1.data(),
      orderdate_bits, rows, filter_time);
  HomComp<Lvl02, LT, LOGIC>(ctx, pt_bs_data, pt_tlwe_data,
      pred_orderdate2_cres.data(), orderdate_ciphers.data(), pred_cipher_orderdate2.data(),
      orderdate_bits, rows, filter_time);
  HomComp<Lvl02, LT, LOGIC>(ctx, pt_bs_data, pt_tlwe_data,
      pred_exsits_cres.data(), commitdate_ciphers.data(), receiptdate_ciphers.data(),
      exsits_bits, rows, filter_time);

  HomAND<LOGIC>(ctx, pt_bs_data_lvl1, pt_tlwe_data_lvl1,
      pred_pred_cres.data(), pred_orderdate1_cres.data(), pred_orderdate2_cres.data(),
      rows, filter_time);
  HomAND<LOGIC>(ctx, pt_bs_data_lvl1, pt_tlwe_data_lvl1,
      pred_pred_cres.data(), pred_pred_cres.data(), pred_exsits_cres.data(),
      rows, filter_time);

  for (size_t j = 0; j < groupby_num; j++) {
    auto index = query_data.group_index(j);

    HomComp<Lvl01, EQ, LOGIC>(ctx, pt_bs_data_lvl1, pt_tlwe_data_lvl1,
        pred_group_cres[j].data(), pred_cipher_orderpriority[index[0]].data(), orderpriority_ciphers.data(),
        orderpriority_bits, rows, filter_time);

    HomAND<ARITHMETIC>(ctx, pt_bs_data_lvl1, pt_tlwe_data_lvl1,
        pred_cres[j].data(), pred_group_cres[j].data(), pred_pred_cres.data(),
        rows, filter_time);
  }

  // check the results
  std::vector<std::vector<uint32_t>> pred_cres_de(groupby_num,
                                                  std::vector<uint32_t>(rows));
  std::vector<uint32_t> pred_orderdate1_cres_de(rows),
      pred_orderdate2_cres_de(rows);
  std::vector<uint32_t> pred_exsits_cres_de(rows);
  std::vector<uint32_t> pred_pred_cres_de(rows);
  std::vector<std::vector<uint32_t>> pred_group_cres_de(
      groupby_num, std::vector<uint32_t>(rows));
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
      pred_group_cres_de[j][i] =
          TFHEpp::tlweSymDecrypt<Lvl1>(pred_group_cres[j][i], sk.key.lvl1);
    }
  }

  size_t error_time = 0;

  uint32_t rlwe_scale_bits = 29;
  for (size_t j = 0; j < groupby_num; j++)
    ari_rescale<Lvl10, Lvl01>(ctx, pt_bs_data_lvl1, pt_tlwe_data_lvl1,
        pred_cres[j].data(), pred_cres[j].data(), rlwe_scale_bits, rows);

  for (size_t i = 0; i < rows; i++)
    for (size_t j = 0; j < groupby_num; j++) {
      pred_cres_de[j][i] = TFHEpp::tlweSymInt32Decrypt<Lvl1>(
          pred_cres[j][i], pow(2., 29), sk.key.get<Lvl1>());
    }
  for (size_t i = 0; i < rows; i++)
    for (size_t j = 0; j < groupby_num; j++)
      error_time += (pred_cres_de[j][i] == pred_res[j][i]) ? 0 : 1;

  std::cout << "Filter Time : " << filter_time << "ms" << std::endl;
  std::cout << "Predicate Error: " << error_time << std::endl;
}

void aggregation(std::vector<PhantomCiphertext> &result,
                 std::vector<std::vector<uint32_t>> &pred_res,
                 std::vector<DataRecord> &data, size_t rows, PhantomRLWE &rlwe,
                 double &aggregation_time) {
  std::cout << "Aggregation :" << std::endl;
  size_t groupby_num = result.size();
  uint64_t slots_count = rows;

  // Table for data, ciphertext, and aggregation results
  struct DataPack {
    std::vector<double> &data;
    PhantomCiphertext &cipher;
    std::vector<PhantomCiphertext> &sum;
  };


  // Filter result * data
  // original data
  std::vector<double> count_data(rows);
  // packed ciphertext
  PhantomCiphertext count_cipher;
  // sum result ciphertext
  std::vector<PhantomCiphertext> order_count(groupby_num);
  std::vector<DataPack> table = {{count_data, count_cipher, order_count}};

  for (size_t i = 0; i < rows; i++) {
    count_data[i] = 1.0;
  }

  // convert data to ciphertext
  PhantomPlaintext t_plain;
  double qd =
      rlwe.parms.coeff_modulus()[result[0].coeff_modulus_size_ - 1].value();
  for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
    pack_encode(*rlwe.context, _data_plaintext, qd, t_plain, *rlwe.ckks_encoder);
    rlwe.secret_key->encrypt_symmetric(*rlwe.context, t_plain, _data_cipher, false);
  }


  std::cout << "Aggregating quantity, prices and discount .." << std::endl;
  // filtering the data
  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();
  for (size_t i = 0; i < groupby_num; ++i) {
    for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
      multiply_and_relinearize(*rlwe.context, result[i], _data_cipher, _sum_cipher[i],
                                     *rlwe.relin_keys);
      rescale_to_next_inplace(*rlwe.context, _sum_cipher[i]);
    }
  }
  cudaDeviceSynchronize();
  end = std::chrono::system_clock::now();
  aggregation_time =
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
          .count();

  // sum to aggregation
  int logrow = log2(rows);
  PhantomCiphertext temp;
  start = std::chrono::system_clock::now();
  for (size_t i = 0; i < groupby_num; ++i) {
    for (size_t j = 0; j < logrow; j++) {
      size_t step = 1 << (logrow - j - 1);
      for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
        temp = _sum_cipher[i];
        rotate_vector_inplace(*rlwe.context, temp, step, *rlwe.galois_keys);
        add_inplace(*rlwe.context, _sum_cipher[i], temp);
      }
    }
  }
  end = std::chrono::system_clock::now();
  aggregation_time +=
      std::chrono::duration_cast<std::chrono::nanoseconds>(end - start)
          .count();
  aggregation_time /= 1000000;
  std::cout << "Aggregation Time: " << aggregation_time << " ms" << std::endl;
  // Decrypt and check the result
  std::vector<double> agg_result(slots_count);
  for (size_t i = 0; i < groupby_num; ++i) {
    for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
      rlwe.secret_key->decrypt(*rlwe.context, _sum_cipher[i], t_plain);
      pack_decode(*rlwe.context, agg_result, t_plain, *rlwe.ckks_encoder);
      double plain_result = 0;
      for (size_t j = 0; j < rows; j++) {
        plain_result += _data_plaintext[j] * pred_res[i][j];
      }
      cout << "Plain_result/Encrypted query result: " << plain_result << "/"
           << agg_result[0] << endl;
    }
  }
}

void query_evaluation(TFHESecretKey &sk, TFHEEvalKey &ek, size_t rows)
{
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
  std::vector<PhantomCiphertext> results;

  predicate_evaluation(pred_cres, pred_res, data, query_data, sk, ek, rows, filter_time);
  PhantomRLWE rlwe(rows);
  rlwe.genLWE2RLWEGaloisKeys();
  conversion(results, pred_cres, pred_res, rlwe, sk, conversion_time);
  rlwe.genGaloisKeys();
  aggregation(results, pred_res, data, rows, rlwe, aggregation_time);
  cout << "End-to-End Time: "
       << (filter_time + conversion_time + aggregation_time) / 1000 << " s"
       << endl;
}

int main(int argc, char** argv)
{
  cudaSetDevice(DEVICE_ID);
  TFHESecretKey sk;
  TFHEEvalKey ek;

  load_keys<BootstrappingKeyFFTLvl01, BootstrappingKeyFFTLvl02,
    KeySwitchingKeyLvl10, KeySwitchingKeyLvl20, KeySwitchingKeyLvl21>(sk, ek);

  query_evaluation(sk, ek, 1<<8);
  phantom::util::global_pool()->Release();
  query_evaluation(sk, ek, 1<<10);
  phantom::util::global_pool()->Release();
  query_evaluation(sk, ek, 1<<12);
  phantom::util::global_pool()->Release();
  query_evaluation(sk, ek, 1<<14);
  phantom::util::global_pool()->Release();
}
