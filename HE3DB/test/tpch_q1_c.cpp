#include "conversion.h"
#include "basic_query1.h"
#include "cache_filter.hpp"
#include "correction.h"
#include "serialize.h"

using namespace HEDB;
using namespace std;

/***
 * TPC-H Query 1 modified
  select
      l_returnflag,
      l_linestatus,
      sum(l_quantity) as sum_qty,
      sum(l_extendedprice) as sum_base_price,
      sum(l_extendedprice * (1 - l_discount)) as sum_disc_price,
      sum(l_extendedprice * (1 - l_discount) * (1 + l_tax)) as sum_charge,
      sum(l_discount) as sum_disc,
      count(*) as count_order
  from
      lineitem
  where
      l_shipdate <= date '1998-12-01' - interval '120' day
  group by
      l_linestatus,
      l_returnflag

    consider data encode by [yyyymmdd], 23 bits,
    group by $m$ types of l_returnflag, $n$ types of l_linestatus
*/

template <typename Lvl = Lvl1, typename T = Lvl::T>
void predicate_evaluation(std::vector<std::vector<TLWELvl1>> &pred_cres,
                          std::vector<std::vector<uint32_t>> &pred_res,
                          size_t rows, std::vector<DataRecord> &data,
                          QueryRequest &query_data, TFHESecretKey &sk,
                          TFHEEvalKey &ek, CacheManager<Lvl> &cm,
                          std::vector<std::vector<CacheFilter>> &filters,
                          std::vector<std::string> &filters_name,
                          std::vector<CacheMetadata<T>> &metas,
                          std::vector<std::vector<CacheFilter>> &gfilters,
                          std::vector<std::string> &gfilters_name,
                          std::vector<CacheMetadata<T>> &gmetas,
                          double &filter_time) {
  std::cout << "Predicate evaluation: " << std::endl;
  using P = Lvl2;

  // Encrypt database
  std::cout << "Encrypting Database..." << std::endl;
  std::vector<TLWELvl1> returnflag_ciphers(rows), linestatus_ciphers(rows);
  std::vector<TLWELvl2> ship_ciphers(rows);
  for (size_t i = 0; i < rows; i++) {
    auto row_data = data[i];
    returnflag_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl1>(
        row_data.returnflag().value, Lvl1::α,
        pow(2., row_data.returnflag().scale_bits<Lvl1>()), sk.key.get<Lvl1>());
    linestatus_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl1>(
        row_data.linestatus().value, Lvl1::α,
        pow(2., row_data.linestatus().scale_bits<Lvl1>()), sk.key.get<Lvl1>());
    ship_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
        row_data.shipdate().value, Lvl2::α,
        pow(2., row_data.shipdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  }

  // Encrypt Predicate values
  std::cout << "Encrypting Predicate Values..." << std::endl;

  // check if the predicate is correct
  auto groupby_num = query_data.groupby_num();
  // pred_ship[rows]
  std::vector<uint32_t> pred_ship_res(rows, 0);
  // pred_group[rows][groupby_num]
  std::vector<std::vector<uint32_t>> pred_group_res(
      rows, std::vector<uint32_t>(groupby_num, 0));
  // pred_res[groupby_num][rows]
  pred_res.resize(groupby_num, std::vector<uint32_t>(rows, 1));
  pred_cres.resize(groupby_num, std::vector<TLWELvl1>(rows));

  // pred_part & pred_group
  for (size_t i = 0; i < rows; i++) {
    auto ship_record = query_data.shipdate();
    pred_ship_res[i] = !!(data[i].shipdate().value <= ship_record.value);
    for (size_t j = 0; j < groupby_num; j++) {
      auto index = query_data.group_index(j);
      pred_group_res[i][j] = (data[i].linestatus().value ==
                              query_data.linestatus()[index[0]].value) &&
                             (data[i].returnflag().value ==
                              query_data.returnflag()[index[1]].value);
    }
  }
  // pred_res
  for (size_t i = 0; i < groupby_num; i++) {
    for (size_t j = 0; j < rows; j++) {
      pred_res[i][j] = pred_group_res[j][i] & pred_ship_res[j];
    }
  }
  std::vector<Lvl1::T> data_shipdate;
  // ==== generate cache filters
  std::transform(data.begin(), data.end(), std::back_inserter(data_shipdate),
                 [](DataRecord &item) { return item.shipdate().value; });
  cm.generate(filters_name[0], data_shipdate, metas[0]);

  size_t i = 0;
  std::vector<Lvl1::T> data_linestatus, data_returnflag;
  std::transform(data.begin(), data.end(), std::back_inserter(data_linestatus),
                 [](DataRecord &item) { return item.linestatus().value; });
  std::transform(data.begin(), data.end(), std::back_inserter(data_returnflag),
                 [](DataRecord &item) { return item.returnflag().value; });
  for (size_t j = 0; j < gfilters[0].size(); ++i, ++j)
    cm.generate(gfilters_name[i], data_linestatus, gmetas[i]);
  for (size_t j = 0; j < gfilters[1].size(); ++i, ++j)
    cm.generate(gfilters_name[i], data_returnflag, gmetas[i]);
  // ==== end of cache filter generation

  // Encrypt Predicates
  TLWELvl2 pred_cipher_ship;
  // pred_cipher_group
  std::vector<TLWELvl1> pred_cipher_linestatus;
  std::vector<TLWELvl1> pred_cipher_returnflag;
  // encrypt predicate part
  pred_cipher_ship = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.shipdate().value, Lvl2::α,
      pow(2., data[0].shipdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  // encrypt group by part
  double linestatus_scale = pow(2., data[0].linestatus().scale_bits<Lvl1>());
  auto linestatus_group = query_data.linestatus();
  pred_cipher_linestatus.resize(linestatus_group.size());
  for (size_t i = 0; i < linestatus_group.size(); i++) {
    pred_cipher_linestatus[i] =
        TFHEpp::tlweSymInt32Encrypt<Lvl1>(linestatus_group[i].value, Lvl1::α,
                                          linestatus_scale, sk.key.get<Lvl1>());
  }
  double returnflag_scale = pow(2., data[0].returnflag().scale_bits<Lvl1>());
  auto returnflag_group = query_data.returnflag();
  pred_cipher_returnflag.resize(returnflag_group.size());
  for (size_t i = 0; i < returnflag_group.size(); i++) {
    pred_cipher_returnflag[i] =
        TFHEpp::tlweSymInt32Encrypt<Lvl1>(returnflag_group[i].value, Lvl1::α,
                                          returnflag_scale, sk.key.get<Lvl1>());
  }

  // Predicate Evaluation
  std::cout << "Start Predicate Evaluation..." << std::endl;
  std::vector<TLWELvl1> pred_ship_cres(rows);
  auto ship_bits = data[0].shipdate().bits;
  std::vector<std::vector<TLWELvl1>> pred_group_cres1(
      rows, std::vector<TLWELvl1>(groupby_num));
  std::vector<std::vector<TLWELvl1>> pred_group_cres2(
      rows, std::vector<TLWELvl1>(groupby_num));
  std::vector<std::vector<TLWELvl1>> pred_group_cres(
      rows, std::vector<TLWELvl1>(groupby_num));
  auto linestatus_bits = data[0].linestatus().bits;
  auto returnflag_bits = data[0].returnflag().bits;
  
  // ==== find cache filters
  // predicates
  for (int i = 0; i < filters_name.size(); i++) {
    cm.find(filters_name[i], filters[i], metas[i]);
  }
  // groupby
  size_t col = 0, row = 0;
  for (int i = 0; i < gfilters_name.size(); i++, row++) {
    std::vector<CacheFilter> tmp;
    cm.find(gfilters_name[i], tmp, gmetas[i]);
    assert(tmp.size() < 2);
    if (!tmp.empty())
      gfilters[col][row] = tmp[0];
    else
      gfilters[col][row] = CacheFilter();
    // update col and row
    if (row == gfilters[col].size() - 1) {
      col++;
      row = -1;
    }
  }
  // ==== end of finding cache filters
  
  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();
  for (size_t i = 0; i < rows; i++) {
    // shipdate
    {
      auto shipdate_filters = filters[0];
      auto shipdate_metas = metas[0];
      less_than_equal<Lvl2>(ship_ciphers[i], pred_cipher_ship,
                            pred_ship_cres[i], ship_bits,
                            shipdate_metas.get_density(), ek, LOGIC);
      tfhe_correction(shipdate_filters, pred_ship_cres[i], ek, i);
    }
    // group by
    std::pair<bool, TLWELvl1> arith_pred_cres(false, TLWELvl1());
    std::vector<size_t> indices(gfilters.size(), 0);
    for (size_t j = 0; j < groupby_num; j++) {
      auto index = query_data.group_index(j);
      // group by - linestatus
      bool operated_linestatus;
      {
        auto linestatus_filters = gfilters[0][indices[0]];
        auto linestatus_metas = gmetas[indices[0]];
        operated_linestatus = !!linestatus_metas.get_density();
        equal<Lvl1>(pred_cipher_linestatus[index[0]], linestatus_ciphers[i],
                    pred_group_cres1[i][j], linestatus_bits,
                    linestatus_metas.get_density(), ek, LOGIC);
        tfhe_correction(linestatus_filters, pred_group_cres1[i][j], ek, i,
                        operated_linestatus);
      }
      // group by - returnflag
      bool operated_returnflag;
      {
        auto base = gfilters[0].size();
        auto returnflag_filters = gfilters[1][indices[1]];
        auto returnflag_metas = gmetas[base + indices[1]];
        operated_returnflag = !!returnflag_metas.get_density();
        equal<Lvl1>(pred_cipher_returnflag[index[1]], returnflag_ciphers[i],
                    pred_group_cres2[i][j], returnflag_bits,
                    returnflag_metas.get_density(), ek, LOGIC);
        tfhe_correction(returnflag_filters, pred_group_cres2[i][j], ek, i,
                        operated_returnflag);
      }

      if (operated_linestatus || operated_returnflag) {
        if (operated_linestatus && operated_returnflag) {
          HomAND(pred_group_cres[i][j], pred_group_cres1[i][j],
                 pred_group_cres2[i][j], ek, LOGIC);
        } else {
          pred_group_cres[i][j] = operated_linestatus ? pred_group_cres1[i][j]
                                                      : pred_group_cres2[i][j];
        }
        HomAND(pred_cres[j][i], pred_group_cres[i][j], pred_ship_cres[i], ek,
               ARITHMETIC);
      } else {
        if (!arith_pred_cres.first) {
          HomAND(arith_pred_cres.second, pred_ship_cres[i], pred_ship_cres[i],
                 ek, ARITHMETIC);
          arith_pred_cres.first = true;
        }
        pred_cres[j][i] = arith_pred_cres.second;
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
  end = std::chrono::system_clock::now();

#ifndef NOCHECK
  // check the results
  std::vector<std::vector<uint32_t>> pred_cres_de(groupby_num,
                                                  std::vector<uint32_t>(rows));
  std::vector<uint32_t> pred_ship_cres_de(rows);
  std::vector<std::vector<uint32_t>> pred_group_cres1_de(
      rows, std::vector<uint32_t>(groupby_num));
  std::vector<std::vector<uint32_t>> pred_group_cres2_de(
      rows, std::vector<uint32_t>(groupby_num));
  std::vector<std::vector<uint32_t>> pred_group_cres_de(
      rows, std::vector<uint32_t>(groupby_num));
  for (size_t i = 0; i < rows; i++) {
    pred_ship_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_ship_cres[i], sk.key.lvl1);
    for (size_t j = 0; j < groupby_num; j++) {
      pred_cres_de[j][i] = TFHEpp::tlweSymInt32Decrypt<Lvl1>(
          pred_cres[j][i], pow(2., 31), sk.key.get<Lvl1>());
      pred_group_cres1_de[i][j] =
          TFHEpp::tlweSymDecrypt<Lvl1>(pred_group_cres1[i][j], sk.key.lvl1);
      pred_group_cres2_de[i][j] =
          TFHEpp::tlweSymDecrypt<Lvl1>(pred_group_cres2[i][j], sk.key.lvl1);
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
  std::vector<double> quantity_data(rows), extendedprice_data(rows),
      extendedprice_discount_data(rows), discount_tax_data(rows),
      discount_data(rows);
  // packed ciphertext
  seal::Ciphertext quantity_cipher, extendedprice_cipher,
      extendedprice_discount_cipher, discount_tax_cipher, discount_cipher;
  // sum result ciphertext
  std::vector<seal::Ciphertext> sum_qty(groupby_num),
      sum_base_price(groupby_num), sum_disc_price(groupby_num),
      sum_charge(groupby_num), sum_disc(groupby_num);
  std::vector<DataPack> table = {
      {quantity_data, quantity_cipher, sum_qty},
      {extendedprice_data, extendedprice_cipher, sum_base_price},
      {extendedprice_discount_data, extendedprice_discount_cipher,
       sum_disc_price},
      {discount_tax_data, discount_tax_cipher, sum_charge},
      {discount_data, discount_cipher, sum_disc}};

  for (size_t i = 0; i < rows; i++) {
    quantity_data[i] = data[i].quantity().value;
    extendedprice_data[i] = data[i].extendedprice().value;
    extendedprice_discount_data[i] =
        data[i].extendedprice().value * (1 - data[i].discount().value);
    discount_tax_data[i] = data[i].extendedprice().value *
                           (1 - data[i].discount().value) *
                           (1 + data[i].tax().value);
    discount_data[i] = data[i].discount().value;
  }

  // convert data to ciphertext
  seal::Plaintext t_plain;
  double qd =
      rlwe.parms.coeff_modulus()[result[0].coeff_modulus_size() - 1].value();
  for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
    seal::pack_encode(_data_plaintext, qd, t_plain, *rlwe.p_ckks_encoder);
    (*rlwe.p_encryptor).encrypt_symmetric(t_plain, _data_cipher);
  }

  std::cout << "Aggregating quantity, prices and discount .." << std::endl;
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

template <typename Lvl = Lvl1, typename T = Lvl::T>
void query_evaluation(size_t rows, TFHESecretKey &sk, TFHEEvalKey &ek,
                      RLWE<Lvl> &rlwe, CacheManager<Lvl> &cm) {
  cout << "===== Query Evaluation: " << rows << " rows =====" << endl;
  // Generate database
  vector<DataRecord> data(rows);
  QueryRequest query_data;
  int returnflag_size = 2, linestatus_size = 3;
  for (size_t i = 0; i < rows; i++) {
    data[i].init(returnflag_size, linestatus_size);
  }
  query_data.init(returnflag_size, linestatus_size);

  std::vector<std::string> filters_name = {"shipdate"};
  std::vector<std::vector<CacheFilter>> filters(filters_name.size());
  std::vector<CacheMetadata<T>> metas = {
      CacheMetadata<T>(CompLogic::LE, (T)query_data.shipdate().value)};

  std::vector<std::string> gfilters_name;
  std::vector<std::vector<CacheFilter>> gfilters(2);
  std::vector<CacheMetadata<T>> gmetas;
  gfilters[0] = std::vector<CacheFilter>(linestatus_size);
  for (size_t i = 0; i < linestatus_size; ++i) {
    gfilters_name.push_back("linestatus");
    gmetas.push_back(CacheMetadata<T>(CompLogic::EQ,
                                 (T)query_data.linestatus()[i].value));
  };
  gfilters[1] = std::vector<CacheFilter>(returnflag_size);
  for (size_t i = 0; i < returnflag_size; ++i) {
    gfilters_name.push_back("returnflag");
    gmetas.push_back(CacheMetadata<T>(CompLogic::EQ,
                                 (T)query_data.returnflag()[i].value));
  };


  double filter_time, conversion_time, correction_time, aggregation_time;
  std::vector<std::vector<TLWELvl1>> pred_cres;
  std::vector<std::vector<uint32_t>> pred_res;
  std::vector<seal::Ciphertext> results;
  predicate_evaluation(pred_cres, pred_res, rows, data, query_data, sk, ek, cm,
                       filters, filters_name, metas, gfilters, gfilters_name,
                       gmetas, filter_time);
  conversion(results, pred_cres, pred_res, rlwe, conversion_time);
  filter_correction(results, pred_res, rlwe, filters, gfilters,
                    correction_time);
  aggregation(results, pred_res, data, rows, rlwe, aggregation_time);
  cout << "End-to-End Time: "
       << (filter_time + conversion_time + correction_time + aggregation_time) /
              1000
       << " s" << endl;
  cm.clear();
}

int main() {
  TFHESecretKey sk;
  TFHEEvalKey ek;
  generate_sk_ek(sk, ek);
  std::vector<size_t> rows = {16, 32, 64};
  RLWE<Lvl1> rlwe(sk, rows);
  CacheManager<Lvl1> cm(&sk, &ek, &rlwe);
  for (auto row : rows)
    query_evaluation<Lvl1>(row, sk, ek, rlwe, cm);
}
