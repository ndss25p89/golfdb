#include "conversion.h"
#include "basic_query6.h"
#include "cache_filter.hpp"
#include "correction.h"
#include "serialize.h"
#include <thread>

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

class DatabaseCData {
  public:
   std::vector<TLWELvl2> shipdate_ciphers, discount_ciphers, quantity_ciphers;
};

class QueryCData {
  public:
    TLWELvl2 pred_cipher_shipdate1, pred_cipher_shipdate2;
    TLWELvl2 pred_cipher_discount1, pred_cipher_discount2;
    TLWELvl2 pred_cipher_quantity;
};

template <typename Lvl = Lvl1, typename T = Lvl::T>
void generate_database(std::vector<std::vector<TLWELvl1>> &pred_cres,
                       std::vector<std::vector<uint32_t>> &pred_res,
                       size_t rows, std::vector<DataRecord> &data,
                       QueryRequest &query_data, TFHESecretKey &sk,
                       TFHEEvalKey &ek, CacheManager<Lvl> &cm,
                       std::vector<std::vector<CacheFilter>> &filters,
                       std::vector<std::string> &filters_name,
                       std::vector<CacheMetadata<T>> &metas,
                       DatabaseCData &db_cdata, QueryCData &query_cdata) {
  using P = Lvl2;
  // Encrypt database
  std::cout << "Encrypting Database..." << std::endl;
  std::vector<TLWELvl2> &shipdate_ciphers = db_cdata.shipdate_ciphers;
  shipdate_ciphers.resize(rows);
  std::vector<TLWELvl2> &discount_ciphers = db_cdata.discount_ciphers;
  discount_ciphers.resize(rows);
  std::vector<TLWELvl2> &quantity_ciphers = db_cdata.quantity_ciphers;
  quantity_ciphers.resize(rows);
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
  auto shipdate_low = query_data.shipdate1().value;
  auto shipdate_up = query_data.shipdate2().value;
  auto discount_low = query_data.discount1().value;
  auto discount_up = query_data.discount2().value;
  auto quantity = query_data.quantity().value;
  std::vector<Lvl1::T> data_shipdate;
  std::vector<Lvl1::T> data_discount, data_quantity;
  // ==== generate cache filters
  std::transform(data.begin(), data.end(), std::back_inserter(data_shipdate),
                 [](DataRecord &item) { return item.shipdate().value; });
  std::transform(data.begin(), data.end(), std::back_inserter(data_discount),
                 [](DataRecord &item) { return item.discount().value; });
  std::transform(data.begin(), data.end(), std::back_inserter(data_quantity),
                 [](DataRecord &item) { return item.quantity().value; });
  cm.generate(filters_name[0], data_shipdate, metas[0]);
  cm.generate(filters_name[1], data_shipdate, metas[1]);
  cm.generate(filters_name[2], data_discount, metas[2]);
  cm.generate(filters_name[3], data_discount, metas[3]);
  cm.generate(filters_name[4], data_quantity, metas[4]);
  // ==== end of cache filter generation
  for (size_t i = 0; i < rows; i++) {
    pred_shipdate1_res[i] = !!(data_shipdate[i] >= shipdate_low);
    pred_shipdate2_res[i] = !!(data_shipdate[i] < shipdate_up);
    pred_discount1_res[i] = !!(data_discount[i] >= discount_low);
    pred_discount2_res[i] = !!(data_discount[i] <= discount_up);
    pred_quantity_res[i] = !!((data_quantity[i] < quantity));
    // pred_res
    pred_res[0][i] = !!(pred_shipdate1_res[i] & pred_shipdate2_res[i] &
                        pred_discount1_res[i] & pred_discount2_res[i] &
                        pred_quantity_res[i]);
  }

  // Encrypt Predicates
  TLWELvl2 &pred_cipher_shipdate1 = query_cdata.pred_cipher_shipdate1;
  TLWELvl2 &pred_cipher_shipdate2 = query_cdata.pred_cipher_shipdate2;
  TLWELvl2 &pred_cipher_discount1 = query_cdata.pred_cipher_discount1;
  TLWELvl2 &pred_cipher_discount2 = query_cdata.pred_cipher_discount2;
  TLWELvl2 &pred_cipher_quantity = query_cdata.pred_cipher_quantity;
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
}

template <typename Lvl = Lvl1, typename T = Lvl::T>
void predicate_evaluation(std::vector<std::vector<TLWELvl1>> &pred_cres,
                          size_t rows, std::vector<DataRecord> &data,
                          QueryRequest &query_data, TFHESecretKey &sk,
                          TFHEEvalKey &ek, CacheManager<Lvl> &cm,
                          std::vector<std::vector<CacheFilter>> &filters,
                          std::vector<std::string> &filters_name,
                          std::vector<CacheMetadata<T>> &metas,
                          DatabaseCData &db_cdata, QueryCData &query_cdata) {
  std::cout << "Predicate evaluation: " << std::endl;
  using P = Lvl2;

  std::vector<TLWELvl2> &shipdate_ciphers = db_cdata.shipdate_ciphers;
  std::vector<TLWELvl2> &discount_ciphers = db_cdata.discount_ciphers;
  std::vector<TLWELvl2> &quantity_ciphers = db_cdata.quantity_ciphers;

  TLWELvl2 &pred_cipher_shipdate1 = query_cdata.pred_cipher_shipdate1;
  TLWELvl2 &pred_cipher_shipdate2 = query_cdata.pred_cipher_shipdate2;
  TLWELvl2 &pred_cipher_discount1 = query_cdata.pred_cipher_discount1;
  TLWELvl2 &pred_cipher_discount2 = query_cdata.pred_cipher_discount2;
  TLWELvl2 &pred_cipher_quantity = query_cdata.pred_cipher_quantity;

  // Predicate Evaluation
  std::cout << "Start Predicate Evaluation..." << std::endl;
  std::vector<TLWELvl1> pred_shipdate1_cres(rows), pred_shipdate2_cres(rows);
  std::vector<TLWELvl1> pred_discount1_cres(rows), pred_discount2_cres(rows);
  std::vector<TLWELvl1> pred_quantity_cres(rows);
  auto shipdate_bits = data[0].shipdate().bits;
  auto discount_bits = data[0].discount().bits;
  auto quantity_bits = data[0].quantity().bits;

  // ==== find cache filters
  for (int i = 0; i < filters_name.size(); i++) {
    cm.find(filters_name[i], filters[i], metas[i]);
  }
  // ==== end of finding cache filters

  for (size_t i = 0; i < rows; i++) {
    // shipdate1
    {
      auto &shipdate1_filters = filters[0];
      auto &shipdate1_meta = metas[0];
      greater_than_equal<Lvl2>(shipdate_ciphers[i], pred_cipher_shipdate1,
                               pred_shipdate1_cres[i], shipdate_bits,
                               shipdate1_meta.get_density(), ek, LOGIC);
      tfhe_correction(shipdate1_filters, pred_shipdate1_cres[i], ek, i);
    }
    // shipdate2
    {
      auto &shipdate2_filters = filters[1];
      auto &shipdate2_meta = metas[1];
      less_than<Lvl2>(shipdate_ciphers[i], pred_cipher_shipdate2,
                      pred_shipdate2_cres[i], shipdate_bits,
                      shipdate2_meta.get_density(), ek, LOGIC);
      tfhe_correction(shipdate2_filters, pred_shipdate2_cres[i], ek, i);
    }
    // discount1
    {
      auto &discount1_filters = filters[2];
      auto &discount1_meta = metas[2];
      greater_than_equal<Lvl2>(discount_ciphers[i], pred_cipher_discount1,
                               pred_discount1_cres[i], discount_bits,
                               discount1_meta.get_density(), ek, LOGIC);
      tfhe_correction(discount1_filters, pred_discount1_cres[i], ek, i);
    }
    // discount2
    {
      auto &discount2_filters = filters[3];
      auto &discount2_meta = metas[3];
      less_than_equal<Lvl2>(discount_ciphers[i], pred_cipher_discount2,
                            pred_discount2_cres[i], discount_bits,
                            discount2_meta.get_density(), ek, LOGIC);
      tfhe_correction(discount2_filters, pred_discount2_cres[i], ek, i);
    }
    // quantity
    {
      auto &quantity_filters = filters[4];
      auto &quantity_meta = metas[4];
      less_than<Lvl2>(quantity_ciphers[i], pred_cipher_quantity,
                      pred_quantity_cres[i], quantity_bits,
                      quantity_meta.get_density(), ek, LOGIC);
      tfhe_correction(quantity_filters, pred_quantity_cres[i], ek, i);
    }
    HomAND(pred_cres[0][i], pred_shipdate1_cres[i], pred_shipdate2_cres[i], ek,
           LOGIC);
    HomAND(pred_cres[0][i], pred_cres[0][i], pred_discount1_cres[i], ek, LOGIC);
    HomAND(pred_cres[0][i], pred_cres[0][i], pred_discount2_cres[i], ek, LOGIC);
    HomAND(pred_cres[0][i], pred_cres[0][i], pred_quantity_cres[i], ek,
           ARITHMETIC);
  }
}

template <typename T = Lvl1>
void aggregation(std::vector<seal::Ciphertext> &result,
                 std::vector<DataRecord> &data, size_t rows, RLWE<T> &rlwe) {
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
  for (size_t i = 0; i < groupby_num; ++i) {
    for (auto [_data_plaintext, _data_cipher, _sum_cipher] : table) {
      seal::multiply_and_relinearize(result[i], _data_cipher, _sum_cipher[i],
                                     *rlwe.p_evaluator, rlwe.relin_keys);
      (*rlwe.p_evaluator).rescale_to_next_inplace(_sum_cipher[i]);
    }
  }

  // sum to aggregation
  int logrow = log2(rows);
  seal::Ciphertext temp;
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
}

template <typename Lvl = Lvl1, typename T = Lvl::T>
void query_evaluation(size_t rows, TFHESecretKey &sk, TFHEEvalKey &ek,
                      RLWE<Lvl> &rlwe, CacheManager<Lvl> &cm,
                      size_t thread_num) {
  cout << "===== Query Evaluation: " << rows << " rows =====" << endl;
  // Generate database
  vector<DataRecord> data(rows);
  QueryRequest query_data;
  for (size_t i = 0; i < rows; i++) {
    data[i].init();
  }
  query_data.init();

  std::vector<std::string> filters_name = {"shipdate", "shipdate", "discount1",
                                           "discount2", "quantity"};
  std::vector<std::vector<CacheFilter>> filters(filters_name.size());
  std::vector<CacheMetadata<T>> metas = {
      CacheMetadata<T>(CompLogic::GE, (T)query_data.shipdate1().value),
      CacheMetadata<T>(CompLogic::LT, (T)query_data.shipdate2().value),
      CacheMetadata<T>(CompLogic::GE, (T)query_data.discount1().value),
      CacheMetadata<T>(CompLogic::LE, (T)query_data.discount2().value),
      CacheMetadata<T>(CompLogic::LT, (T)query_data.quantity().value)};

  std::vector<std::vector<TLWELvl1>> pred_cres;
  std::vector<std::vector<uint32_t>> pred_res;
  DatabaseCData db_cdata;
  QueryCData query_cdata;
  generate_database(pred_cres, pred_res, rows, data, query_data, sk, ek, cm,
                    filters, filters_name, metas, db_cdata, query_cdata);

  std::vector<std::thread> threads;
  auto start = std::chrono::steady_clock::now();
  for (int i = 0; i < thread_num; i++) {
    threads.emplace_back([&]() {
      std::vector<std::vector<TLWELvl1>> pred_cres_self;
      std::ranges::copy(pred_cres, std::back_inserter(pred_cres_self));

      predicate_evaluation(pred_cres_self, rows, data, query_data, sk, ek, cm,
                           filters, filters_name, metas, db_cdata, query_cdata);
      std::vector<seal::Ciphertext> results;
      conversion(results, pred_cres_self, rlwe);
      auto gfilters = std::vector<std::vector<CacheFilter>>();
      filter_correction(results, rlwe, filters, gfilters);
      aggregation(results, data, rows, rlwe);
    });
  }

  for (auto &t : threads) {
    t.join();
  }
  auto end = std::chrono::steady_clock::now();
  auto duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
  std::cout << "Overall Query Time [thread " << thread_num
            << "]: " << duration.count() << " ms" << std::endl;
  cm.clear();
}

int main(int argc, char **argv) {
  if (argc < 4) {
    std::cerr << "Usage: " << argv[0] << " [row] [thread] [iteration]" << std::endl;
    return 1;
  }
  size_t row = std::stoi(argv[1]);
  size_t thread_num = std::stoi(argv[2]);
  size_t iteration = std::stoi(argv[3]);
  TFHESecretKey sk;
  TFHEEvalKey ek;
  generate_sk_ek(sk, ek);
  std::vector<size_t> rows;
  for (int i = 0; i < iteration; i++)
    rows.push_back(row);
  RLWE<Lvl1> rlwe(sk, rows);
  CacheManager<Lvl1> cm(&sk, &ek, &rlwe);
  for (auto row : rows)
    query_evaluation<Lvl1>(row, sk, ek, rlwe, cm, thread_num);
}
