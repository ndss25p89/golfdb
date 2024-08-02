#include <golfdb.h>
#include <phantom.h>
#include <chrono>
#include <thread>
#include "data_q6.h"

using namespace cuTFHEpp;
using namespace GolfDB;
using namespace std;

/***
 * TPC-H Query 6
 * select
 sum(l_extendedprice * l_discount) as revenue
 from
 lineitem
 where
 l_shipdate >= date ':1'
 and l_shipdate < date ':1' + interval '1' year;

 consider data \in [20200101~20221231]
 */

void predicate_evaluation(std::vector<std::vector<TLWELvl1>> &pred_cres,
                          std::vector<std::vector<uint32_t>> &pred_res,
                          std::vector<DataRecord> &data,
                          QueryRequest &query_data, TFHESecretKey &sk,
                          TFHEEvalKey &ek, CacheManager<Lvl1> &cm,
                          std::vector<std::vector<CacheFilter>> &filters,
                          std::vector<std::string> &filters_name,
                          std::vector<CacheMetadata<Lvl1::T>> &metas,
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
  std::vector<TLWELvl2> shipdate_ciphers(rows);
  for (size_t i = 0; i < rows; i++) {
    auto row_data = data[i];
    shipdate_ciphers[i] = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
        row_data.shipdate().value, Lvl2::α,
        pow(2., row_data.shipdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  }

  // Encrypt Predicate values
  std::cout << "Encrypting Predicate Values..." << std::endl;

  // check if the predicate is correct
  auto groupby_num = query_data.groupby_num();
  // pred_shipdate[rows]
  std::vector<uint32_t> pred_shipdate1_res(rows, 0);
  std::vector<uint32_t> pred_shipdate2_res(rows, 0);
  // pred_res[groupby_num][rows]
  pred_res.resize(groupby_num, std::vector<uint32_t>(rows, 1));
  pred_cres.resize(groupby_num, std::vector<TLWELvl1>(rows));

  // pred_part
  auto shipdate_low = query_data.shipdate1().value;
  auto shipdate_up = query_data.shipdate2().value;
  std::vector<Lvl1::T> data_shipdate;
  // ==== generate cache filters
  std::transform(data.begin(), data.end(), std::back_inserter(data_shipdate),
                 [](DataRecord &item) { return item.shipdate().value; });
  cm.generate(filters_name[0], data_shipdate, metas[0]);
  cm.generate(filters_name[1], data_shipdate, metas[1]);
  // ==== end of cache filter generation
  for (size_t i = 0; i < rows; i++) {
    pred_shipdate1_res[i] = !!(data_shipdate[i] >= shipdate_low);
    pred_shipdate2_res[i] = !!(data_shipdate[i] < shipdate_up);
    // pred_res
    pred_res[0][i] = !!(pred_shipdate1_res[i] & pred_shipdate2_res[i]);
  }

  // Encrypt Predicates
  std::vector<TLWELvl2> pred_cipher_shipdate1(rows), pred_cipher_shipdate2(rows);
  // encrypt predicate part
  auto pred_cipher_shipdate1_temp = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.shipdate1().value, Lvl2::α,
      pow(2., data[0].shipdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());
  auto pred_cipher_shipdate2_temp = TFHEpp::tlweSymInt32Encrypt<Lvl2>(
      query_data.shipdate2().value, Lvl2::α,
      pow(2., data[0].shipdate().scale_bits<Lvl2>()), sk.key.get<Lvl2>());

  for (size_t i = 0; i < rows; i++) {
    pred_cipher_shipdate1[i] = pred_cipher_shipdate1_temp;
    pred_cipher_shipdate2[i] = pred_cipher_shipdate2_temp;
  }

  // Predicate Evaluation
  std::cout << "Start Predicate Evaluation..." << std::endl;
  std::vector<TLWELvl1> pred_shipdate1_cres(rows), pred_shipdate2_cres(rows);
  auto shipdate_bits = data[0].shipdate().bits;

  // ==== find cache filters
  for (int i = 0; i < filters_name.size(); i++) {
    cm.find(filters_name[i], filters[i], metas[i]);
  }
  // ==== end of finding cache filters

  Pointer<BootstrappingData<Lvl02>> pt_bs_data(rows);
  auto &pt_bs_data_lvl1 = pt_bs_data.template safe_cast<BootstrappingData<Lvl01>>();

  std::vector<Pointer<cuTLWE<Lvl2>>> tlwe_data;
  tlwe_data.reserve(4);
  for (size_t i = 0; i < 4; ++i) tlwe_data.emplace_back(rows);

  Pointer<cuTLWE<Lvl2>> *pt_tlwe_data = tlwe_data.data();
  Pointer<cuTLWE<Lvl1>> *pt_tlwe_data_lvl1 = &pt_tlwe_data->template safe_cast<cuTLWE<Lvl1>>();

  filter_time = 0;
  double tfhe_correction_time = 0;

  HomFastComp<Lvl02, GE, LOGIC>(ctx, pt_bs_data, pt_tlwe_data,
      pred_shipdate1_cres.data(), shipdate_ciphers.data(), pred_cipher_shipdate1.data(),
      shipdate_bits, metas[0].get_density(), rows, filter_time);
  tfhe_correction(ctx, filters[0], pt_bs_data_lvl1, pt_tlwe_data_lvl1,
      pred_shipdate1_cres.data(), rows, tfhe_correction_time);

  HomFastComp<Lvl02, LT, LOGIC>(ctx, pt_bs_data, pt_tlwe_data,
      pred_shipdate2_cres.data(), shipdate_ciphers.data(), pred_cipher_shipdate2.data(),
      shipdate_bits, metas[1].get_density(), rows, filter_time);
  tfhe_correction(ctx, filters[1], pt_bs_data_lvl1, pt_tlwe_data_lvl1,
      pred_shipdate2_cres.data(), rows, tfhe_correction_time);

  HomAND<ARITHMETIC>(ctx, pt_bs_data_lvl1, pt_tlwe_data_lvl1,
      pred_cres[0].data(), pred_shipdate1_cres.data(), pred_shipdate2_cres.data(),
      rows, filter_time);

  // check the results
#ifndef NOCHECK
  std::vector<std::vector<uint32_t>> pred_cres_de(groupby_num,
                                                  std::vector<uint32_t>(rows));
  std::vector<uint32_t> pred_shipdate1_cres_de(rows),
      pred_shipdate2_cres_de(rows);
  for (size_t i = 0; i < rows; i++) {
    pred_shipdate1_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_shipdate1_cres[i], sk.key.lvl1);
    pred_shipdate2_cres_de[i] =
        TFHEpp::tlweSymDecrypt<Lvl1>(pred_shipdate2_cres[i], sk.key.lvl1);
    if (pred_shipdate1_cres_de[i] != pred_shipdate1_res[i]) {
      std::cout << "Predicate shipdate1[" << i << "] Error: " << pred_shipdate1_cres_de[i]
                << " " << pred_shipdate1_res[i] << std::endl;
    }
    if (pred_shipdate2_cres_de[i] != pred_shipdate2_res[i]) {
      std::cout << "Predicate shipdate2[" << i << "] Error: " << pred_shipdate2_cres_de[i]
                << " " << pred_shipdate2_res[i] << std::endl;
    }
    pred_cres_de[0][i] = TFHEpp::tlweSymInt32Decrypt<Lvl1>(
        pred_cres[0][i], pow(2., 31), sk.key.get<Lvl1>());
  }

  size_t error_time = 0;

  uint32_t rlwe_scale_bits = 29;
  ari_rescale<Lvl10, Lvl01>(ctx, pt_bs_data_lvl1, pt_tlwe_data_lvl1,
      pred_cres[0].data(), pred_cres[0].data(), rlwe_scale_bits, rows);

  for (size_t i = 0; i < rows; i++)
    pred_cres_de[0][i] = TFHEpp::tlweSymInt32Decrypt<Lvl1>(
        pred_cres[0][i], pow(2., 29), sk.key.get<Lvl1>());
  for (size_t i = 0; i < rows; i++)
    error_time += (pred_cres_de[0][i] == pred_res[0][i]) ? 0 : 1;
  std::cout << "Predicate Error: " << error_time << std::endl;
#endif
  std::cout << "[PHC] " << filter_time << "ms" << std::endl;
  std::cout << "[TFHE Correction] " << tfhe_correction_time << "ms"
            << std::endl;
  filter_time += tfhe_correction_time;
  std::cout << "[Evaluation] " << filter_time << "ms" << std::endl;
}

void query_evaluation(TFHESecretKey &sk, TFHEEvalKey &ek, size_t rows, uint32_t precision, bool fast_comp, double &time)
{
  using T = Lvl1::T;
  cout << "===== Query Evaluation: " << rows << " rows, precision " << precision << " =====" << endl;
    // Generate database
  vector<DataRecord> data(rows, DataRecord(precision));
  QueryRequest query_data;
  for (size_t i = 0; i < rows; i++) {
    data[i].init();
  }
  query_data.init();

  PhantomRLWE rlwe(rows);
  CacheManager<Lvl1> cm(&sk, &ek, &rlwe, fast_comp);

  std::vector<std::string> filters_name = {"shipdate", "shipdate"};
  std::vector<std::vector<CacheFilter>> filters(filters_name.size());
  std::vector<CacheMetadata<T>> metas = {
      CacheMetadata<T>(CompLogic::GE, (T)query_data.shipdate1().value),
      CacheMetadata<T>(CompLogic::LT, (T)query_data.shipdate2().value)};

  double filter_time, conversion_time, correction_time;
  std::vector<std::vector<TLWELvl1>> pred_cres;
  std::vector<std::vector<uint32_t>> pred_res;
  std::vector<PhantomCiphertext> results;

  predicate_evaluation(pred_cres, pred_res, data, query_data, sk, ek,
      cm, filters, filters_name, metas, rows, filter_time);
  rlwe.genLWE2RLWEGaloisKeys();
  conversion(results, pred_cres, pred_res, rlwe, sk, conversion_time);
  rlwe.genGaloisKeys();
  auto gfilters = std::vector<std::vector<CacheFilter>>();

  filter_correction(results, pred_res, rlwe, filters, gfilters,
                  correction_time);

  cout << "End-to-End Time: "
       << (filter_time + conversion_time + correction_time) / 1000 << " s"
       << endl;
  cm.clear();

  time = (filter_time + conversion_time + correction_time) / 1000;
}

int main(int argc, char** argv)
{
  cudaSetDevice(DEVICE_ID);
  TFHESecretKey sk;
  TFHEEvalKey ek;

  load_keys<BootstrappingKeyFFTLvl01, BootstrappingKeyFFTLvl02,
    KeySwitchingKeyLvl10, KeySwitchingKeyLvl20, KeySwitchingKeyLvl21>(sk, ek);

  bool fast_comp = false;
  std::vector<double> times(32, 0);

  for (size_t i = 1; i <= 32; i++) {
    query_evaluation(sk, ek, 1024, i, fast_comp, times[i-1]);
    phantom::util::global_pool()->Release();
  }

  if (argc > 1) {
    ofstream ofs(argv[1]);
    for (size_t i = 0; i < 32; i++) {
      ofs << times[i] << endl;
    }
    ofs.close();
  } else {
    for (size_t i = 0; i < 32; i++) {
      cout << times[i] << endl;
    }
  }
}
