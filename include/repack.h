#pragma once

// This code was modified based on: https://github.com/zhouzhangwalker/HE3DB

#include <phantom.h>
#include <cutfhe++.h>
#include "utils.h"
#include "polyeval_bsgs.h"

using namespace cuTFHEpp;

namespace GolfDB
{
  static std::vector<double> sin_coeff {0.07043813426689680968, 0.00000000000000021373, 0.13648426242848080148, -0.00000000000000065511, 0.12251850008297035521,
    0.00000000000000138338, 0.09687911813122730698, -0.00000000000000086808, 0.05705995636145275163, -0.00000000000000031285,
    0.00190187312696625684, 0.00000000000000044354, -0.06571531807303646056, 0.00000000000000006187, -0.13574001749816311246,
    0.00000000000000010202, -0.18904743240584598318, 0.00000000000000071687, -0.19987271926250091414, -0.00000000000000041061,
    -0.14604929968900889903, -0.00000000000000043404, -0.02740391745089436684, 0.00000000000000064004, 0.11591361998332121164,
    -0.00000000000000074717, 0.20462201735538801395, -0.00000000000000080824, 0.16189767223136858343, -0.00000000000000026978,
    -0.01077097508287188157, -0.00000000000000003535, -0.18568750764013738919, 0.00000000000000053534, -0.18278566848347499452,
    -0.00000000000000019242, 0.03006119366883018562, -0.00000000000000096166, 0.21645511738551495573, 0.00000000000000012574,
    0.10356123542751023703, 0.00000000000000037192, -0.17891441905512733834, 0.00000000000000035345, -0.16355634150343503763,
    -0.00000000000000053488, 0.16482549804489621259, -0.00000000000000118865, 0.16413921800264116846, 0.00000000000000026596,
    -0.20888412226960773044, 0.00000000000000142608, -0.08344642688900480443, -0.00000000000000024583, 0.26869912801153833515,
    0.00000000000000000804, -0.13548482981129844616, 0.00000000000000109860, -0.13729914741849616466, 0.00000000000000277430,
    0.31392945514509801308, 0.00000000000000319002, -0.32761217572456985403, 0.00000000000000107757, 0.24389625486353291861,
    0.00000000000000062732, -0.14493001079259371089, 0.00000000000000155720, 0.07233834282998567733, -0.00000000000000110679,
    -0.03123261034259527599, -0.00000000000000262276, 0.01189279261890215621, -0.00000000000000323379, -0.00404956978046461594,
    -0.00000000000000441352, 0.00124605558777123146, -0.00000000000000212377, -0.00034935166504105009, -0.00000000000000081908,
    0.00008984823446769276, -0.00000000000000558015, -0.00002131648317308570, 0.00000000000000019052, 0.00000468762132811721,
    0.00000000000000103557, -0.00000095941952191024, 0.00000000000000107394, 0.00000018342015938494, 0.00000000000000161096,
    -0.00000003285866440681, 0.00000000000000201318, 0.00000000553158897361, 0.00000000000000262726, -0.00000000087731624365,
    0.00000000000000194294, 0.00000000013139619346, 0.00000000000000145072, -0.00000000001866069215, -0.00000000000000088172,
    0.00000000000282372220};

  static std::vector<double> coeff1 = {1.5, -0.5}; // 1.5 x  - 0.5 x ^ 3
  static std::vector<double> coeff3 = {2.1875 , -2.1875 , 1.3125 , -0.3125};
  static std::vector<double> coeff5 = {2.4609375/2, -3.28125/2, 2.953125/2, -1.40625/2, 0.2734375/2};
  // -0.2095 x ^ 15 + 1.692 x ^ 13 + -5.999 x ^ 11 + 12.22 x ^ 9 + -15.71 x ^ 7 + 13.2 x ^ 5 + -7.332 x ^ 3 + 3.142 x
  static std::vector<double> coeff7 = {3.142 / 2, -7.332 / 2, 13.2 / 2, -15.71 / 2, 12.22 / 2, -5.999 / 2, 1.692 / 2, -0.2095 / 2}; 


  typedef struct LTPreKey
  {
    PhantomCiphertext key;
    std::vector<PhantomCiphertext> rotated_keys;
  } LTPreKey;

  void LWEsToRLWEKeyGen(const PhantomContext &context, LTPreKey &eval_key, double scale,
      const PhantomSecretKey &phantom_key, const TFHESecretKey &tfhepp_key,
      size_t tfhe_n, PhantomCKKSEncoder &encoder);

  void LWEsToRLWE(const PhantomContext &context, PhantomCiphertext &result,
      std::vector<TLWELvl1> &lwe_ciphers, LTPreKey &eval_key, double scale,
      double q0, double rescale, PhantomCKKSEncoder &encoder,
      PhantomGaloisKey &galois_keys, PhantomRelinKey &relin_keys);

  void HomRound(const PhantomContext &context, PhantomCiphertext &cipher,
      double scale, PhantomCKKSEncoder &encoder, PhantomRelinKey &relin_keys);
}