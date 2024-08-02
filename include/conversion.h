#pragma once

#include <chrono>
#include "rlwe.cuh"
#include <phantom.h>

namespace GolfDB
{
  void conversion(std::vector<PhantomCiphertext> &results,
      std::vector<std::vector<TLWELvl1>> &pred_cres,
      std::vector<std::vector<uint32_t>> &pred_res, PhantomRLWE &rlwe,
      TFHESecretKey &sk,
      double &conversion_time);
} // namespace GolfDB
