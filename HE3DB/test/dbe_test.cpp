#define DBE
#define DBE_DEBUG
#include "cache_filter.hpp"
#include "serialize.h"

using namespace HEDB;
using namespace std;

int main() {
  TFHESecretKey sk;
  TFHEEvalKey ek;
  std::vector<size_t> rows = {16};
  RLWE<Lvl1> rlwe;
  CacheManager<Lvl1> cm(&sk, &ek, &rlwe);
  std::vector<Lvl1::T> data = {1, 2, 3, 4};
  for (size_t i = 1; i < 220; i++) {
    cm.generate("test", data, CompLogic::GT, i);
  }
  for (size_t i = 1; i < 20; i++)
    cm.find("test", data, CompLogic::GT, 220);
  cm.generate("test", data, CompLogic::GT, 10000);
  cm.generate("test", data, CompLogic::GT, 10031);
}