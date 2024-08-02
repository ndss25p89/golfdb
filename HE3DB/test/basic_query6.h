#ifndef BASIC_QUERY6_H
#define BASIC_QUERY6_H

#include <assert.h>

#include <type_traits>
#include <variant>

#include "HEDB/comparison/comparison.h"
#include "HEDB/conversion/repack.h"
#include "HEDB/utils/utils.h"
#include "zipfian_int_distribution.h"

template <typename T>
constexpr bool false_v = false;

constexpr int scale_double = 1000;

using namespace HEDB;
using namespace std;

uint32_t generate_date(uint64_t down, uint64_t up) {
  uint64_t dyear, dmonth, dday, uyear, umonth, uday;
  dyear = down / 10000;
  dmonth = (down / 100) % 100;
  dday = down % 100;
  uyear = up / 10000;
  umonth = (up / 100) % 100;
  uday = up % 100;
  std::random_device seed_gen;
  std::mt19937 engine(seed_gen());
  uniform_int_distribution<Lvl1::T> day_message(dday, uday);
  uniform_int_distribution<Lvl1::T> month_message(dmonth, umonth);
  uniform_int_distribution<Lvl1::T> year_message(dyear, uyear);
  return day_message(engine) + 100 * month_message(engine) +
         10000 * year_message(engine);
}

uint32_t data_add(uint32_t a, uint32_t b) {
  uint64_t ayear, amonth, aday, byear, bmonth, bday;
  ayear = a / 10000;
  amonth = (a / 100) % 100;
  aday = a % 100;
  byear = b / 10000;
  bmonth = (b / 100) % 100;
  bday = b % 100;
  aday += bday;
  if (aday > 31) {
    aday -= 31;
    amonth++;
  }
  amonth += bmonth;
  if (amonth > 12) {
    amonth -= 12;
    ayear++;
  }
  ayear += byear;
  return aday + 100 * amonth + 10000 * ayear;
}

template <typename T>
class Value {
 public:
  T value;
  uint32_t bits;

 public:
  Value() : value(0), bits(0) {}
  Value(T v, uint32_t b) : value(v), bits(b) {}
  ~Value() {}
  void set(T v, uint32_t b) {
    value = v;
    bits = b;
  }
  void set_value(T v) { value = v; }
  void set_bits(uint32_t b) { bits = b; }

 public:
  template <typename Level>
  int scale_bits() {
    return std::numeric_limits<typename Level::T>::digits - bits - 1;
  }
};

class DataRecord {
  using ValueD = Value<double>;
  using ValueC = Value<char>;
  using ValueL = Value<Lvl1::T>;
  using VariantType = std::variant<ValueD, ValueC, ValueL>;

 public:
  // Value<double> quantity;
  // Value<double> extendedprice;
  // Value<double> discount;
  // Value<double> tax;

  // Value<char> returnflag;
  // Value<char> linestatus;

  // Value<Lvl1::T> shipdate;
  // Value<Lvl1::T> commitdate;
  // Value<Lvl1::T> receiptdate;
  std::array<VariantType, 9> values;
  const int double_scale = scale_double;

  ValueD& quantity() { return std::get<ValueD>(values[0]); }
  ValueD& extendedprice() { return std::get<ValueD>(values[1]); }
  ValueD& discount() { return std::get<ValueD>(values[2]); }
  ValueD& tax() { return std::get<ValueD>(values[3]); }
  ValueC& returnflag() { return std::get<ValueC>(values[4]); }
  ValueC& linestatus() { return std::get<ValueC>(values[5]); }
  ValueL& shipdate() { return std::get<ValueL>(values[6]); }
  ValueL& commitdate() { return std::get<ValueL>(values[7]); }
  ValueL& receiptdate() { return std::get<ValueL>(values[8]); }

  DataRecord() {
    values = {ValueD(0, 16), ValueD(0, 10), ValueD(0, 12),
              ValueD(0, 4),  ValueC(0, 6),  ValueC(0, 6),
              ValueL(0, 26), ValueL(0, 26), ValueL(0, 26)};
  }
  ~DataRecord() {}

  void init() {
    randomize();
  }

 private:
  void randomize() {
    std::random_device seed_gen;
    std::mt19937 engine(seed_gen());
    std::uniform_real_distribution<double> quantity_message(1, 50);
    std::uniform_real_distribution<double> extendedprice_message(1, 100);
    std::uniform_real_distribution<double> discount_message(0, 0.1);
    std::uniform_real_distribution<double> tax_message(0, 0.1);
    std::uniform_int_distribution<char> returnflag_message(0, 1);
    std::uniform_int_distribution<char> linestatus_message(0, 1);
    quantity().set_value((Lvl1::T)(quantity_message(engine) * scale_double));
    extendedprice().set_value(extendedprice_message(engine));
    discount().set_value((Lvl1::T)(discount_message(engine) * scale_double));
    tax().set_value(tax_message(engine));
    returnflag().set_value(returnflag_message(engine));
    linestatus().set_value(linestatus_message(engine));
    shipdate().set_value(generate_date(20200101, 20221231));
    commitdate().set_value(generate_date(20200101, 20221231));
    receiptdate().set_value(generate_date(20200101, 20221231));
  }
};

template <typename T>
class QueryData {
 public:
  T value;
  uint32_t record_index;

 private:
  using ComparisonFunction = std::function<bool(const T&, const T&)>;
  ComparisonFunction compare;

 public:
  QueryData() {
    if constexpr (std::is_same_v<decltype(value), int>) {
      value = 0;
    } else if constexpr (std::is_same_v<decltype(value), char>) {
      value = 0;
    } else if constexpr (std::is_same_v<decltype(value), Lvl1::T>) {
      value = 0;
    } else {
      static_assert(false_v<T>, "Undefined type!");
    }
    record_index = 0;
  }
  ~QueryData() {}

  void setComparisonFunction(ComparisonFunction compFunc) {
    compare = compFunc;
  }

  inline uint32_t getRecordIndex() { return record_index; }
  void setIndex(uint32_t index) { record_index = index; }

 public:
  bool compareValues(const T& otherValue) const {
    if (compare) {
      return compare(otherValue, value);
    }
    return false;
  }
};

class QueryRequest {
  using QDataL = QueryData<Lvl1::T>;
  using QDataC = std::vector<QueryData<char>>;
  using VariantType1 = std::variant<QDataL>;
  using VariantType2 = std::variant<QDataC>;

 public:
  // QueryData<Lvl1::T> shipdate1;
  // QueryData<Lvl1::T> shipdate1;
  // QueryData<Lvl1::T> discount1;
  // QueryData<Lvl1::T> discount2;
  // QueryData<Lvl1::T> quantity;
  std::array<VariantType1, 5> predicates;
  std::array<VariantType2, 0> groupby;
  QDataL& shipdate1() { return std::get<QDataL>(predicates[0]); }
  QDataL& shipdate2() { return std::get<QDataL>(predicates[1]); }
  QDataL& discount1() { return std::get<QDataL>(predicates[2]); }
  QDataL& discount2() { return std::get<QDataL>(predicates[3]); }
  QDataL& quantity() { return std::get<QDataL>(predicates[4]); }

  bool zipf = false;
 public:
  QueryRequest() : QueryRequest(false) {}
  QueryRequest(bool _zipf) {
    zipf = _zipf;
    predicates = {QDataL()};
#ifdef RNDSEED
    engine = std::make_shared<std::mt19937>(RNDSEED);
#else
    std::random_device seed_gen;
    engine = std::make_shared<std::mt19937>(seed_gen());
#endif
  }
  ~QueryRequest() {}

  void init() {
    randomize();
    generateGroupBy();
  }

 private:
  std::shared_ptr<std::mt19937> engine;

 public:
  int pred_num() { return predicates.size(); }
  int groupby_num() { return 1; }
  std::vector<int> group_index(int index) { return {0}; }

  // template <typename T>
  // T generate_zipfian_value(int n, double s, T min_value, T max_value) {
  //   static std::discrete_distribution<int> distribution;
  //   static std::tuple<int, double> cached_params = std::make_tuple(0, 0.0);

  //   // Initialize the distribution on the first call or if the parameters have changed
  //   auto [cached_n, cached_s] = cached_params;
  //   if (cached_n != n || cached_s != s) {
  //       std::vector<double> probabilities(n);
  //       double harmonic_sum = 0.0;
  //       for (int i = 0; i < n; i++) {
  //           probabilities[i] = 1.0 / std::pow(i + 1, s);
  //           harmonic_sum += probabilities[i];
  //       }
  //       for (double& p : probabilities) {
  //           p /= harmonic_sum;
  //       }
  //       distribution.param(std::discrete_distribution<int>::param_type(probabilities.begin(), probabilities.end()));
  //       cached_params = std::make_tuple(n, s);
  //   }

  //   int index = distribution(*engine);
  //   return min_value + static_cast<T>(index) * (max_value - min_value) / (n - 1);
  // }

 private:
  void randomize() {
    Lvl1::T _shipdate, _discount, _quantity;
    if (zipf) {
      zipfian_int_distribution<int> shipdate_message(20200101, 20221231, 0.8);
      zipfian_int_distribution<int> quantity_message(24 * scale_double,
                                                     50 * scale_double, 0.8);
      zipfian_int_distribution<int> discount_message(0 * scale_double,
                                                     0.1 * scale_double, 0.8);
      _shipdate = shipdate_message(*engine);
      _discount = quantity_message(*engine);
      _quantity = discount_message(*engine);
    } else {
      std::uniform_real_distribution<double> quantity_message(24, 50);
      std::uniform_real_distribution<double> discount_message(0, 0.1);
      _shipdate = generate_date(20200101, 20221231);
      _discount = (Lvl1::T)(discount_message(*engine) * scale_double);
      _quantity = (Lvl1::T)(quantity_message(*engine) * scale_double);
    }
    shipdate1().value = _shipdate;
    shipdate2().value = data_add(_shipdate, 1 * 10000);  // + 1year
    discount1().value = _discount;
    discount2().value = _discount + 20;
    quantity().value = _quantity;
  }

  void generateGroupBy() {}
};

#endif  // BASIC_QUERY6_H
