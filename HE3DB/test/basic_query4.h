#ifndef BASIC_QUERY4_H
#define BASIC_QUERY4_H

#include <assert.h>
#include <type_traits>
#include <variant>

#include "HEDB/comparison/comparison.h"
#include "HEDB/conversion/repack.h"
#include "HEDB/utils/utils.h"

template <typename T>
constexpr bool false_v = false;

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
  return day_message(engine) + 100 * month_message(engine) + 10000 * year_message(engine);
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
  // Value<char>    orderstatus;
  // Value<double>  totalprice;
  // Value<Lvl1::T> orderdate;
  // Value<Lvl1::T> orderpriority;
  // Value<Lvl1::T> clerk;
  // Value<Lvl1::T> shippriority;

  // Value<Lvl1::T> commitdate;
  // Value<Lvl1::T> receiptdate;
  std::array<VariantType, 8> values;

  ValueC& orderstatus() { return std::get<ValueC>(values[0]); }
  ValueD& totalprice() { return std::get<ValueD>(values[1]); }
  ValueL& orderdate() { return std::get<ValueL>(values[2]); }
  ValueL& orderpriority() { return std::get<ValueL>(values[3]); }
  ValueL& clerk() { return std::get<ValueL>(values[4]); }
  ValueL& shippriority() { return std::get<ValueL>(values[5]); }

  ValueL& commitdate() { return std::get<ValueL>(values[6]); }
  ValueL& receiptdate() { return std::get<ValueL>(values[7]); }

  DataRecord() {
    values = {ValueC(0, 8),  ValueD(0, 32), ValueL(0, 26),
              ValueL(0, 8), ValueL(0, 20), ValueL(0, 20),
              ValueL(0, 26), ValueL(0, 26)};
  }
  ~DataRecord() {}

  void init(int orderpriority) {
    randomize(orderpriority);
  }

 private:
  void randomize(int m) {
    std::random_device seed_gen;
    std::mt19937 engine(seed_gen());
    uniform_int_distribution<char> orderstatus_message(0, 2);
    uniform_real_distribution<double> totalprice_message(1, 5000);
    uniform_int_distribution<Lvl1::T> orderpriority_message(0, m - 1);
    uniform_int_distribution<Lvl1::T> clerk_message(0, 1000);
    uniform_int_distribution<Lvl1::T> shippriority_message(0, 1000);
    orderstatus().value = orderstatus_message(engine);
    totalprice().value = totalprice_message(engine);
    orderdate().value = generate_date(19920101, 19981231);
    orderpriority().value = orderpriority_message(engine);
    clerk().value = clerk_message(engine);
    shippriority().value = shippriority_message(engine);
    commitdate().value = generate_date(19920101, 19981231);
    receiptdate().value = generate_date(19981231, 19991231);
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
  QueryData() : value(0), record_index(0) {}
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
  using QDataVL = std::vector<QueryData<Lvl1::T>>;
  using VariantType1 = std::variant<QDataL>;
  using VariantType2 = std::variant<QDataVL>;

 public:
  // QueryData<Lvl1::T> orderdate1;
  // QueryData<Lvl1::T> orderdate2;
  // std::vector<QueryData<Lvl1::T>> orderpriority;
  std::array<VariantType1, 2> predicates;
  std::array<VariantType2, 1> groupby;
  QDataL& orderdate1() { return std::get<QDataL>(predicates[0]); }
  QDataL& orderdate2() { return std::get<QDataL>(predicates[1]); }
  QDataVL& orderpriority() { return std::get<QDataVL>(groupby[0]); }

 public:
  QueryRequest() {
    predicates = {QDataL(), QDataL()};
    groupby = {QDataVL()};
  }
  ~QueryRequest() {}

  void init(int orderpriority_size) {
    randomize();
    generateGroupBy(orderpriority_size);
  }

 public:
  int pred_num() { return predicates.size(); }
  int groupby_num() { return orderpriority().size(); }
  std::vector<int> group_index(int index) {
    int i = index % orderpriority().size();
    return {i};
  }

 private:
  void randomize() {
    auto date = generate_date(19920101, 19981231);
    orderdate1().value = date;
    orderdate2().value = data_add(date, 3 * 100); // + 3months
  }

  void generateGroupBy(int m) {
    orderpriority().resize(m);
    for (size_t i = 0; i < m; i++) orderpriority()[i].value = i;
  }
};

#endif  // BASIC_QUERY4_H
