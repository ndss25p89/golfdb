#ifndef BASIC_QUERY1_H
#define BASIC_QUERY1_H

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
    values = {ValueD(0, 6),  ValueD(0, 10), ValueD(0, 4),
              ValueD(0, 4),  ValueC(0, 6),  ValueC(0, 6),
              ValueL(0, 26), ValueL(0, 26), ValueL(0, 26)};
  }
  ~DataRecord() {}

  void init(int returnflag_size, int linestatus_size) {
    randomize(returnflag_size, linestatus_size);
  }

 private:
  void randomize(int m, int n) {
    std::random_device seed_gen;
    std::mt19937 engine(seed_gen());
    std::uniform_real_distribution<double> quantity_message(1, 50);
    std::uniform_real_distribution<double> extendedprice_message(1, 100);
    std::uniform_real_distribution<double> discount_message(0, 0.1);
    std::uniform_real_distribution<double> tax_message(0, 0.1);
    std::uniform_int_distribution<char> returnflag_message(0, m - 1);
    std::uniform_int_distribution<char> linestatus_message(0, n - 1);
    quantity().set_value(quantity_message(engine));
    extendedprice().set_value(extendedprice_message(engine));
    discount().set_value(discount_message(engine));
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
  // QueryData<Lvl1::T> shipdate;
  // std::vector<QueryData<char>> returnflag;
  // std::vector<QueryData<char>> linestatus;
  std::array<VariantType1, 1> predicates;
  std::array<VariantType2, 2> groupby;
  QDataL& shipdate() { return std::get<QDataL>(predicates[0]); }
  QDataC& returnflag() { return std::get<QDataC>(groupby[0]); }
  QDataC& linestatus() { return std::get<QDataC>(groupby[1]); }

 public:
  QueryRequest() {
    predicates = {QDataL()};
    groupby = {QDataC(), QDataC()};
  }
  ~QueryRequest() {}

  void init(int returnflag_size, int linestatus_size) {
    randomize();
    generateGroupBy(returnflag_size, linestatus_size);
  }

 public:
  int pred_num() { return predicates.size(); }
  int groupby_num() { return returnflag().size() * linestatus().size(); }
  std::vector<int> group_index(int index) {
    int i = index / returnflag().size();  // line status
    int j = index % returnflag().size();  // return flag
    return {i, j};
  }

 private:
  void randomize() { shipdate().value = generate_date(20200101, 20221231); }

  void generateGroupBy(int m, int n) {
    returnflag().resize(m);
    linestatus().resize(n);
    for (size_t i = 0; i < m; i++) returnflag()[i].value = i;
    for (size_t i = 0; i < n; i++) linestatus()[i].value = i;
  }
};

#endif  // BASIC_QUERY1_H
