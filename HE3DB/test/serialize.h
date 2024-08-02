#ifndef _SERIALIZE_H_
#define _SERIALIZE_H_

#include <fstream>
#include <iostream>
#include <tfhe++.hpp>

#define SECRET_KEY_NAME "secret.key"
#define EVAL_KEY_NAME_BKFFTLVL01 "bkfftlvl01.key"
#define EVAL_KEY_NAME_BKFFTLVL02 "bkfftlvl02.key"
#define EVAL_KEY_NAME_IKSKLVL10 "iksklvl10.key"
#define EVAL_KEY_NAME_IKSKLVL20 "iksklvl20.key"
#define EVAL_KEY_NAME_IKSKLVL21 "iksklvl21.key"
#define LOAD_KEY 1
#define STORE_KEY 0
#define IS_LOAD_KEY(a) a
#define IS_STORE_KEY(a) !a

template <class P>
inline std::string get_evalkey_path(const char *path) {
  if constexpr (std::is_same_v<P, TFHEpp::BootstrappingKeyFFT<Lvl01>>)
    return std::string(path) + "/" + EVAL_KEY_NAME_BKFFTLVL01;
  else if constexpr (std::is_same_v<P, TFHEpp::BootstrappingKeyFFT<Lvl02>>)
    return std::string(path) + "/" + EVAL_KEY_NAME_BKFFTLVL02;
  else if constexpr (std::is_same_v<P, TFHEpp::KeySwitchingKey<Lvl10>>)
    return std::string(path) + "/" + EVAL_KEY_NAME_IKSKLVL10;
  else if constexpr (std::is_same_v<P, TFHEpp::KeySwitchingKey<Lvl20>>)
    return std::string(path) + "/" + EVAL_KEY_NAME_IKSKLVL20;
  else if constexpr (std::is_same_v<P, TFHEpp::KeySwitchingKey<Lvl21>>)
    return std::string(path) + "/" + EVAL_KEY_NAME_IKSKLVL21;
  else
    static_assert(TFHEpp::false_v<P>, "Unsupported EvalKey Type");
}

template <class P, class Archive>
inline void evalkey_serilize(TFHEEvalKey &ek, Archive &ar) {
  if constexpr (std::is_same_v<P, TFHEpp::BootstrappingKeyFFT<Lvl01>>)
    ek.serialize_bkfftlvl01(ar);
  else if constexpr (std::is_same_v<P, TFHEpp::BootstrappingKeyFFT<Lvl02>>)
    ek.serialize_bkfftlvl02(ar);
  else if constexpr (std::is_same_v<P, TFHEpp::KeySwitchingKey<Lvl10>>)
    ek.serialize_iksklvl10(ar);
  else if constexpr (std::is_same_v<P, TFHEpp::KeySwitchingKey<Lvl20>>)
    ek.serialize_iksklvl20(ar);
  else if constexpr (std::is_same_v<P, TFHEpp::KeySwitchingKey<Lvl21>>)
    ek.serialize_iksklvl21(ar);
  else
    static_assert(TFHEpp::false_v<P>, "Unsupported EvalKey Type");
}

template <class P>
inline decltype(auto) get_evalkey(TFHEEvalKey &ek) {
  if constexpr (std::is_same_v<P, TFHEpp::BootstrappingKeyFFT<Lvl01>>)
    return ek.bkfftlvl01.get();
  else if constexpr (std::is_same_v<P, TFHEpp::BootstrappingKeyFFT<Lvl02>>)
    return ek.bkfftlvl02.get();
  else if constexpr (std::is_same_v<P, TFHEpp::KeySwitchingKey<Lvl10>>)
    return ek.iksklvl10.get();
  else if constexpr (std::is_same_v<P, TFHEpp::KeySwitchingKey<Lvl20>>)
    return ek.iksklvl20.get();
  else if constexpr (std::is_same_v<P, TFHEpp::KeySwitchingKey<Lvl21>>)
    return ek.iksklvl21.get();
  else
    static_assert(TFHEpp::false_v<P>, "Unsupported EvalKey Type");
}

template <bool type>
void serializeSecretKey(TFHESecretKey &sk) {
  using Archive =
      std::conditional_t<IS_LOAD_KEY(type), cereal::PortableBinaryInputArchive,
                         cereal::PortableBinaryOutputArchive>;
  using FileStream =
      std::conditional_t<IS_LOAD_KEY(type), std::ifstream, std::ofstream>;

  std::string file_path = std::string("./") + SECRET_KEY_NAME;
  FileStream fs{file_path, std::ios::binary};
  Archive ar(fs);
  sk.serialize(ar);
}

template <class P, bool type>
void serializeEvalKey(TFHEEvalKey &ek) {
  if constexpr (IS_STORE_KEY(type)) assert(get_evalkey<P>(ek));
  using Archive =
      std::conditional_t<IS_LOAD_KEY(type), cereal::PortableBinaryInputArchive,
                         cereal::PortableBinaryOutputArchive>;
  using FileStream =
      std::conditional_t<IS_LOAD_KEY(type), std::ifstream, std::ofstream>;

  std::string file_path = get_evalkey_path<P>(".");
  FileStream fs{file_path, std::ios::binary};
  Archive ar(fs);
  evalkey_serilize<P>(ek, ar);
}

void generate_sk_ek(TFHESecretKey &sk, TFHEEvalKey &ek) {
  try {
    cout << "Try loading keys" << endl;
    serializeSecretKey<LOAD_KEY>(sk);
    serializeEvalKey<TFHEpp::BootstrappingKeyFFT<Lvl01>, LOAD_KEY>(ek);
    serializeEvalKey<TFHEpp::BootstrappingKeyFFT<Lvl02>, LOAD_KEY>(ek);
    serializeEvalKey<TFHEpp::KeySwitchingKey<Lvl10>, LOAD_KEY>(ek);
    serializeEvalKey<TFHEpp::KeySwitchingKey<Lvl20>, LOAD_KEY>(ek);
    serializeEvalKey<TFHEpp::KeySwitchingKey<Lvl21>, LOAD_KEY>(ek);
  } catch (const exception &e) {
    std::cout << "Generating evaluation key..." << std::endl;
    ek.emplacebkfft<Lvl01>(sk);
    ek.emplacebkfft<Lvl02>(sk);
    ek.emplaceiksk<Lvl10>(sk);
    ek.emplaceiksk<Lvl20>(sk);
    ek.emplaceiksk<Lvl21>(sk);
    serializeSecretKey<STORE_KEY>(sk);
    serializeEvalKey<TFHEpp::BootstrappingKeyFFT<Lvl01>, STORE_KEY>(ek);
    serializeEvalKey<TFHEpp::BootstrappingKeyFFT<Lvl02>, STORE_KEY>(ek);
    serializeEvalKey<TFHEpp::KeySwitchingKey<Lvl10>, STORE_KEY>(ek);
    serializeEvalKey<TFHEpp::KeySwitchingKey<Lvl20>, STORE_KEY>(ek);
    serializeEvalKey<TFHEpp::KeySwitchingKey<Lvl21>, STORE_KEY>(ek);
  }
}

#endif // _SERIALIZE_H_
