#pragma once
#include "seal/seal.h"

namespace seal
{
    template <class T, class A>
    void pack_encode(std::vector<T, A> &input, double scale, Plaintext &plain, CKKSEncoder &ckks_encoder)
    {
        size_t slot_count = ckks_encoder.slot_count();
        size_t input_size = input.size();
        if (input_size <= slot_count)
        {
            int step_size = slot_count / input_size;
            std::vector<double> plain_input(slot_count, 0.);
            for (size_t i = 0; i < slot_count; i++)
            {
                plain_input[i] = (double)input[i % input_size];
            }
            ckks_encoder.encode(plain_input, scale, plain);
        }
        else
        {
            throw std::invalid_argument("Out of size.");
        }
    }

    void pack_encode_param_id(std::vector<double> &input, seal::parms_id_type param_id, 
                                double scale, Plaintext &plain, CKKSEncoder &ckks_encoder);

    void pack_decode(std::vector<double> &result, Plaintext &plain, CKKSEncoder &ckks_encoder);

    void add_scalar(Ciphertext &result, double scalar, CKKSEncoder &ckks_encoder, Evaluator &evaluator);

    void multiply_scalar(Ciphertext &result, double scalar, double scale, CKKSEncoder &ckks_encoder, Evaluator &evaluator);

    void multiply_and_relinearize(Ciphertext &cipher1, Ciphertext &cipher2, Ciphertext &result, Evaluator &evaluator, RelinKeys &relin_keys);

    void encrypt_no_noise(Ciphertext result, Plaintext &plain, Encryptor &encryptor);

} // namespace seal
