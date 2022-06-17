#include <iostream>
#include "seal/util/polyarithsmallmod.h"
#include "seal/util/polycore.h"
#include <chrono>
#include <iostream>
#include <fstream>
#include <algorithm>
#include <random>
#include <pthread.h>
#include "nfl.hpp"
#include "tools.h"
#include "seal/seal.h"
#include "external_prod.h"
#include "util.h"
#include "pir.h"
#include "pir_server.h"
#include "pir_client.h"


using namespace std;
using namespace std::chrono;
using namespace std;
using namespace seal;
using namespace seal::util;


typedef vector<Ciphertext> GSWCiphertext;

void
test_external_prod_with_sk(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                           shared_ptr<SEALContext> context, SecretKey sk) {

    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
    const int base_bits = 8;


    Plaintext gsw_plain(to_string(1));
    Plaintext msg;
    msg.resize(coeff_count);
    msg.set_zero();
    msg[0]=1;

    vector<Ciphertext> sk_gsw_ciphertext;




    ///test ct of rlwe
    Plaintext test_rlwe_pt("1");

    Ciphertext test_rlwe_ct;
    encryptor1.encrypt_symmetric(test_rlwe_pt, test_rlwe_ct);

    cout << "Noise budget before external product=" << decryptor1.invariant_noise_budget(test_rlwe_ct) << endl;

    vector<uint64_t *> rlwe_decom;


    int duration = 0;
    int interations = 0;



    for (int i = base_bits; i > 1; i = ceil(i / 2)) {
        interations++;
        const int lvl = context_data2->total_coeff_modulus_bit_count() / i;


        sk_gsw_ciphertext.clear();
        poc_enc_sk_gsw64(sk, context, i, sk_gsw_ciphertext);



        auto gsw_enc_time_start = std::chrono::steady_clock::now();

        rwle_decompositions64_nocrt(test_rlwe_ct, context, lvl, i, rlwe_decom);
        poc_nfllib_ntt_rlwe_decomp(rlwe_decom);


        /// steps for external product. Both rlwe and gsw must be crt-decomposed
        Ciphertext res_ct;
        res_ct.resize(context, context->first_context_data()->parms_id(), 2);


        poc_nfllib_external_product(sk_gsw_ciphertext, rlwe_decom, context, lvl, res_ct, 1);
        poc_nfllib_intt_ct(res_ct, context);
        auto gsw_enc_time_end = std::chrono::steady_clock::now();

        for (auto p : rlwe_decom) {
            free(p);
        }
        rlwe_decom.clear();




//        for(int i=0; i< sk_gsw_ciphertext.size();i++){
//            Plaintext ppt;
//            decryptor1.decrypt(sk_gsw_ciphertext[i],ppt);
//            cout<< "decrypted : " << ppt.to_string()<<endl;
//        }


            Plaintext ppt;
            decryptor1.decrypt(res_ct,ppt);
            cout<< "decrypted : " << ppt.to_string()<<endl;

        duration = duration_cast<std::chrono::milliseconds>(gsw_enc_time_end - gsw_enc_time_start).count();

        cout << "---------------------------------" << endl;
        cout << "For Base bits=" << i << endl;
        cout << "Noise budget after external product= "
             << decryptor1.invariant_noise_budget(res_ct) << endl;

        cout << "External prod duration= " << duration << "ms" << endl;

 break;
    }


}

void test_external_prod(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                        shared_ptr<SEALContext> context, SecretKey sk) {

    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
    const int base_bits = 30;


//    Plaintext gsw_plain(to_string(1));
    Plaintext msg;
    msg.resize(coeff_count);
    for (int h = 0; h < coeff_count; h++) {


            msg.data()[h] = 1;
            //cout<< msg.data()[h ]<<endl;

    }


    GSWCiphertext choice_bit;


    ///test ct of rlwe
    Plaintext test_rlwe_pt("1");

    Ciphertext test_rlwe_ct;
    encryptor1.encrypt_symmetric(test_rlwe_pt, test_rlwe_ct);

    cout << "-----------------------------------------------" << endl;
    cout << "Noise budget before external product=" << decryptor1.invariant_noise_budget(test_rlwe_ct) << endl;

    vector<uint64_t *> rlwe_decom;


    int duration = 0;
    int interations = 0;
    for (int i = base_bits; i > 1; i = ceil(i / 2)) {
        interations++;
        const int lvl = context_data2->total_coeff_modulus_bit_count() / i;
        choice_bit.clear();


        //poc_gsw_enc128(lvl, i, context, sk, choice_bit, msg, pool, 0);

        poc_gsw_enc64(lvl, i, context, sk, choice_bit, msg, pool, 0);



        poc_nfllib_ntt_gsw(choice_bit, context);

        auto gsw_enc_time_start = std::chrono::steady_clock::now();

        rwle_decompositions64_nocrt(test_rlwe_ct, context, lvl, i, rlwe_decom);


        poc_nfllib_ntt_rlwe_decomp(rlwe_decom);


        /// steps for external product. Both rlwe and gsw must be crt-decomposed
        Ciphertext res_ct;
        res_ct.resize(context, context->first_context_data()->parms_id(), 2);


        poc_nfllib_external_product(choice_bit, rlwe_decom, context, lvl, res_ct, 1);
        poc_nfllib_intt_ct(res_ct, context);
        auto gsw_enc_time_end = std::chrono::steady_clock::now();

        for (auto p : rlwe_decom) {
            free(p);
        }
        rlwe_decom.clear();

        Plaintext ppt;
        decryptor1.decrypt(res_ct,ppt);
        cout<< ppt.to_string()<<endl;


        duration = duration_cast<std::chrono::milliseconds>(gsw_enc_time_end - gsw_enc_time_start).count();

        cout << "---------------------------------" << endl;
        cout << "For Base bits=" << i << endl;
        cout << "Noise budget after external product= "
             << decryptor1.invariant_noise_budget(res_ct) << endl;

        cout << "External prod duration= " << duration << "ms" << endl;
    }


}

void test_nfllib_ct_add(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                        shared_ptr<SEALContext> context, SecretKey sk) {

    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
    Plaintext msg;
    msg.resize(coeff_count);
    for (int h = 0; h < coeff_count; h++) {
        if (h == 0) {

            msg.data()[h] = 1;
//cout<< msg.data()[h ]<<endl;
        } else
            msg.data()[h] = 0;
    }
    Ciphertext ct1, ct2;

    encryptor1.encrypt_symmetric(msg, ct1);
    encryptor1.encrypt_symmetric(msg, ct2);

    auto gsw_enc_time_start = std::chrono::high_resolution_clock::now();
    //poc_nfllib_ntt_ct(test_rlwe_ct, context);

    //poc_nfllib_plain_ct_prod(test_rlwe_ct , msg, context, res_ct);

    //poc_nfllib_add_ct(ct1,ct2,context);
    evaluator1.add_inplace(ct1, ct2);

    auto gsw_enc_time_end = std::chrono::high_resolution_clock::now();
    //poc_nfllib_intt_ct(test_rlwe_ct, context);

    int duration = duration_cast<std::chrono::microseconds>(gsw_enc_time_end - gsw_enc_time_start).count();
    Plaintext ppt;
    decryptor1.decrypt(ct1, ppt);
    cout << duration << endl;


}

void test_gsw_expansion(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                        shared_ptr<SEALContext> context, SecretKey sk) {

    GaloisKeys galois_keys = generate_galois_keys(context, keygen);
    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
    uint64_t base_bit = 8;
    const int l = context_data2->total_coeff_modulus_bit_count() / base_bit;


    //int64_t swapbitsSize = get_swapbits_size(32);
    uint64_t dimension_size = 2048;
    int logsize = ceil(log2(dimension_size));
    int gap = ceil(coeff_count / (1 << logsize));


    cout << "dimension size = " << dimension_size << endl;

    Plaintext msg;
    msg.resize(coeff_count);
    msg.set_zero();
    msg[0]=1;

    // get upper half (l) part of gsw where b*B^i is added to C_0
    vector<Ciphertext> half_gsw_ciphertext;
    //poc_l_pack_enc128(l, base_bit, context, sk, half_gsw_ciphertext, msg, decryptor1,  pool);


    poc_half_gsw_enc64(l, base_bit, context, sk, half_gsw_ciphertext, msg, pool, (1 << logsize ));


    int bsk = 8;
    int lsk = context_data2->total_coeff_modulus_bit_count() / bsk;;
    vector<Ciphertext> sk_gsw_ciphertext;
    //poc_enc_sk_gsw64(sk, context, i, sk_gsw_ciphertext);
    poc_enc_sk_gsw64(sk, context, bsk, sk_gsw_ciphertext);//tested



    vector<GSWCiphertext> CtMuxBits;
    CtMuxBits.resize((1 << logsize), GSWCiphertext(2 * l));


    int size = (1 << logsize);
    vector<GSWCiphertext>::iterator gswCiphers_ptr = CtMuxBits.begin();
    auto expand_start = std::chrono::high_resolution_clock::now();
    thread_server_expand64_nocrt(gswCiphers_ptr, half_gsw_ciphertext, context, 0, l, size, galois_keys, l, base_bit, lsk, bsk,
                           sk_gsw_ciphertext, decryptor1);
    auto expand_end = std::chrono::high_resolution_clock::now();

    int idx=0;
    cout << "client gap = " << logsize << endl;
    poc_nfllib_ntt_gsw(gswCiphers_ptr[idx], context);
    Plaintext test_rlwe_pt("1");
    Ciphertext test_rlwe_ct;
    encryptor1.encrypt_symmetric(test_rlwe_pt, test_rlwe_ct);
    ///steps to crt-compose -> baseB-decompose -> crt-decompose
    vector<uint64_t *> rlwe_decom;
    rwle_decompositions64_nocrt(test_rlwe_ct, context, l, base_bit, rlwe_decom);
    poc_nfllib_ntt_rlwe_decomp(rlwe_decom);



    /// steps for external product. Both rlwe and gsw must be crt-decomposed
    Ciphertext res_ct;
    res_ct.resize(context, context->first_context_data()->parms_id(), 2);
    //set_ciphertext(res_ct, context);

    //poc_external_product(gswCiphers_ptr[0], rlwe_decom, context, l, res_ct);
    poc_nfllib_external_product(gswCiphers_ptr[idx], rlwe_decom, context, l, res_ct, 1);
    poc_nfllib_intt_ct(res_ct, context);


    int duration = 0;
    Plaintext pp;
    decryptor1.decrypt(res_ct, pp);
    cout << "decrypted: " << pp.to_string() << endl;
    cout << "noise budget: " << decryptor1.invariant_noise_budget(res_ct) << endl;

    duration = duration_cast<std::chrono::milliseconds>(expand_end - expand_start).count();
    cout << "plain prod duration: " << duration << "ms" << endl;

}


void test_rlwe_to_gsw(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                        shared_ptr<SEALContext> context, SecretKey sk) {

    GaloisKeys galois_keys = generate_galois_keys(context, keygen);
    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
    uint64_t base_bit = 4;
    const int l = context_data2->total_coeff_modulus_bit_count() / base_bit;




    Plaintext msg;
    msg.resize(coeff_count);
    msg.set_zero();
    msg[0]=1;

    // get upper half (l) part of gsw where b*B^i is added to C_0
    vector<Ciphertext> half_gsw_ciphertext;
    //poc_l_pack_enc128(l, base_bit, context, sk, half_gsw_ciphertext, msg, decryptor1,  pool);

    Ciphertext test_rlwe_ct;
    encryptor1.encrypt_symmetric(msg, test_rlwe_ct);
    //poc_half_gsw_enc64(l, base_bit, context, sk, half_gsw_ciphertext, msg, pool, (1 ));


    int bsk = 4;
    int lsk = context_data2->total_coeff_modulus_bit_count() / bsk;;
    vector<Ciphertext> sk_gsw_ciphertext;
    //poc_enc_sk_gsw64(sk, context, i, sk_gsw_ciphertext);
    poc_enc_sk_gsw64(sk, context, bsk, sk_gsw_ciphertext);//tested



    GSWCiphertext full_gsw_ciphertext;
    full_gsw_ciphertext.resize((2 * l));

    vector<uint64_t *> rlwe_decom;
    for (int i=0 ; i< l; i++){
        full_gsw_ciphertext[i]=test_rlwe_ct;

        Ciphertext res_ct;
        rlwe_decom.clear();
        rwle_decompositions64_nocrt(test_rlwe_ct, context, lsk, bsk, rlwe_decom);
        poc_nfllib_ntt_rlwe_decomp(rlwe_decom);
        res_ct.resize(context, context->first_context_data()->parms_id(), 2);
        poc_nfllib_external_product(sk_gsw_ciphertext, rlwe_decom, context, lsk, res_ct,1);

        for (auto p : rlwe_decom) {
            free(p);
        }
        poc_nfllib_intt_ct(res_ct, context);

        full_gsw_ciphertext[i+l]= res_ct;
   }

    auto expand_start = std::chrono::high_resolution_clock::now();

    for(int i=0; i< full_gsw_ciphertext.size(); i++){

        Plaintext ppt;
        decryptor1.decrypt(full_gsw_ciphertext[i],ppt);
        cout << "decryption of ct: " << i << " " << ppt.to_string()<<endl;

    }


    poc_nfllib_ntt_gsw(full_gsw_ciphertext, context);



    auto expand_end = std::chrono::high_resolution_clock::now();
    Plaintext test_rlwe_pt("0");
    //Ciphertext test_rlwe_ct;
    encryptor1.encrypt_symmetric(test_rlwe_pt, test_rlwe_ct);

    ///steps to crt-compose -> baseB-decompose -> crt-decompose
    vector<uint64_t *> rlwe_decom2;
    rwle_decompositions64(test_rlwe_ct, context, l, base_bit, rlwe_decom2);
    poc_nfllib_ntt_rlwe_decomp(rlwe_decom2);



    /// steps for external product. Both rlwe and gsw must be crt-decomposed
    Ciphertext res_ct;
    res_ct.resize(context, context->first_context_data()->parms_id(), 2);
    //set_ciphertext(res_ct, context);

    //poc_external_product(gswCiphers_ptr[0], rlwe_decom, context, l, res_ct);
    poc_nfllib_external_product(full_gsw_ciphertext, rlwe_decom2, context, l, res_ct, 1);
    poc_nfllib_intt_ct(res_ct, context);


    int duration = 0;
    Plaintext pp;
    decryptor1.decrypt(res_ct, pp);
    cout << "decrypted: " << pp.to_string() << endl;
    cout << "noise budget: " << decryptor1.invariant_noise_budget(res_ct) << endl;

    duration = duration_cast<std::chrono::milliseconds>(expand_end - expand_start).count();
    cout << "plain prod duration: " << duration << "ms" << endl;

}


void
test_homomorphic_permutation(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                             shared_ptr<SEALContext> context, SecretKey sk) {
    GaloisKeys galois_keys = generate_galois_keys(context, keygen);
    const auto &context_data = context->first_context_data();
    auto &parms = context_data->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);
    uint64_t base_bit = 16;
    const int l = 5;
//    context_data->total_coeff_modulus_bit_count() / base_bit;

    //DATA NEEDED  FOR gsw expansion
    int bsk = 16;
    int lsk = context_data->total_coeff_modulus_bit_count() / base_bit;;
    vector<Ciphertext> sk_gsw_ciphertext;
    poc_enc_sk_gsw(sk, context, bsk, sk_gsw_ciphertext);




    //total elements in database and their relevant elements
    uint64_t total_elements = 32;
    uint64_t swapbitsSize = get_swapbits_size(total_elements);

    //spacing of gap needed for packing
    int logsize = ceil(log2(swapbitsSize));
    int gap = ceil(coeff_count / (1 << logsize));
    cout << "swapbits size = " << swapbitsSize << endl;


    //setting up server data
    vector<Ciphertext> server;
    server.resize(total_elements);
    fill_server_bkt(server, total_elements, encryptor1);
    vector<Ciphertext>::iterator input = server.begin();


    //decide the permutation
    vector<uint32_t> permutation;
    permutation.resize(total_elements);
    iota(permutation.begin(), permutation.end(), 0);
    int ttp = total_elements - 1;
    for (int i = 0; i < total_elements; i++) {
        permutation[i] = ttp;
        ttp--;
    }


    int *inverse = computeInversePermutation((int *) permutation.data(), total_elements);
    vector<int> swapbits = sortingNetworkBits(inverse, total_elements);

    assert(swapbits.size() == swapbitsSize);
    Plaintext msg;
    msg.resize(coeff_count);
    for (int h = 0; h < swapbitsSize; h++) {
        msg.data()[h * gap] = ((int64_t) swapbits[h]);
        cout << "swap bit number=" << h << "=" << swapbits[h] << endl;
    }

    //encrypted packked permutation cxtx
    vector<Ciphertext> packed_perm_cxtx;
    poc_half_gsw_enc128(l, base_bit, context, sk, packed_perm_cxtx, msg, pool, (1 << logsize));


    vector<GSWCiphertext> CtMuxBits;
    CtMuxBits.resize((1 << logsize), GSWCiphertext(2 * l));


    int size = (1 << logsize);
    vector<GSWCiphertext>::iterator gswCiphers_ptr = CtMuxBits.begin();

    thread_server_expand(gswCiphers_ptr, packed_perm_cxtx, context, 0, l, size, galois_keys, l, base_bit, lsk, bsk,
                         sk_gsw_ciphertext);

    gswCiphers_ptr = CtMuxBits.begin();


    Plaintext test_rlwe_pt("1");
    Ciphertext test_rlwe_ct;
    encryptor1.encrypt_symmetric(test_rlwe_pt, test_rlwe_ct);

    ///steps to crt-compose -> baseB-decompose -> crt-decompose
    vector<uint64_t *> rlwe_decom;
    rwle_decompositions(test_rlwe_ct, context, l, base_bit, rlwe_decom);
    poc_nfllib_ntt_rlwe_decomp(rlwe_decom);


    /// steps for external product. Both rlwe and gsw must be crt-decomposed

    Ciphertext res_ct;
    res_ct.resize(context, context->first_context_data()->parms_id(), 2);


    //poc_external_product(gswCiphers_ptr[0], rlwe_decom, context, l, res_ct);

    for (int i = 0; i < swapbitsSize; i++) {
        set_ciphertext(res_ct, context);
        poc_nfllib_ntt_gsw(gswCiphers_ptr[i], context);
        poc_nfllib_external_product(gswCiphers_ptr[i], rlwe_decom, context, l, res_ct, 1);
        poc_nfllib_intt_ct(res_ct, context);

        Plaintext pp;
        decryptor1.decrypt(res_ct, pp);
        cout << "decrypted=" << pp.to_string() << endl;
        cout << "noise budget=" << decryptor1.invariant_noise_budget(res_ct) << endl;
    }


}

void test_plain_expansion(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                          shared_ptr<SEALContext> context, SecretKey sk) {

    GaloisKeys galois_keys = generate_galois_keys(context, keygen);
    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);

    uint64_t dimension_size = 4;
    int logsize = ceil(log2(dimension_size));
    int gap = ceil(coeff_count / (1 << logsize));

    int idx = 0;
    Plaintext msg(coeff_count);
    msg.set_zero();
    msg[idx * gap] = 1;

    Plaintext pt;
    pt.resize(coeff_count);
    pt.set_zero();
    pt[0] = 1;


    const int base_bits = 20;

    const int decomp_size = parms.plain_modulus().bit_count() / base_bits;

    //gen gsw ct
    GSWCiphertext packed_ct;



    //poc_plain_gsw_enc128(decomp_size, base_bits, context, sk, packed_ct, msg, pool, dimension_size);

    poc_plain_gsw_enc64(decomp_size, base_bits, context, sk, packed_ct, msg, pool, dimension_size);
    //evaluator1.add_inplace(test,choice_bit[1]);




    vector<GSWCiphertext> list_enc;
    list_enc.resize(dimension_size, GSWCiphertext(decomp_size));

    vector<GSWCiphertext>::iterator list_enc_ptr = list_enc.begin();

    auto gsw_enc_time_start = std::chrono::steady_clock::now();

    //poc_expand_flat_threaded(list_enc_ptr, packed_ct, context, dimension_size, galois_keys);
    poc_expand_flat(list_enc_ptr, packed_ct, context, dimension_size, galois_keys);
    auto gsw_enc_time_end = std::chrono::steady_clock::now();


    vector<uint64_t *> plain_decom;
    plain_decompositions64_nocrt(pt, context, decomp_size, base_bits, plain_decom);


    poc_nfllib_ntt_rlwe_decomp(plain_decom);
    poc_nfllib_ntt_gsw(list_enc[idx], context);
    Ciphertext res_ct;
    res_ct.resize(context, context->first_context_data()->parms_id(), 2);
    poc_nfllib_external_product(list_enc[idx], plain_decom, context, decomp_size, res_ct, 1);
    poc_nfllib_intt_ct(res_ct, context);
    int duration = duration_cast<std::chrono::milliseconds>(gsw_enc_time_end - gsw_enc_time_start).count();
    cout << "Plain expansion duration :" << duration << " ms" << endl;

    Plaintext ppt;
    decryptor1.decrypt(res_ct, ppt);
    cout << "Output value :" << ppt.to_string() << endl;
    cout << "Noise budget after external product :" << decryptor1.invariant_noise_budget(res_ct) << endl;

}

void test_rlwe_expansion(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                         shared_ptr<SEALContext> context, SecretKey sk) {

    GaloisKeys galois_keys = generate_galois_keys(context, keygen);
    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);

    Plaintext msg(coeff_count);


    const int base_bits = 4;

    const int decomp_size = parms.plain_modulus().bit_count() / base_bits;

    //gen gsw ct
    GSWCiphertext packed_ct;

    uint64_t dimension_size = 512;

    msg.set_zero();

    int logsize = ceil(log2(dimension_size));

    msg[0] = 1;
    //msg[1]=1;

    Ciphertext ct;
    encryptor1.encrypt_symmetric(msg, ct);
    poc_plain_gsw_enc64(decomp_size, base_bits, context, sk, packed_ct, msg, pool, (1 << logsize));
    vector<Ciphertext> list_enc;
    //evaluator1.add_inplace(test,choice_bit[1]);
    auto gsw_enc_time_start = std::chrono::steady_clock::now();
    list_enc = poc_rlwe_expand(packed_ct[1], context, galois_keys, (1 << logsize));
    auto gsw_enc_time_end = std::chrono::steady_clock::now();
    int duration = duration_cast<std::chrono::milliseconds>(gsw_enc_time_end - gsw_enc_time_start).count();
    cout << "Plain prod duration= " << duration << " ms" << endl;

    for (int i = 0; i < dimension_size; i++) {


        Plaintext ppt;
        decryptor1.decrypt(list_enc[i], ppt);
        cout <<"Value: "<< ppt.to_string() << endl;
        cout << "Noise budget after external product: " << decryptor1.invariant_noise_budget(list_enc[i]) << endl;
    }

}


void test_plain_flatening(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                          shared_ptr<SEALContext> context, SecretKey sk) {

    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);

    Plaintext msg;
    msg.resize(coeff_count);
    msg.set_zero();
    msg[0] = 1;


    Plaintext pt;
    pt.resize(coeff_count);
    pt.set_zero();
    pt[0] = 240;


    const int base_bits = 7;

    const int decomp_size = parms.plain_modulus().bit_count() / base_bits;

    //gen gsw ct
    GSWCiphertext choice_bit;


    // poc_plain_gsw_enc128(decomp_size, base_bits, context, sk, choice_bit, msg, pool, 0);

    poc_plain_gsw_enc64(decomp_size, base_bits, context, sk, choice_bit, msg, pool, 0);
    //evaluator1.add_inplace(test,choice_bit[1]);



    vector<uint64_t *> plain_decom;
    plain_decompositions64(pt, context, decomp_size, base_bits, plain_decom);



    //evaluator1.transform_to_ntt_inplace(pt,context->first_parms_id());
    //evaluator1.transform_to_ntt_inplace(choice_bit[0]);

    poc_nfllib_ntt_rlwe_decomp(plain_decom);

    poc_nfllib_ntt_gsw(choice_bit, context);


    auto gsw_enc_time_start = std::chrono::steady_clock::now();

    Ciphertext res_ct;
    res_ct.resize(context, context->first_context_data()->parms_id(), 2);
    poc_nfllib_external_product(choice_bit, plain_decom, context, decomp_size, res_ct, 1);

    auto gsw_enc_time_end = std::chrono::steady_clock::now();

    poc_nfllib_intt_ct(res_ct, context);


    int duration = duration_cast<std::chrono::microseconds>(gsw_enc_time_end - gsw_enc_time_start).count();
    cout << "Plain prod duration= " << duration << " us" << endl;

    Plaintext ppt;
    decryptor1.decrypt(res_ct, ppt);
    cout << ppt.to_string() << endl;
    cout << "Noise budget after external product " << decryptor1.invariant_noise_budget(res_ct) << endl;

}

void test_external_prod_chain(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
                              shared_ptr<SEALContext> context, SecretKey sk) {

    const auto &context_data2 = context->first_context_data();
    auto &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);


    const int base_bits = 40;
    int iterations = 1000;


    Plaintext gsw_plain(to_string(1));
    Plaintext msg;
    msg.resize(coeff_count);
    msg.set_zero();
    msg[0] = 1;



    const int lvl = context_data2->total_coeff_modulus_bit_count() / base_bits;

    //gen gsw ct
    GSWCiphertext choice_bit;
    poc_gsw_enc128(lvl, base_bits, context, sk, choice_bit, msg, pool, 0);


    ///gen ct of rlwe
    Plaintext test_rlwe_pt("12345678");
    Ciphertext test_rlwe_ct;
    encryptor1.encrypt_symmetric(test_rlwe_pt, test_rlwe_ct);

    ///steps to crt-compose -> baseB-decompose -> crt-decompose
    vector<uint64_t *> rlwe_decom;
    rwle_decompositions(test_rlwe_ct, context, lvl, base_bits, rlwe_decom);

    Ciphertext res_ct;
    res_ct.resize(context, context->first_context_data()->parms_id(), 2);
    poc_nfllib_external_product(choice_bit, rlwe_decom, context, lvl, res_ct, 1);


    cout << "-----------------------------------------------" << endl;
    cout << " Testing external product chain " << endl;
    cout << "-----------------------------------------------" << endl;


    GSWCiphertext chain_gsw;
    poc_gsw_enc128(lvl, base_bits, context, sk, chain_gsw, msg, pool, 0);

    int i = 1;
    while (decryptor1.invariant_noise_budget(res_ct) > 0 && i < iterations) {
        i++;

        Plaintext pp;
        decryptor1.decrypt(res_ct, pp);
        cout << "Noise budget after " << i << " external product " << decryptor1.invariant_noise_budget(res_ct) << endl;

        vector<uint64_t *> rlwe_decom;
        rwle_decompositions(res_ct, context, lvl, base_bits, rlwe_decom);

        poc_nfllib_external_product(choice_bit, rlwe_decom, context, lvl, res_ct, 1);
        poc_nfllib_intt_ct(res_ct, context);
        for (auto p : rlwe_decom) {
            free(p);
        }
        rlwe_decom.clear();

    }

    cout << "-----------------------------------------------" << endl;
    cout << " Testing bfv product chain " << endl;
    cout << "-----------------------------------------------" << endl;


    Plaintext left_rlwe_pt("1");
    Ciphertext left_rlwe_ct;
    encryptor1.encrypt_symmetric(left_rlwe_pt, left_rlwe_ct);


    Ciphertext res_ct_;


    i = 0;
    while (decryptor1.invariant_noise_budget(test_rlwe_ct) > 0 && i < iterations) {


        evaluator1.multiply_inplace(test_rlwe_ct, left_rlwe_ct);
        cout << "Noise budget after " << i << " product " << decryptor1.invariant_noise_budget(test_rlwe_ct) << endl;
        i++;
    }
    if (i == 0)
        cout << "Noise budget after " << i << " product " << decryptor1.invariant_noise_budget(test_rlwe_ct) << endl;

}


void test_seal(Evaluator &evaluator1, Encryptor &encryptor1, Decryptor &decryptor1, KeyGenerator &keygen,
               shared_ptr<SEALContext> context, SecretKey sk) {

    const auto &context_data2 = context->first_context_data();
    const seal::EncryptionParameters &parms = context_data2->parms();
    auto &coeff_modulus = parms.coeff_modulus();
    size_t coeff_modulus_size = coeff_modulus.size();
    auto small_ntt_tables = context_data2->small_ntt_tables();
    size_t coeff_count = parms.poly_modulus_degree();
    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);


    Plaintext gsw_plain(to_string(1));
    Plaintext msg;
    msg.resize(coeff_count);
    for (int h = 0; h < coeff_count; h++) {

        msg.data()[h] = 1;

    }

    Ciphertext test_rlwe_ct, temp;
    encryptor1.encrypt_symmetric(msg, test_rlwe_ct);


    evaluator1.transform_to_ntt_inplace(msg, context->first_parms_id());
    evaluator1.transform_to_ntt_inplace(test_rlwe_ct);
    //evaluator1.transform_to_ntt_inplace(test_rlwe_ct);

    int duration = 0;
    int iterations = 1000;
    Ciphertext res_ct;
    for (int i = 0; i < iterations; i++) {


        auto gsw_enc_time_start = std::chrono::high_resolution_clock::now();
        //poc_nfllib_ntt_ct(test_rlwe_ct, context);
        evaluator1.multiply_plain_inplace(test_rlwe_ct, msg);
        //poc_nfllib_plain_ct_prod(test_rlwe_ct , msg, context, res_ct);
        auto gsw_enc_time_end = std::chrono::high_resolution_clock::now();
        //poc_nfllib_intt_ct(test_rlwe_ct, context);

        duration = duration + duration_cast<std::chrono::microseconds>(gsw_enc_time_end - gsw_enc_time_start).count();
    }

    //evaluator1.transform_from_ntt_inplace(res_ct);
    Plaintext ppt;
    //decryptor1.decrypt(res_ct, ppt);
    //cout<< ppt.to_string()<<endl;

    //evaluator1.transform_to_ntt_inplace(msg,context->first_parms_id());



    //poc_nfllib_plain_ct_prod2(test_rlwe_ct,msg,context,temp);
    //poc_nfllib_plain_ct_prod(test_rlwe_ct,msg,context,temp);
    //evaluator1.multiply_plain(test_rlwe_ct,msg,temp);

    //evaluator1.multiply_plain(test_rlwe_ct,msg,temp);



    cout << "prod duration= " << duration / iterations << " us" << endl;
    //evaluator1.add_inplace(test_rlwe_ct,temp);

}

int main_tests() {

    EncryptionParameters parms(scheme_type::BFV);
    //set_bfv_parms64(parms);
    auto context = SEALContext::Create(parms);
    print_line(__LINE__);
    print_parameters(context);

    KeyGenerator keygen(context);

    //generating secret key
    Plaintext secret_key_pt;
    SecretKey secret_key = keygen.secret_key();


    /// generating encryptor, decryptor and evaluator
    Encryptor encryptor(context, secret_key);
    Decryptor decryptor(context, secret_key);
    Evaluator evaluator(context);


    //test_rlwe_to_gsw(evaluator, encryptor, decryptor, keygen, context, secret_key);
    //test_gsw_expansion(evaluator, encryptor, decryptor, keygen, context, secret_key);
    //test_homomorphic_permutation(evaluator, encryptor, decryptor, keygen, context, secret_key);
    //test_rlwe_expansion(evaluator, encryptor, decryptor, keygen,  context, secret_key);
    //test_plain_expansion(evaluator, encryptor, decryptor, keygen, context, secret_key);
    //test_nfllib_ct_add(evaluator, encryptor, decryptor, keygen,  context, secret_key);
    //test_plain_flatening(evaluator, encryptor, decryptor, keygen,  context, secret_key);
    //test_external_prod_with_sk(evaluator, encryptor, decryptor, keygen,  context, secret_key);
    //test_external_prod(evaluator, encryptor, decryptor, keygen,  context, secret_key);
    //test_external_prod_chain(evaluator, encryptor, decryptor, keygen,  context, secret_key);
    //test_seal(evaluator, encryptor, decryptor, keygen,  context, secret_key);
    return 0;
}

int main_onionpir_big() {

    uint64_t number_of_items = 1 << 14;
    uint64_t size_per_item = 30000; // in bytes
    uint32_t N = 4096;

    // Recommended values: (logt, d) = (12, 2) or (8, 1).
    uint32_t logt = 60;
    PirParams pir_params;


    EncryptionParameters parms(scheme_type::BFV);
    set_bfv_parms(parms);
    gen_params(number_of_items, size_per_item, N, logt,
               pir_params);


//    auto context = SEALContext::Create(parms);
//    print_line(__LINE__);
//    print_parameters(context);
//
//    const auto &context_data2 = context->first_context_data();
//    auto &coeff_modulus = parms.coeff_modulus();
//    size_t coeff_modulus_size = coeff_modulus.size();
//    auto small_ntt_tables = context_data2->small_ntt_tables();
//    size_t coeff_count = parms.poly_modulus_degree();
//    auto pool = MemoryManager::GetPool(mm_prof_opt::FORCE_NEW);






    cout << "Main: Initializing the database (this may take some time) ..." << endl;

    // Create test database
    auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));

    // Copy of the database. We use this at the end to make sure we retrieved
    // the correct element.
    auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));

    random_device rd;

    for (uint64_t i = 0; i < number_of_items; i++) {
        for (uint64_t j = 0; j < size_per_item; j++) {
//            auto val =  123;
            db.get()[(i * size_per_item) + j] = i + j;
            db_copy.get()[(i * size_per_item) + j] = i + j;
            //cout<<db.get()[(i * size_per_item) + j]<<endl;
        }
    }

    // Initialize PIR Server
    cout << "Main: Initializing server and client" << endl;
    pir_server server(parms, pir_params);

    // Initialize PIR client....
    pir_client client(parms, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();

    cout << "Main: Setting Galois keys...";
    server.set_galois_key(0, galois_keys);

    auto time_pre_s = high_resolution_clock::now();
    server.set_database(move(db), number_of_items, size_per_item);
    server.preprocess_database();
    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();

    uint64_t ele_index = rd() % number_of_items; // element in DB at random position
    //uint64_t ele_index =20;
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item);
    cout << "Main: element index = " << ele_index << " from [0, " << number_of_items - 1 << "]" << endl;
    cout << "Main: FV index = " << index << ", FV offset = " << offset << endl;

    // offset in FV plaintext
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query_combined(index);

    cout << "Main: query size = " << query.size() << endl;

    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;

    //client.test_query_expansion( query,  galois_keys);
    SecretKey sk = client.get_decryptor();

    GSWCiphertext enc_sk = client.get_enc_sk();
    server.set_enc_sk(enc_sk);

    auto time_server_s = high_resolution_clock::now();
    PirReply reply = server.generate_reply_combined(query, 0, sk);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us = duration_cast<microseconds>(time_server_e - time_server_s).count();

    Plaintext rep = client.decrypt_result(reply);

    // Convert from FV plaintext (polynomial) to database element at the client
    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, rep, elems.data(), (N * logt) / 8);

    // Check that we retrieved the correct element
    for (uint32_t i = 0; i < size_per_item; i++) {

        if (elems[(offset * size_per_item) + i] != db_copy.get()[(ele_index * size_per_item) + i]) {
            cout << "Main: elems " << (int) elems[(offset * size_per_item) + i] << ", db "
                 << (int) db_copy.get()[(ele_index * size_per_item) + i] << endl;
            cout << "Main: PIR result wrong!" << endl;
            return -1;
        }
    }

    // Output results
    cout << "Main: PIR result correct!" << endl;
    cout << "Main: PIRServer pre-processing time: " << time_pre_us / 1000 << " ms" << endl;
    cout << "Main: PIRClient query generation time: " << time_query_us / 1000 << " ms" << endl;
    cout << "Main: PIRServer reply generation time: " << time_server_us / 1000 << " ms"
         << endl;
    //cout << "Main: Reply num ciphertexts: " << reply.size() << endl;

    return 0;
}

int main_onionpir_small() {

    uint64_t number_of_items = 1 << 14;
    uint64_t size_per_item = 16000; // in bytes
    size_t N = 8192;
    uint32_t logt = 17;
    PirParams pir_params;
    EncryptionParameters bfv_parms(scheme_type::BFV);
    set_bfv_parms64(bfv_parms, N, logt);
    set_pir_params64(number_of_items, size_per_item, N, logt,
                 pir_params);
    auto context = SEALContext::Create(bfv_parms);
    print_line(__LINE__);
    print_parameters(context);
    cout << "Main: Initializing the database (this may take some time) ..." << endl;

    // Create test database
    auto db(make_unique<uint8_t[]>(number_of_items * size_per_item));
    // Copy of the database. We use this at the end to make sure we retrieved
    // the correct element.
    auto db_copy(make_unique<uint8_t[]>(number_of_items * size_per_item));
    random_device rd;
    for (uint64_t i = 0; i < number_of_items; i++) {
        for (uint64_t j = 0; j < size_per_item; j++) {

            auto val = rd() % 128;
            db.get()[(i * size_per_item) + j] = val;
            db_copy.get()[(i * size_per_item) + j] = val;

        }
    }

    // Initialize PIR Server
    cout << "Main: Initializing server and client" << endl;
    pir_server server(bfv_parms, pir_params);
    // Initialize PIR client
    pir_client client(bfv_parms, pir_params);
    GaloisKeys galois_keys = client.generate_galois_keys();
    cout << "Main: Setting Galois keys...";
    server.set_galois_key(0, galois_keys);
    auto time_pre_s = high_resolution_clock::now();
    server.set_database(move(db), number_of_items, size_per_item);
    // NTT processing of database
    server.preprocess_database64();
    auto time_pre_e = high_resolution_clock::now();
    auto time_pre_us = duration_cast<microseconds>(time_pre_e - time_pre_s).count();

    uint64_t ele_index = rd() % number_of_items; // element in DB at random position
    uint64_t index = client.get_fv_index(ele_index, size_per_item);   // index of FV plaintext
    uint64_t offset = client.get_fv_offset(ele_index, size_per_item);
    cout << "Main: element index = " << ele_index << " from [0, " << number_of_items - 1 << "]" << endl;
    cout << "Main: FV index = " << index << ", FV offset = " << offset << endl;

    // offset in FV plaintext
    auto time_query_s = high_resolution_clock::now();
    PirQuery query = client.generate_query_combined64(index);
    cout << "Main: query size = " << query.size() << endl;
    auto time_query_e = high_resolution_clock::now();
    auto time_query_us = duration_cast<microseconds>(time_query_e - time_query_s).count();
    cout << "Main: query generated" << endl;

    //client.test_query_expansion( query,  galois_keys);
    SecretKey sk = client.get_decryptor();

    GSWCiphertext enc_sk = client.get_enc_sk();
    server.set_enc_sk(enc_sk);

    auto time_server_s = high_resolution_clock::now();
    PirReply reply = server.generate_reply_combined64(query, 0, sk);
    auto time_server_e = high_resolution_clock::now();
    auto time_server_us = duration_cast<microseconds>(time_server_e - time_server_s).count();

    Plaintext rep = client.decrypt_result(reply);

    //cout << rep.to_string() << endl;
    // Convert from FV plaintext (polynomial) to database element at the client
    vector<uint8_t> elems(N * logt / 8);
    coeffs_to_bytes(logt, rep, elems.data(), (N * logt) / 8);

    // Check that we retrieved the correct element
    for (uint32_t i = 0; i < size_per_item; i++) {
        //cout << "Main: elems " << (int)elems[(offset * size_per_item) + i] <<endl;
        if (elems[(offset * size_per_item) + i] != db_copy.get()[(ele_index * size_per_item) + i]) {

            cout << "Main: elems " << (int) elems[(offset * size_per_item) + i] << ", db "
                 << (int) db_copy.get()[(ele_index * size_per_item) + i] << endl;
            cout << "Main: PIR result wrong!" << i << endl;
            return -1;
        }
    }

    // Output results
    cout << "Main: PIR result correct!" << endl;
    cout << "Main: PIRServer pre-processing time: " << time_pre_us / 1024 << " ms" << endl;
    cout << "Main: PIRClient query generation time: " << time_query_us / 1024 << " ms" << endl;
    cout << "Main: PIRServer reply generation time: " << time_server_us / 1024 << " ms"
         << endl;

    return 0;
}


int main() {

    main_onionpir_small();

    //main_onionpir_big();
    //main_tests();

    return 0;
}
