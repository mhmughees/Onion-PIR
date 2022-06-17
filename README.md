# OnionPIR: Response-Efficient Single-Server Private Information Retrieval
This repository contains code for [OnionPIR: Response Efficient Single-Server PIR](https://eprint.iacr.org/2021/1081) 

Note that OnionPIR protocol can be implemented using different parameters selection. In paper we disccussed one such selection that showed best results but we can optimize OninPIR design by picking different parameters. Check branch [small-onionpir](https://github.com/mhmughees/Onion-PIR/tree/mughees/small-onionpir) for one extra example.


### Dependencies
- [Microsoft Seal version 3.5](https://github.com/microsoft/SEAL/tree/3.5.0)
- [NFLlib](https://github.com/quarkslab/NFLlib) 


OnionPIR scheme utilizes recent advances in somewhat homomorphic encryption (SHE) and carefully composes two lattice-based SHE schemes and homomorphic operations to control the noise growth and response size. OnionPIR achieves a response overhead of just 4.2x over the insecure baseline.

<!-- ## Implementation details

- Our implementation is based on Microsoft Seal and NFLlib. Specifically, we have utilized CRT variant of **BFV** scheme that is implemented in Microsoft Seal. Due to CRT, our implementation could handle coefficient modulus of 124 bits. 
- We have implemented **RGSW** encryption schemes within Microsoft Seal from scratch and only used few helper functions to manage polynomials. 
- Even thought Microsoft Seal provides NTT based polynomial multiplications which has a complexity of *O(n log n)*. But we found Microsoft Seal's implementation of polynomial multiplications at least 3x slower than similar libraries such as TFHE. Therefore, we further integrated **NFLlib** polynomial mutiplications within Microsoft seal. **NFLlib** is an efficient C++ library specialized in polynomial rings operations. It uses several programming optimization techniques (SSE and AVX2 specializations) to provide efficient polynomial operations. 
 -->
## Compilation

1. First download [Microsoft Seal version 3.5.1](https://github.com/microsoft/SEAL/tree/3.5.1). This will be cloned in SEAL directory. 
 - Make following changes to line 29-37 of [/native/src/seal/util/defines.h
](https://github.com/microsoft/SEAL/blob/f7d748c97ed841376c4a1cdec9e7c978f5e64a95/native/src/seal/util/defines.h#L29)
```
// Bounds for bit-length of all coefficient moduli
//#define SEAL_MOD_BIT_COUNT_MAX 61
#define SEAL_MOD_BIT_COUNT_MAX 62
#define SEAL_MOD_BIT_COUNT_MIN 2

// Bit-length of internally used coefficient moduli, e.g., auxiliary base in BFV
//#define SEAL_INTERNAL_MOD_BIT_COUNT 61
#define SEAL_INTERNAL_MOD_BIT_COUNT 62

// Bounds for bit-length of user-defined coefficient moduli
//#define SEAL_USER_MOD_BIT_COUNT_MAX 60
#define SEAL_USER_MOD_BIT_COUNT_MAX 62
#define SEAL_USER_MOD_BIT_COUNT_MIN 2
```

- Comment following lines in [/native/src/seal/context.cpp ](https://github.com/microsoft/SEAL/blob/f7d748c97ed841376c4a1cdec9e7c978f5e64a95/native/src/seal/context.cpp#L211)

```
//    // Check if the parameters are secure according to HomomorphicEncryption.org security standard
//  if (context_data.total_coeff_modulus_bit_count_ > CoeffModulus::MaxBitCount(poly_modulus_degree, sec_level_))
//    {
//       // Not secure according to HomomorphicEncryption.org security standard
//       context_data.qualifiers_.sec_level = sec_level_type::none;
//       if (sec_level_ != sec_level_type::none)
//         {
//             // Parameters are not valid
//              context_data.qualifiers_.parameter_error = error_type::invalid_parameters_insecure;
//              return context_data;
//          }
//    }
```

 - Make following changes to line 29-37 of [/native/src/seal/util/rns.cpp
](https://github.com/microsoft/SEAL/blob/f7d748c97ed841376c4a1cdec9e7c978f5e64a95/native/src/seal/util/rns.cpp#L588)
```
//auto baseconv_primes = get_primes(coeff_count_, SEAL_USER_MOD_BIT_COUNT_MAX + 1, base_Bsk_m_tilde_size);
auto baseconv_primes = get_primes(coeff_count_, SEAL_USER_MOD_BIT_COUNT_MAX , base_Bsk_m_tilde_size);
```
*These changes are needed because there is incompatibility between SEAL and NFLlib*

2. Now build and install SEAL library by using following commands:
```
cmake . -DCMAKE_BUILD_TYPE=Release -DSEAL_USE_MSGSL=OFF -DSEAL_USE_ZLIB=OFF
make
sudo make install
```

3. And then install [NFLlib](https://github.com/micciancio/NFLlib) 
4. Make sure these libraries are properly installed in `/usr/local/lib`  and `/usr/local/include`
5. Now clone Onion-PIR in seprate folder.
6. Then build the library using following commands:
```
cmake . -DCMAKE_BUILD_TYPE=Release -DNTT_AVX2=ON -DSEAL_USE_ZLIB=OFF -DSEAL_USE_MSGSL=OFF
make
```

7. Then just run `./onionpir`. This file is your build file that should be in the same folder where you run above commands.

## PIR Library
- This implementation sets `q\approx 2^{124}, n=4096, t\approx 2^{60}`, where q= coefficient mod, n= polynomial degree, t= plaintext mod. These parameters allow expansion factor of 4.2 only. 

- There are a `Server` and `Client` classes with their dedicated operations.
- `Server.set_database:` Initialize the database.
- `Server.preprocess_database:` Performs decomposition and NTT on the database and store database in NTTes form.  
- `Client.generate_query_combined:` Generates query for client index.
- `Server.generate_reply_combined:` Evaluates PIR query over database using client's encrypted query. 

 
