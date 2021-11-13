# OnionPIR: Response-Efficient Single-Server Private Information Retrieval
This is a codebase of OnionPIR which is the state-of-art single server PIR scheme.

--over the course of next few weeks this library will be updated to become more stable 

### Dependencies
- [Microsoft Seal version 3.5](https://github.com/microsoft/SEAL/tree/3.5.0)
- [NFLlib](https://github.com/quarkslab/NFLlib) 


# OnionPIR
This repository contains code for [OnionPIR: Response Efficient Single-Server PIR](https://eprint.iacr.org/2021/1081) 

OnionPIR scheme utilizes recent advances in somewhat homomorphic encryption (SHE) and carefully composes two lattice-based SHE schemes and homomorphic operations to control the noise growth and response size. OnionPIR achieves a response overhead of just 4.2x over the insecure baseline.

## Implementation details

- Our implementation is based on Microsoft Seal and NFLlib. Specifically, we have utilized CRT variant of **BFV** scheme that is implemented in Microsoft Seal. Due to CRT, our implementation could handle coefficient modulus of 124 bits. 
- We have implemented **RGSW** encryption schemes within Microsoft Seal from scratch and only used few helper functions to manage polynomials. 
- Even thought Microsoft Seal provides NTT based polynomial multiplications which has a complexity of *O(n log n)*. But we found Microsoft Seal's implementation of polynomial multiplications at least 3x slower than similar libraries such as TFHE. Therefore, we further integrated **NFLlib** polynomial mutiplications within Microsoft seal. **NFLlib** is an efficient C++ library specialized in polynomial rings operations. It uses several programming optimization techniques (SSE and AVX2 specializations) to provide efficient polynomial operations. 

## Compilation

- First install [Microsoft Seal version 3.5.1](https://github.com/microsoft/SEAL/tree/3.5.1) 
- And then install [NFLlib](https://github.com/micciancio/NFLlib) 
- Make sure these libraries are properly installed in `/usr/local/lib`  and `/usr/local/include`
- Then compile this code using `cmake` with these cmake options `-DCMAKE_BUILD_TYPE=Release -DNTT_AVX2=ON -DSEAL_USE_ZLIB=OFF  -DSEAL_USE_MSGSL=OFF`
- Then run `make` in the same folder
- Then just run `./onionpir`. This file is your compiled file that should be in the same folder where you run make.

## PIR Library
- This implementation sets `q=2^{124}, n=4096, t=2^{62}`, where q= coefficient mod, n= polynomial degree, t= plaintext mod. These parameters allow expansion factor of 4.2 only. 

- There are a `Server` and `Client` classes with their dedicated operations.
- `Server.set_database:` Initialize the database.
- `Server.preprocess_database:` Performs decomposition and NTT on the database and store database in NTTes form.  
- `Client.generate_query_combined:` Generates query for client index.
- `Server.generate_reply_combined:` Evaluates PIR query over database using client's encrypted query. 

## Note for compiling on MacOS

For Macos change your c++ compiler to 
