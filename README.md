# is-crypto-openssl

This C program (`s9118.c`) solves the exam task for processing and encrypting given binary files using OpenSSL.  
It operates entirely in memory and does not read intermediate results from files.

The processing includes the following steps:

1. Decryption
    - The files `s91187-cipher1.bin` and `s91187-cipher2.bin` are decrypted using AES-192-CBC.
    - The key is read from `s911878-key1.bin`
    - Initialization vectors (IVs) are extracted directly from the files, as they are stored at the beginning of the ciphertext.
2. Hash verification
    - The decrypted plaintexts are hashed using SHA-224.
    - Only the plaintext whose hash matches the expected hash in `s91187-dgst.bin` is further processed; the other is discarded
3. Cleaning up impaired text
    - The beginning of the plaintext contains a section affected by sticky keys (`u`/`i`).
    - The program removes extra `u` or `i` characters based on majority vote, leaving the rest of the plaintext unchanged.
    - Result: cleaned data = [cleaned text][\0][unaltered text]
4. Encryption of cleaned data
    - The cleaned data is encrypted using SM4-CTR.
    - The key is taken from `s91187-key2.bin`.
    - The initialization vector is generated pseudorandomly.
    - Result: IV + ciphertext stored sequentially in `s91187-result.bin`.

### Build and Execution

```bash
make
make run
```