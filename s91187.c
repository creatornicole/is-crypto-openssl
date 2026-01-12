/*
 * s91187.c
 * 
 * This program demonstrates a complete cryptographic processing pipeline usign OpenSSL:
 * - Decryption of two AES-192-CBC encrypted ciphertexts
 * - Hashing of the resulting plaintexts with SHA-224
 * - Selection of the plaintext matching a given reference hash
 * - Post-processing of the selected plaintext
 * - Re-encryption using SM4 in CTR mode with a freshly generated IV
 * 
 * The final output consists of the generated IV followed by the ciphertext,
 * written to a binary output file.
 * 
 * build and run with:
 *	make
 *	make run
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// TODO: mit define arbeiten für Dateinamen
#define OUT_FILE    "s91187-result.bin"

//-- Helper Functions ---------------------------------------------- //
unsigned char* read_key(const char *filepath, size_t key_len)
{
	// open file
	FILE *f = fopen(filepath, "rb");
	if (!f) {
		printf("cannot open key file %s\n", filepath);
		return NULL;
	}

	// allocate memory at runtime
	unsigned char *key = malloc(key_len);
	if (!key) {
		printf("malloc failed for key from %s\n", filepath);
		fclose(f);
		return NULL;
	}

	// read key
	if (fread(key, 1, key_len, f) != key_len) {
		printf("cannot read key from %s\n", filepath);
		free(key);
		fclose(f);
		return NULL;
	}

	fclose(f);

	return key;
}

unsigned char* read_iv(FILE *cipher_file, size_t iv_len)
{
	// allocate memory at runtime
	unsigned char *iv = malloc(iv_len);
	if (!iv) {
		printf("malloc failed for IV\n");
		return NULL;
	}

	if (fread(iv, 1, iv_len, cipher_file) != iv_len) {
		printf("cannot read IV from cipher file\n");
		free(iv);
		return NULL;
	}

	// hint: the file pointer now points directly after the IV
	return iv;
}

FILE* open_file(const char *filepath)
{
	FILE *file = fopen(filepath, "rb");
	if (!file) {
		printf("cannot open cipher file %s\n", filepath);
		perror(filepath);
		return NULL;
	}
	return file;
}

int check_file_pointer(FILE *file, const char *filename, size_t iv_len)
{
	long pos = ftell(file);
	if (pos == -1L) {
		perror("ftell failed");
		return 1;
	}

	printf("File pointer for %s is at position: %ld\n", filename, pos);

	if (pos == iv_len) {
		printf("File pointer %s is correctly just after the IV\n", filename);
		return 0;
	} else {
		printf("File pointer %s is NOT after IV\n", filename);
		return 1;
	}
}

unsigned char* read_file(FILE *file, size_t offset, size_t *data_size)
{
	// position file pointer and determine file size
	fseek(file, 0, SEEK_END);
	long filesize = ftell(file);
	if (filesize <= 0 || offset > (size_t)filesize) {
		printf("invalid file parameters: filesize=%ld, offset=%ld\n", filesize, offset);
		return NULL;
	}
	fseek(file, offset, SEEK_SET);

	*data_size = filesize - offset;

	// allocate memory
	unsigned char *txt = malloc(*data_size);
	if (!txt) { perror("malloc failed"); return NULL; }

	// read file content
	if (fread(txt, 1, *data_size, file) != *data_size) {
		perror("fread failed");
		printf("cannot read file\n");
		free(txt);
		return NULL;
	}

	// return file content
	return txt;
}

unsigned char* decrypt(const EVP_CIPHER *cipher_type, unsigned char *ciphertext, size_t cipher_len, 
	const unsigned char *key, const unsigned char *iv, size_t *plaintext_len) 
{
	// allocate memory for plaintext
	int block_size = EVP_CIPHER_block_size(cipher_type);
	unsigned char *plain = malloc(cipher_len + block_size);
	if (!plain) { perror("malloc failed for decrypt"); return NULL; }

	// create and initialize context (stores the state of the decryption operation)
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) { printf("cannot create context\n"); free(plain); return NULL; }

	// initialize the decryption operation
	if (!EVP_DecryptInit_ex(ctx, cipher_type, NULL, key, iv)) {
		printf("EVP_DecryptInit_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		free(plain);
		return NULL;
	}

	// decrypt
	int decrypted_len = 0; // will store number of bytes written by EVP_DecryptUpdate
	if (!EVP_DecryptUpdate(ctx, plain, &decrypted_len, ciphertext, cipher_len)) {
		printf("EVP_DecryptUpdate failed\n");
		EVP_CIPHER_CTX_free(ctx);
		free(plain);
		return NULL;
	}

	// finalize decryption (handles any remaining bytes (e.g., due to padding in block ciphers))
	int final_len = 0; // will store number of bytes written by EVP_DecryptFinal_ex
	if (!EVP_DecryptFinal_ex(ctx, plain + decrypted_len, &final_len)) {
		printf("EVP_DecryptFinal_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		free(plain);
		return NULL;
	}

	// total plaintext length (must sum bytes written by Update + Final because padding may change length)
	*plaintext_len = (size_t)decrypted_len + (size_t)final_len;
	
	// cleanup
	EVP_CIPHER_CTX_free(ctx);

	// return pointer to decrpyted plaintext
	return plain;
}

unsigned char *compute_digest(const EVP_MD *hash_type, const unsigned char *data, size_t len, size_t hash_len) 
{
	// allocate memory for digest/hash
	unsigned char *digest = malloc(hash_len);
	if (!digest) { perror("malloc failed for digest"); return NULL; }

	// create and initialize context (stores the state of the hash operation)
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) { 
		printf("cannot create context\n");
		free(digest);
		return NULL;
	}

	// initialize the hash operation
	if (!EVP_DigestInit_ex(ctx, hash_type, NULL)) {
		printf("EVP_DigestInit_ex failed\n");
		EVP_MD_CTX_free(ctx);
		free(digest);
		return NULL;
	}

	// hash
	unsigned int digest_len = 0; // will store number of bytes written by EVP_DigestUpdate
	if (!EVP_DigestUpdate(ctx, data, len)) {
		printf("EVP_DigestUpdate failed\n");
		EVP_MD_CTX_free(ctx);
		free(digest);
		return NULL;
	}

	// finalize hashing
	if (!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {
		printf("EVP_DigestFinal_ex failed\n");
		EVP_MD_CTX_free(ctx);
		free(digest);
		return NULL;
	}

	if (digest_len != hash_len) {
		printf("Digest length mismatch: expected %zu bytes, got %u bytes\n", hash_len, digest_len);
		EVP_MD_CTX_free(ctx);
		free(digest);
		return NULL;
	}


	// cleanup
	EVP_MD_CTX_free(ctx);

	// return pointer to hash
	return digest;
}

void print_hex(const unsigned char *buf, size_t len)
{
	for (size_t i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

unsigned char* encrypt(const EVP_CIPHER *cipher_type, unsigned char *plain, size_t plain_len,
	const unsigned char *key, const unsigned char *iv, size_t *cipher_len)
{
	// allocate memory for cipher
	int block_size = EVP_CIPHER_block_size(cipher_type);
	unsigned char *cipher = malloc(plain_len + block_size);
	if (!cipher) { perror("malloc failed for decrypt"); return NULL; }

	// create and initialize context (stores the state of the encryption operation)
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) { printf("cannot create context\n"); free(cipher); return NULL; }

	// initialize encryption operation
	if (!EVP_EncryptInit_ex(ctx, cipher_type, NULL, key, iv)) {
		printf("EVP_EncryptInit_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		free(cipher);
		return NULL;
	}

	// encrypt
	int encrypted_len = 0; // will store number of bytes written by EVP_EncryptUpdate
	if (!EVP_EncryptUpdate(ctx, cipher, &encrypted_len, plain, plain_len)) {
		printf("EVP_EncryptUpdate failed\n");
		EVP_CIPHER_CTX_free(ctx);
		free(cipher);
		return NULL;
	}

	// finalize encryption
	int final_len = 0; // will store number of bytes written by EVP
	if (!EVP_EncryptFinal_ex(ctx, cipher + encrypted_len, &final_len)) {
		printf("EVP_EncryptFinal_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		free(cipher);
		return NULL;
	}

	// total plaintext length (must sum bytes written by Update + Final because padding may change length)
	*cipher_len = (size_t)encrypted_len + (size_t)final_len;

	EVP_CIPHER_CTX_free(ctx);

	// return pointer to decrypted cleaned plain
	return cipher;
}

unsigned char *generate_iv(size_t iv_len) 
{
	unsigned char *iv = malloc(iv_len);
	if (!iv) {
		perror("malloc failed for encrypt_iv\n");
		return NULL;
	}

	if (RAND_bytes(iv, iv_len) != 1) {
		printf("cannot randomly generate iv for encryption\n");
		free(iv);
		return NULL;
	}

	return iv;
}

int write_file(const char *out_filepath, const unsigned char *data, size_t data_len)
{
	FILE *of = fopen(out_filepath, "wb");
	if (!of) { perror("output file"); return 1; }

	size_t written = fwrite(data, 1, data_len, of);
	if (written != data_len) { perror("write error"); fclose(of); return 1; }

	fclose(of);
	return 0;
}

// only free memory you own - if the caller allocated memory, don't free it inside your called function
// otherwise you risk double-free or freeing memory you don't own

// returns plaintext that matches the expected hash
// also provides nont-matching plaintext via `to_free` so it can be freed outside
unsigned char* pick_matching_plaintext(
	unsigned char *plain1, unsigned char *hash1, size_t plain1_len,
	unsigned char *plain2, unsigned char *hash2, size_t plain2_len,
	unsigned char *expected_hash, size_t hash_len,
	unsigned char **to_free, size_t *matching_plain_len
) {
	if (memcmp(hash1, expected_hash, hash_len) == 0) {
		printf("plain1 matches the expected hash.\n");
		*to_free = plain2; // discard non-matching plaintext
		*matching_plain_len = plain1_len;
		return plain1;
	} else if (memcmp(hash2, expected_hash, hash_len) == 0) {
		printf("plain2 matches the expected hash.\n");
		*to_free = plain1; // discard non-matching plaintext
		*matching_plain_len = plain2_len;
		return plain2;
	} else {
		printf("Neither plaintext matches the expected hash!\n");
		return NULL;
	}
}

// beeintraechtigter Text bis Nullzeichen \0
// matching_plain: [beeinträchtigt][\0][nicht beeinträchtigt]
void clean_up_text(unsigned char *plain, size_t plain_len) {
	unsigned char *read = plain; // zeigt auf das aktuelle Zeichen zum Lesen
	unsigned char *write = plain; // zeigt auf die Position, wo das nächste Zeichen im angepassten Text stehen soll

	while (*read != '\0') {
		if (*read == 'i' || *read == 'u') {
			int i_count = 0;
			int u_count = 0;

			// count i and u
			while (*read == 'i' || *read == 'u') {
				if (*read == 'i') i_count++;
				if (*read == 'u') u_count++;
				read++;
			}

			// replace with more frequent letter
			*write = (i_count >= u_count) ? 'i' : 'u';
			write++;
		} else {
			// simply copy all other chars
			*write++ = *read++;
		}
	}

	size_t affected_len = read - plain; // length until '\0'
	size_t remaining_len = plain_len - affected_len -1;

	// memcpy vom nicht-beeinträchtigten Teil
	memcpy(write, read + 1, remaining_len);
	write += remaining_len;

	*write = '\0';
}

// ueber Methoden Aufgabenerfuellung schreiben oder in Dok Comments oder Readme?

int main()
{
	int ret = 0; // in case of success 0 should be returned

	//-- Open Files ---------------------------------------------------- //
	FILE *c1_file = open_file("./data/s91187-cipher1.bin");
	if (!c1_file) return 1;

	FILE *c2_file = open_file("./data/s91187-cipher2.bin");
	if (!c2_file) return 1;

	FILE *expected_hash_file = open_file("./data/s91187-dgst.bin");
	if (!expected_hash_file) return 1;
	//------------------------------------------------------------------ //

	//-- Get Information about Decrypt-Function ------------------------ //
	// EVP_aes_192_abc contains information about decrypt-function including key and iv length
	const EVP_CIPHER *aes_type = EVP_aes_192_cbc();

	size_t decrypt_key_len = EVP_CIPHER_key_length(aes_type);
	size_t decrypt_iv_len = EVP_CIPHER_iv_length(aes_type);
	//------------------------------------------------------------------ //

	//-- Get Information about Encrypt-Function ------------------------ //
	const EVP_CIPHER *sm4_ctr_type = EVP_sm4_ctr();

	size_t encrypt_key_len = EVP_CIPHER_key_length(sm4_ctr_type);
	size_t encrypt_iv_len = EVP_CIPHER_iv_length(sm4_ctr_type);
	//------------------------------------------------------------------ //

	// printf("Key (%d Bytes) and IV (%d Bytes) for AES-192-CBC.\n", key_len, iv_len);

	//-- Get Keys ------------------------------------------------------- //
	const char *k1_filepath = "./data/s91187-key1.bin";
	unsigned char *k1 = read_key(k1_filepath, decrypt_key_len);
	if (!k1) { perror(k1_filepath); ret = 1; goto cleanup; }

	const char *k2_filepath = "./data/s91187-key2.bin";
	unsigned char *k2 = read_key(k2_filepath, encrypt_key_len);
	if (!k2) { perror(k2_filepath); ret = 1; goto cleanup; }
	//------------------------------------------------------------------ //

	//-- Get IVs ------------------------------------------------------- //
	unsigned char *iv1 = read_iv(c1_file, decrypt_iv_len);
	if (!iv1) { ret = 1; goto cleanup; }

	unsigned char *iv2 = read_iv(c2_file, encrypt_iv_len);
	if (!iv2) { ret = 1; goto cleanup; }
	//------------------------------------------------------------------ //

	// c1_file and c2_file pointer should now be directly after IV
	print_hex(iv1, decrypt_iv_len);
	print_hex(iv2, encrypt_iv_len);
	// if (check_file_pointer(c1_file, "c1_file", iv_len)) { ret = 1; goto cleanup; }
	// if (check_file_pointer(c2_file, "c2_file", iv_len)) { ret = 1; goto cleanup; };

	//-- Decrypt ------------------------------------------------------- //
	size_t plain1_len;
	size_t c1_len;
	unsigned char *c1 = read_file(c1_file, decrypt_iv_len, &c1_len);
	unsigned char *plain1 = decrypt(aes_type, c1, c1_len, k1, iv1, &plain1_len);

	size_t plain2_len;
	size_t c2_len;
	unsigned char *c2 = read_file(c2_file, decrypt_iv_len, &c2_len);
	unsigned char *plain2 = decrypt(aes_type, c2, c2_len, k1, iv2, &plain2_len);

	if (!plain1 || !plain2) { printf("Decryption failed\n"); ret = 1; goto cleanup; }
	//------------------------------------------------------------------ //

	// printf("Decrypted c1_file:\n%s\n", plain1);
	// printf("Decrypted c2_file:\n%s\n", plain2);

	//-- Hash ---------------------------------------------------------- //
	const EVP_MD *sha224_type = EVP_sha224();
	size_t hash_len = EVP_MD_size(sha224_type);
	
	unsigned char *hash1 = compute_digest(sha224_type, plain1, plain1_len, hash_len);
	unsigned char *hash2 = compute_digest(sha224_type, plain2, plain2_len, hash_len);

	if (!hash1 || !hash2) { printf("SHA224 computation failed\n"); ret = 1; goto cleanup; }
	//------------------------------------------------------------------ //
	
	// printf("SHA-224 plain1:\n");
	// print_hex(hash1, hash_len);

	// printf("SHA-224 plain2:\n");
	// print_hex(hash2, hash_len);

	//-- Compare Hashes ------------------------------------------------ //
	size_t hash_size;	// filled by read_file
	unsigned char *expected_hash = read_file(expected_hash_file, 0, &hash_size);
	if (!expected_hash) { printf("cannot read expected hash\n"); ret = 1; goto cleanup; }

	// print_hex(buffer, outlen);

	unsigned char *to_free = NULL;
	size_t matching_plain_len;
	unsigned char *matching_plain = pick_matching_plaintext(
		plain1, hash1, plain1_len,
		plain2, hash2, plain2_len,
		expected_hash, hash_len,
		&to_free, &matching_plain_len
	);
	if (!matching_plain) { printf("No matching plaintext found\n"); ret = 1; goto cleanup; }

	// free the non-matching plaintext
	if (to_free) free(to_free);
	//------------------------------------------------------------------ //

	//-- Clean Up Text ------------------------------------------------- //
	clean_up_text(matching_plain, matching_plain_len);
	//------------------------------------------------------------------ //

	// printf("%s\n", matching_plain);

	//-- Encrypt ------------------------------------------------------- //
	// iv notwendig: https://chatgpt.com/c/695aac5e-bcd0-8327-bf1a-38a143d039c2
	// (pseudo)zufällig erzeugen
	unsigned char *encrypt_iv = generate_iv(encrypt_iv_len);
	if (!encrypt_iv) { printf("encryption iv could not be generated\n"); ret = 1; goto cleanup; }

	size_t final_cipher_len;
	unsigned char *final_cipher = encrypt(sm4_ctr_type, matching_plain, matching_plain_len, 
											k2, encrypt_iv, &final_cipher_len);
	
	//------------------------------------------------------------------ //

	//-- Store IV and Cipher in File ----------------------------------- //
	size_t total_len = encrypt_iv_len + final_cipher_len;
	unsigned char *final_data = malloc(total_len);
	if (!final_data) { perror("malloc failed for final_data"); ret = 1; goto cleanup; }

	memcpy(final_data, encrypt_iv, encrypt_iv_len);
	memcpy(final_data + encrypt_iv_len, final_cipher, final_cipher_len);

	if (write_file(OUT_FILE, final_data, total_len)) { perror("write failed"); ret = 1; goto cleanup; };
	//------------------------------------------------------------------ //

	printf("Verschlüsselung erfolgreich\n");
	printf("IV (%zu Byte) + Chiffrat (%zu Byte) in %s gespeichert\n",
			encrypt_iv_len, final_cipher_len, OUT_FILE);

	//-- Cleanup  ------------------------------------------------------ //
cleanup:
	if (k1) free(k1);
    if (k2) free(k2);
    if (iv1) free(iv1);
    if (iv2) free(iv2);
    if (c1) free(c1);
    if (c2) free(c2);
    if (plain1 && (plain1 == matching_plain || !matching_plain)) free(plain1);
    if (plain2 && (plain2 == matching_plain || !matching_plain)) free(plain2);
    if (hash1) free(hash1);
    if (hash2) free(hash2);
    if (expected_hash) free(expected_hash);
    if (c1_file) fclose(c1_file);
    if (c2_file) fclose(c2_file);
    if (expected_hash_file) fclose(expected_hash_file);
	if (encrypt_iv) free(encrypt_iv);
	if (final_data) free(final_data);
	if (final_cipher) free(final_cipher);
	//------------------------------------------------------------------ //

	return ret;
}
