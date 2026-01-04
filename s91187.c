/*
 * compile and run with:
 *	make
 *	make run
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

//-- Helper Functions ---------------------------------------------- //
unsigned char* read_key(const char *filepath, int key_len)
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

unsigned char* read_iv(FILE *cipher_file, int iv_len)
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

int check_file_pointer(FILE *file, const char *filename, int iv_len)
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

unsigned char* read_file(FILE *file, long offset, long *data_size)
{
	// position file pointer and determine file size
	fseek(file, 0, SEEK_END);
	long filesize = ftell(file);
	if (filesize <= 0 || offset < 0 || offset > filesize) {
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

unsigned char* decrypt(EVP_CIPHER *cipher_type, unsigned char *ciphertext, long cipher_len, 
	unsigned char *key, unsigned char *iv, long *plaintext_len) 
{
	// allocate memory for plaintext
	unsigned char *plain = malloc(cipher_len);
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
	*plaintext_len = decrypted_len + final_len;
	
	// cleanup
	EVP_CIPHER_CTX_free(ctx);

	// return pointer to decrpyted plaintext
	return plain;
}

unsigned char *compute_digest(EVP_MD *hash_type, const unsigned char *data, long len, int hash_len) 
{
	// allocate memory for digest/hash
	unsigned char *digest = malloc(hash_len);
	if (!digest) { perror("malloc failed for digest"); free(digest); return NULL; }

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
	int digest_len = 0; // will store number of bytes written by EVP_DigestUpdate
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

	// cleanup
	EVP_MD_CTX_free(ctx);

	// return pointer to hash
	return digest;
}

void print_hex(const unsigned char *buf, int len)
{
	for (int i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

// only free memory you own - if the caller allocated memory, don't free it inside your called function
// otherwise you risk double-free or freeing memory you don't own

// returns plaintext that matches the expected hash
// also provides nont-matching plaintext via `to_free` so it can be freed outside
unsigned char* pick_matching_plaintext(
	unsigned char *plain1, unsigned char *hash1, long plain1_len,
	unsigned char *plain2, unsigned char *hash2, long plain2_len,
	unsigned char *expected_hash, int hash_len,
	unsigned char **to_free, long *matching_plain_len
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
unsigned char* clean_up_text(unsigned char *plain, long plain_len) {
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

// TODO: readme anpassen! (jetzt Entwicklung unter Linux nicht Windows!!!)
// + Aufgabenstellung umschrieben mit reinbringen

// TODOS:
// (Done) 1. Bisher existierenden Code ausbessern
// 2. mit (3) und (4) von Aufgabenstellung weiter
// 3. Fehler-/Warnungen bei Kompilierung beheben
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

	int key_len = EVP_CIPHER_key_length(aes_type);
	int iv_len = EVP_CIPHER_iv_length(aes_type);
	//------------------------------------------------------------------ //

	// printf("Key (%d Bytes) and IV (%d Bytes) for AES-192-CBC.\n", key_len, iv_len);

	//-- Get Keys ------------------------------------------------------- //
	const char *k1_filepath = "./data/s91187-key1.bin";
	unsigned char *k1 = read_key(k1_filepath, key_len);
	if (!k1) { perror(k1_filepath); ret = 1; goto cleanup; }

	const char *k2_filepath = "./data/s91187-key1.bin";
	unsigned char *k2 = read_key(k2_filepath, key_len);
	if (!k2) { perror(k2_filepath); ret = 1; goto cleanup; }
	//------------------------------------------------------------------ //

	//-- Get IVs ------------------------------------------------------- //
	unsigned char *iv1 = read_iv(c1_file, iv_len);
	if (!iv1) { ret = 1; goto cleanup; }

	unsigned char *iv2 = read_iv(c2_file, iv_len);
	if (!iv2) { ret = 1; goto cleanup; }
	//------------------------------------------------------------------ //

	// c1_file and c2_file pointer should now be directly after IV
	// if (check_file_pointer(c1_file, "c1_file", iv_len)) return 1;
	// if (check_file_pointer(c2_file, "c2_file", iv_len)) return 1;

	//-- Decrypt ------------------------------------------------------- //
	long plain1_len;
	long c1_len;
	unsigned char *c1 = read_file(c1_file, iv_len, &c1_len);
	unsigned char *plain1 = decrypt(aes_type, c1, c1_len, k1, iv1, &plain1_len);

	long plain2_len;
	long c2_len;
	unsigned char *c2 = read_file(c2_file, iv_len, &c2_len);
	unsigned char *plain2 = decrypt(aes_type, c2, c2_len, k1, iv2, &plain2_len);

	if (!plain1 || !plain2) {
		printf("Decryption failed\n");
		ret = 1;
		goto cleanup;
	}
	//------------------------------------------------------------------ //

	// printf("Decrypted c1_file:\n%s\n", plain1);
	// printf("Decrypted c2_file:\n%s\n", plain2);

	//-- Hash ---------------------------------------------------------- //
	const EVP_MD *sha224_type = EVP_sha224();
	int hash_len = EVP_MD_size(sha224_type);
	
	unsigned char *hash1 = compute_digest(sha224_type, plain1, plain1_len, hash_len);
	unsigned char *hash2 = compute_digest(sha224_type, plain2, plain2_len, hash_len);

	if (!hash1 || !hash2) {
		printf("SHA224 computation failed\n");
		ret = 1;
		goto cleanup;
	}
	//------------------------------------------------------------------ //
	
	// printf("SHA-224 plain1:\n");
	// print_hex(hash1, hash_len);

	// printf("SHA-224 plain2:\n");
	// print_hex(hash2, hash_len);

	//-- Compare Hashes ------------------------------------------------ //
	long hash_size;	// filled by read_file
	unsigned char *expected_hash = read_file(expected_hash_file, 0, &hash_size);
	if (!expected_hash) { 
		printf("cannot read expected hash\n");
		ret = 1;
		goto cleanup;
	}

	// print_hex(buffer, outlen);

	unsigned char *to_free = NULL;
	long matching_plain_len;
	unsigned char *matching_plain = pick_matching_plaintext(
		plain1, hash1, plain1_len,
		plain2, hash2, plain2_len,
		expected_hash, hash_len,
		&to_free, &matching_plain_len
	);
	if (!matching_plain) {
		printf("No matching plaintext found\n");
		ret = 1;
		goto cleanup;
	}

	// free the non-matching plaintext
	if (to_free) free(to_free);
	//------------------------------------------------------------------ //

	//-- Clean Up Text ------------------------------------------------- //
	clean_up_text(matching_plain, matching_plain_len);


	printf("%s\n", matching_plain);


	//------------------------------------------------------------------ //
	

cleanup:
	if (k1) free(k1);
    if (k2) free(k2);
    if (iv1) free(iv1);
    if (iv2) free(iv2);
    if (c1) free(c1);
    if (c2) free(c2);
    if (plain1 && plain1 == matching_plain) free(plain1);
    if (plain2 && plain2 == matching_plain) free(plain2);
    if (hash1) free(hash1);
    if (hash2) free(hash2);
    if (expected_hash) free(expected_hash);
    if (c1_file) fclose(c1_file);
    if (c2_file) fclose(c2_file);
    if (expected_hash_file) fclose(expected_hash_file);

	return ret;
}
