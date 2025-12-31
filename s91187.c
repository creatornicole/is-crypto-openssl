/*
 * compile and run with:
 *	make
 *	make run
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

//-- Functions to read Key and IV ---------------------------------- //
unsigned char* read_key(const char *filepath, int key_len)
{
	// open file
	FILE *f = fopen(filepath, "rb");
	if (!f) {
		printf("cannot open key file %s\n", filepath);
		return NULL;
	}

	// allocate memory at runtim
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
		return NULL;
	}

	// hint: the file pointer now points directly after the IV
	return iv;
}
//------------------------------------------------------------------ //

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

// TODO: NOCH BESSER BESCHREIBEN
unsigned char* decrypt_file(EVP_CIPHER *cipher_type, FILE *cipher_file, unsigned char *key, unsigned char *iv, int key_len, int iv_len, int *plaintext_len) 
{
	// read cipher (after IV)
	fseek(cipher_file, 0, SEEK_END);
	long file_size = ftell(cipher_file);
	fseek(cipher_file, iv_len, SEEK_SET); // set after IV
	int cipher_len = file_size - iv_len;

	unsigned char *ciphertext = malloc(cipher_len);
	if (fread(ciphertext, 1, cipher_len, cipher_file) != cipher_len) {
		printf("cannot read ciphertext\n");
		free(ciphertext);
		return NULL;
	}

	unsigned char *plaintext = malloc(cipher_len);
	int outlen1 = 0, outlen2 = 0;

	// create context, stores state
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if (!ctx) { printf("cannot create context\n"); free(ciphertext); free(plaintext); return NULL; }

	// initialization
	EVP_DecryptInit_ex(ctx, cipher_type, NULL, key, iv);

	// decrypt
	if (!EVP_DecryptUpdate(ctx, plaintext, &outlen1, ciphertext, cipher_len)) {
		printf("EVP_DecryptUpdate failed\n");
		EVP_CIPHER_CTX_free(ctx);
		free(ciphertext);
		free(plaintext);
		return NULL;
	}

	// ??
	if (!EVP_DecryptFinal_ex(ctx, plaintext + outlen1, &outlen2)) {
		printf("EVP_DecryptFinal_ex failed\n");
		EVP_CIPHER_CTX_free(ctx);
		free(ciphertext);
		free(plaintext);
		return NULL;
	}

	*plaintext_len = outlen1 + outlen2;

	EVP_CIPHER_CTX_free(ctx);
	free(ciphertext);
	return plaintext;
}

// TODO: NOCH BESSER BESCHREIBEN/ VERSTAENDLICH SCHREIBEN
unsigned char *sha224_buffer(EVP_MD *hash_type, const unsigned char *data, int len, int hash_len) 
{
	unsigned char *digest = malloc(hash_len);
	if (!digest) {
		printf("malloc failed for digest\n");
		return NULL;
	}

	unsigned int digest_len = 0;

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx) {
		free(digest);
		return NULL;
	}

	if (!EVP_DigestInit_ex(ctx, EVP_sha224(), NULL) ||
		!EVP_DigestUpdate(ctx, data, len) ||
		!EVP_DigestFinal_ex(ctx, digest, &digest_len)) {

		printf("SHA224 computation failed\n");
		EVP_MD_CTX_free(ctx);
		free(digest);
		return NULL;
	}

	EVP_MD_CTX_free(ctx);

	// sanity check (28)
	if (digest_len != 28) {
		printf("unexpected SHA224 length: %u\n", digest_len);
		free(digest);
		return NULL;
	}

	// return hash
	return digest;
}

void print_hex(const unsigned char *buf, int len)
{
	for (int i = 0; i < len; i++)
		printf("%02x", buf[i]);
	printf("\n");
}

unsigned char* pick_matching_plaintext(
	unsigned char *plain1, unsigned char *hash1,
	unsigned char *plain2, unsigned char *hash2,
	unsigned char *expected_hash, int hash_len
) {
	// TODO: muss noch mehr freigegeben werden, um Kriterium "Verwerfen Sie die Daten der anderen Datei, zu denen er nicht passt" zu entsprechen?
	if (memcmp(hash1, expected_hash, hash_len) == 0) {
		printf("plain1 matches the expected hash.\n");
		free(plain2); // discard non-matching plaintext
		return plain1;
	} else if (memcmp(hash2, expected_hash, hash_len) == 0) {
		printf("plain2 matches the expected hash.\n");
		free(plain1); // discard non-matching plaintext
		return plain2;
	} else {
		printf("Neither palintext matches the expected hash!\n");
		free(plain1);
		free(plain2);
		return NULL;
	}
}

// TODO: readme anpassen! (jetzt Entwicklung unter Linux nicht Windows!!!)
// Fehler-/Warnungen bei Kompilierung beheben

// TODOS:
// 1. Bisher existierenden Code ausbessern
// 2. mit 3. und 4. von Aufgabenstellung weiter

int main()
{
	//-- Read Files ---------------------------------------------------- //
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

	//-- Get Key ------------------------------------------------------- //
	const char *k1_filepath = "./data/s91187-key1.bin";
	unsigned char *k1 = read_key(k1_filepath, key_len);
	if (!k1) { perror(k1_filepath); return 1; }
	//------------------------------------------------------------------ //

	//-- Get IVs ------------------------------------------------------- //
	unsigned char *iv1 = read_iv(c1_file, iv_len);
	if (!iv1) { free(k1); return 1; }

	unsigned char *iv2 = read_iv(c2_file, iv_len);
	if (!iv2) { free(k1); free(iv1); return 1; }
	//------------------------------------------------------------------ //

	// c1_file and c2_file pointer should now be directly after IV, ready for ciphertext
	// if (check_file_pointer(c1_file, "c1_file", iv_len)) return 1;
	// if (check_file_pointer(c2_file, "c2_file", iv_len)) return 1;

	//-- Decrypt ------------------------------------------------------- //
	int plain1_len = 0;
	unsigned char *plain1 = decrypt_file(aes_type, c1_file, k1, iv1, key_len, iv_len, &plain1_len);

	int plain2_len = 0;
	unsigned char *plain2 = decrypt_file(aes_type, c2_file, k1, iv2, key_len, iv_len, &plain2_len);

	if (!plain1 || !plain2) {
		printf("Decryption failed\n");
		free(k1); free(iv1); free(iv2);
		fclose(c1_file); fclose(c2_file);
		free(plain1); free(plain2);
		return 1;
	}

	//------------------------------------------------------------------ //

	// printf("Decrypted c1_file:\n%s\n", plain1);
	// printf("Decrypted c2_file:\n%s\n", plain2);

	//-- Hash ---------------------------------------------------------- //
	const EVP_MD *sha224_type = EVP_sha224();
	int hash_len = EVP_MD_size(sha224_type);
	
	unsigned char *hash1 = sha224_buffer(sha224_type, plain1, plain1_len, hash_len);
	unsigned char *hash2 = sha224_buffer(sha224_type, plain2, plain2_len, hash_len);

	if (!hash1 || !hash2) {
		printf("Hashing failed\n");
		return 1;
	}
	//------------------------------------------------------------------ //
	
	// printf("SHA-224 plain1:\n");
	// print_hex(hash1, hash_len);

	// printf("SHA-224 plain2:\n");
	// print_hex(hash2, hash_len);

	//-- Compare Hashes ------------------------------------------------ //
	// TODO: auch in Methode? und irgendwie kombinierbar mit read file in decrypt_file?
	// TODO: ÜBERARBEITEN!
	fseek(expected_hash_file, 0, SEEK_END);
	long filesize = ftell(expected_hash_file);
	fseek(expected_hash_file, 0, SEEK_SET);

	if (filesize <= 0) {
		fclose(expected_hash_file);
		return 1;
	}

	// allocate memory
	unsigned char *buffer = malloc(filesize);
	if (!buffer) {
		perror("malloc failed");
		fclose(expected_hash_file);
		return 1;
	}

	// read file content
	if (fread(buffer, 1, filesize, expected_hash_file) != (size_t)filesize) {
		perror("fread failed");
		free(buffer);
		fclose(expected_hash_file);
		return 1;
	}

	int *outlen = filesize;

	// print_hex(buffer, outlen);

	//
	unsigned char *matching_plaintext = pick_matching_plaintext(
		plain1, hash1,
		plain2, hash2,
		buffer, hash_len
	);
	if (!matching_plaintext) return 1;

	//------------------------------------------------------------------ //


	//-- Cleanup ------------------------------------------------------- //
	free(k1);
	free(iv1); free(iv2);
	// free(plain1); free(plain2); // TODO: change, causes double free
	fclose(c1_file); fclose(c2_file);
	// free(hash1); free(hash2);
	//------------------------------------------------------------------ //
	



	//=====================================================================



	/*
	EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(ctx, plaintext, &outlen1, ciphertext, cipher_len);
	EVP_DecryptFinal_ex(ctx, plaintext + outlen1, &outlen2);
	*/

	/*
	free(k1); // Speicher wieder freigeben, wenn er nicht mehr benötigt wird
	// free(iv);
	fclose(c1_file);
	fclose(c2_file);
	*/

	return 0;
}
