/*
 * compile and run with:
 *	make
 *	make run
 */
#include <stdio.h>
#include <openssl/evp.h>

// --------- Functions to read Key and IV --------- //

unsigned char* read_key(const char *filename, int key_len) {
	// open file
	FILE *f = fopen(filename, "rb");
	if (!f) {
		printf("cannot open key file %s\n", filename);
		return NULL;
	}

	// allocate memory at runtim
	unsigned char *key = malloc(key_len);
	if (!key) {
		printf("malloc failed for key from %s\n", filename);
		fclose(f);
		return NULL;
	}

	// read key
	if (fread(key, 1, key_len, f) != key_len) {
		printf("cannot read key from %s\n", filename);
		free(key);
		fclose(f);
		return NULL;
	}

	fclose(f);
	return key;
}

unsigned char* read_iv(FILE *cipher_file, int iv_len) {
	// allocate memory at runtime
	unsigned char *iv = malloc(iv_len);
	if (!iv) {
		printf("malloc failed for IV\n");
		return NULL;
	}

	if (fread(iv, 1, iv_len, cipher_file) != iv_len) {
		printf("cannot read IV from cipher file %s\n", cip)
	}
}

// ------------------------------------------------ //



int main()
{
	/*
	 * If the following line causes the error message
	 * undefined reference to 'EVP_idea_ecb',
	 * please check the SSLDIR that is set in the Makefile.
	 */
	// EVP_idea_ecb();
	FILE *c1_file;
	FILE *k1_file;
	FILE *c2_file;
	FILE *k2_file;
	const EVP_CIPHER *cipher;
	int key_len;
	int iv_len;

	//== READ FILES =======================================================
	c1_file = fopen("s91187-cipher1.bin", "rb");
	if (!c1_file) {
		printf("cannot open s91187-cipher1.bin\n");
		return 1;
	}

	k1_file = fopen("s91187-key1.bin", "rb");
	if (!k1_file) {
		printf("cannot open s91187-key1.bin\n");
		return 1;
	}

	c2_file = fopen("s91187-cipher2.bin", "rb");
	if (!c2_file) {
		printf("cannot open s91187-cipher2.bin\n");
		return 1;
	}

	k2_file = fopen("s91187-key2.bin", "rb");
	if (!k2_file) {
		printf("cannot open s91187-key2.bin\n");
		return 1;
	}
	//=====================================================================

	// contains information about decrypt-function
	// including block size, key size, IV length
	cipher = EVP_aes_192_cbc();
	key_len = EVP_CIPHER_key_length(cipher);
	iv_len = EVP_CIPHER_iv_length(cipher);

	// TODO: Funktion für key2 anlegen


	// read ivs from files
	unsigned char *iv = malloc(iv_len);
	if (fread(iv, 1, iv_len, c1_file) != iv_len) {
		printf("cannot read IV 1");
		return 1;
	}

	printf("Key (%d Bytes) und IV (%d Bytes) eingelesen.\n", key_len, iv_len);

	/*
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv);
	EVP_DecryptUpdate(ctx, plaintext, &outlen1, ciphertext, cipher_len);
	EVP_DecryptFinal_ex(ctx, plaintext + outlen1, &outlen2);
	*/

	printf("hello, world\n");
	printf("key length: %d\n", key_len);
	printf("IV length: %d\n", iv_len);

	// free(key); // Speicher wieder freigeben, wenn er nicht mehr benötigt wird
	// free(iv);

	return 0;
}
