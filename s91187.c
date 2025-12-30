/*
 * compile and run with:
 *	make
 *	make run
 */
#include <stdio.h>
#include <openssl/evp.h>

int main()
{
	/*
	 * If the following line causes the error message
	 * 	undefined reference to 'EVP_idea_ecb',
	 * please check the SSLDIR that is set in the Makefile.
	 */
	EVP_idea_ecb();
	printf("hello, world\n");
	return 0;
}
