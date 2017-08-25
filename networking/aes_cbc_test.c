#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_cbc_pkcs7.h"

#define KEYBITS		(128)
#define KEYBYTES	(KEYBITS / 8)

void dump(const void *buf, int len, const char *info)
{
	int i;
	const unsigned char *b = buf;
	if (info)
		printf("%s", info);
	for (i = 0; i < len; i++) {
		if (i % 16 == 0)
			if (i != 0)
				printf("\n");
			else if (i % 8 == 0)
				printf(" ");
		printf("%02x ", b[i]);
	}
	printf("\n");
}

void aes_cbc_test(void)
{
	const uint8_t key[KEYBYTES] = "this-aes-key";
	const uint8_t iv[AES_BLOCK_SIZE] = "0123456789abcdef";

	uint8_t ciphertext[256];
	uint8_t decrypttext[256];
	const uint8_t *plaintext;
	int plainlen, cipherlen, decryptlen;

	struct aes_ctx *ctx = aes_alloc(key, KEYBITS, iv);
	if (!ctx)
		return;

	plaintext = "012";
	plainlen = strlen(plaintext) + 1;
	cipherlen = aes_cbc_encrypt(ctx, plaintext, plainlen,
		ciphertext, sizeof(ciphertext), true);
	decryptlen = aes_cbc_decrypt(ctx, ciphertext, cipherlen,
		decrypttext, sizeof(decrypttext), true);
	dump(plaintext, plainlen, "plaintext:   ");
	dump(ciphertext, cipherlen, "ciphertext:  ");
	dump(decrypttext, decryptlen, "decrypttext: ");

	plaintext = "0123456789abcde";
	plainlen = strlen(plaintext) + 1;
	cipherlen = aes_cbc_encrypt(ctx, plaintext, plainlen,
		ciphertext, sizeof(ciphertext), true);
	decryptlen = aes_cbc_decrypt(ctx, ciphertext, cipherlen,
		decrypttext, sizeof(decrypttext), true);
	dump(plaintext, plainlen, "plaintext:   ");
	dump(ciphertext, cipherlen, "ciphertext:  ");
	dump(decrypttext, decryptlen, "decrypttext: ");

	plaintext = "0123456789abcdef 0123456789";
	plainlen = strlen(plaintext) + 1;
	cipherlen = aes_cbc_encrypt(ctx, plaintext, AES_BLOCK_SIZE,
		ciphertext, sizeof(ciphertext), false);
	cipherlen += aes_cbc_encrypt(ctx, plaintext + AES_BLOCK_SIZE,
		plainlen - AES_BLOCK_SIZE,
		ciphertext + AES_BLOCK_SIZE,
		sizeof(ciphertext) - AES_BLOCK_SIZE, true);
	decryptlen = aes_cbc_decrypt(ctx, ciphertext, cipherlen,
		decrypttext, sizeof(decrypttext), true);
	dump(plaintext, plainlen, "plaintext:   ");
	dump(ciphertext, cipherlen, "ciphertext:  ");
	dump(decrypttext, decryptlen, "decrypttext: ");

	aes_free(ctx);
}

int main(int argc, char *argv[])
{
	aes_cbc_test();
	return 0;
}
