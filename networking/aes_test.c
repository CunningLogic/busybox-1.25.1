#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "aes.h"

#define KEYBITS		(128)
#define KEYBYTES	(KEYBITS / 8)
const uint8_t key[KEYBYTES] = "this-aes-key";
const uint8_t iv[AES_BLOCK_SIZE] = {0};
const uint8_t plaintext[16] = "0123456789abcdef";
uint8_t ciphertext[16];
uint8_t decrypttext[16];

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

int encrypt(void)
{
	uint8_t iv_tmp[AES_BLOCK_SIZE] = {0};
	AES_KEY enc_key;
	if (AES_set_encrypt_key(key, KEYBITS, &enc_key) < 0) {
		fprintf(stderr, "invalid key\n");
		return -1;
	}
	memcpy(iv_tmp, iv, sizeof(iv));
	AES_cbc_encrypt(plaintext, ciphertext, sizeof(plaintext),
		&enc_key, iv_tmp, 1);
	return 0;
}

int decrypt(void)
{
	uint8_t iv_tmp[AES_BLOCK_SIZE];
	AES_KEY dec_key;
	if (AES_set_decrypt_key(key, KEYBITS, &dec_key) < 0) {
		fprintf(stderr, "invalid key\n");
		return -1;
	}
	memcpy(iv_tmp, iv, sizeof(iv));
	AES_cbc_encrypt(ciphertext, decrypttext, sizeof(ciphertext),
		&dec_key, iv_tmp, 0);
	return 0;

}

int main(int argc, char *argv[])
{
	encrypt();
	decrypt();
	dump(plaintext, sizeof(plaintext), "plaintext:   ");
	dump(ciphertext, sizeof(ciphertext), "ciphertext:  ");
	dump(decrypttext, sizeof(decrypttext), "decrypttext: ");

	if (0 != memcmp(plaintext, decrypttext, sizeof(plaintext)))
		printf("encrypt/decrypt: FAIL!\n");
	else
		printf("encrypt/decrypt: PASS\n");
	return 0;
}
