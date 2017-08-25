#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "aes.h"

#define KEYBITS		(128)
#define KEYBYTES	(KEYBITS / 8)

static void display_help(void)
{
	printf(
		"encrypt/decrypt file:\n"
		"       aes [option] -i <in_file> -o <out_file>\n"
		"option:\n"
		"  -h, --help              show this help messagen\n"
		"  -d, --decrypt           decrypt file\n"
		"  -k, --key               key string, 16 characters\n"
		"  -v, --iv                initial vector, 16 characters,\n"
		"                          0 by default\n"
		"  -i, --input=FILE        input file name,\n"
		"                          input from stdin by default\n"
		"  -o, --output=FILE       output file name,\n"
		"                          output to stdout by default\n"
	);
}

static const struct option long_options[] = {
	{"help",	0, NULL, 'h'},
	{"decrypt",	0, NULL, 'd'},
	{"key",		1, NULL, 'k'},
	{"iv",		1, NULL, 'v'},
	{"input",	1, NULL, 'i'},
	{"output",	1, NULL, 'o'},
	{NULL,		0, NULL, 0},
};

/* local varialbles */
static const char *key = NULL;
static const char *iv = NULL;
static bool is_decrypt = false;
static const char *in = NULL;
static const char *out = NULL;

static void parse_command(int argc, char *argv[])
{
	while (1) {
		int opt = getopt_long(argc, argv,
				"hdk:v:i:o",
				long_options, NULL);
		if (opt < 0)
			break;

		switch(opt) {
		case 'h':
			display_help();
			exit(0);
		case 'd':
			is_decrypt = true;
			break;
		case 'k':
			key = optarg;
			break;
		case 'v':
			iv = optarg;
			break;
		case 'i':
			in = optarg;
			break;
		case 'o':
			out = optarg;
			break;
		default:
			printf("unknow option : -%c\n", opt);
			display_help();
			exit(-1);
		}
	}
	if (!key) {
		printf("must input key\n");
		display_help();
		exit(-1);
	}
}

void dump(const void *buf, int len, const char *printf)
{
	int i;
	const unsigned char *b = buf;
	if (printf)
		printf("%s", printf);
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

size_t aes_cbc_encrypt(uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen,
		const uint8_t *key, size_t keybits,
		const uint8_t *iv, size_t ivlen)
{
	AES_KEY enc_key;
	size_t enclen = ALIGN(inlen, AES_BLOCK_SIZE);
	if (outlen < enclen) {
		printf("too small output lenth, %ld < %ld\n", outlen, enclen);
		return 0;
	}

	uint8_t iv_tmp[AES_BLOCK_SIZE] = {0};
	if (iv && ivlen > 0)
		memcpy(iv_tmp, iv, min(sizeof(iv_tmp), ivlen));
	if (AES_set_encrypt_key(key, keybits, &enc_key) < 0) {
		printf("invalid key\n");
		return 0;
	}
	AES_cbc_encrypt(in, out, inlen, &enc_key, iv_tmp, 1);

	return enclen;
}

size_t aes_cbc_decrypt(uint8_t *out, size_t outlen,
		const uint8_t *in, size_t inlen,
		const uint8_t *key, size_t keybits,
		const uint8_t *iv, size_t ivlen)
{
	AES_KEY dec_key;
	if (outlen < inlen || ((inlen & (AES_BLOCK_SIZE - 1)) != 0)) {
		printf("too small output lenth, %ld < %ld\n", outlen, inlen);
		return 0;
	}

	uint8_t iv_tmp[AES_BLOCK_SIZE];
	if (iv && ivlen > 0)
		memcpy(iv_tmp, iv, min(sizeof(iv_tmp), ivlen));
	if (AES_set_decrypt_key(key, keybits, &dec_key) < 0) {
		printf("invalid key\n");
		return 0;
	}
	AES_cbc_encrypt(in, out, inlen, &dec_key, iv_tmp, 0);
	return inlen;
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
