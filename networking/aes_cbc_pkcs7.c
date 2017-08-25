/*
 * AES CBC implementation.
 *
 * Copyright (C) 2017 SZ DJI Technology Co., Ltd.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include "aes.h"
#include "aes_cbc_pkcs7.h"

struct aes_ctx {
	int bits;
	uint8_t key[32];
	uint8_t iv[AES_BLOCK_SIZE];
	uint8_t enc_iv[AES_BLOCK_SIZE];
	uint8_t dec_iv[AES_BLOCK_SIZE];
};

struct aes_ctx *aes_alloc(const uint8_t *key, int keybits,
	const uint8_t iv[AES_BLOCK_SIZE])
{
	struct aes_ctx *ctx = NULL;
	if (!key || (keybits != 128 && keybits != 192 && keybits != 256)) {
		fprintf(stderr, "invalid parameters\n");
		return NULL;
	}

	ctx = malloc(sizeof(struct aes_ctx));
	if (!ctx)
		return NULL;

	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->key, key, keybits / 8);

	if (iv) {
		memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
		memcpy(ctx->enc_iv, iv, AES_BLOCK_SIZE);
		memcpy(ctx->dec_iv, iv, AES_BLOCK_SIZE);
	}

	AES_set_key(ctx->key);

	return ctx;
failed:
	if (ctx)
		free(ctx);
	return NULL;
}

void aes_free(struct aes_ctx *ctx)
{
	if (ctx)
		free(ctx);
}

int aes_cbc_encrypt(struct aes_ctx *ctx, const uint8_t *in, int inlen,
	uint8_t *out, int outlen, bool last)
{
	long n;
	long len = inlen;
	uint8_t tmp[AES_BLOCK_SIZE];
	uint8_t *ivec = ctx->enc_iv;

	while (len >= AES_BLOCK_SIZE) {
		for (n = 0; n < AES_BLOCK_SIZE; n++)
			tmp[n] = in[n] ^ ivec[n];
		AES_encrypt(tmp, out);
		memcpy(ivec, out, AES_BLOCK_SIZE);
		len -= AES_BLOCK_SIZE;
		in += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
	}

	if (len && !last) {
		fprintf(stderr,
			"for non-last block, inlen must be %dbytes aligned\n",
			AES_BLOCK_SIZE);
		return -EINVAL;
	}

	outlen = inlen - len;

	if (last) {
		outlen += AES_BLOCK_SIZE;

		for (n = 0; n < len; ++n)
			tmp[n] = in[n] ^ ivec[n];
		/* use PKCS5/PKCS7 padding */
		for (n = len; n < AES_BLOCK_SIZE; n++)
			tmp[n] = (AES_BLOCK_SIZE - len) ^ ivec[n];
		AES_encrypt(tmp, tmp);
		memcpy(out, tmp, AES_BLOCK_SIZE);
		memcpy(ivec, ctx->iv, AES_BLOCK_SIZE);
	}
	return outlen;
}


int aes_cbc_decrypt(struct aes_ctx *ctx, const uint8_t *in, int inlen,
	uint8_t *out, int outlen, bool last)
{
	int n;
	int len = inlen;
	uint8_t tmp[AES_BLOCK_SIZE];
	uint8_t *ivec = ctx->dec_iv;

	while (len >= AES_BLOCK_SIZE) {
		memcpy(tmp, in, AES_BLOCK_SIZE);
		AES_decrypt(in, out);
		for (n = 0; n < AES_BLOCK_SIZE; n++)
			out[n] ^= ivec[n];
		memcpy(ivec, tmp, AES_BLOCK_SIZE);
		len -= AES_BLOCK_SIZE;
		in += AES_BLOCK_SIZE;
		out += AES_BLOCK_SIZE;
	}
	/* must be AES_BLOCK_SIZE aligned */
	if (len) {
		fprintf(stderr,
			"inlen must be %dbytes aligned\n", AES_BLOCK_SIZE);
		return -EINVAL;
	}

	outlen = inlen;

	/* check PKCS5/PKCS7 padding */
	if (last) {
		uint8_t pad = *(out - 1);
		for (n = 1; n < pad; n++) {
			if (*(out - n) != pad) {
				fprintf(stderr, "wrong padding bytes\n");
				return -EINVAL;
			}
		}
		outlen -= pad;
		memcpy(ivec, ctx->iv, AES_BLOCK_SIZE);
	}

	return outlen;
}
