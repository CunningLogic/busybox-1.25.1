/*
 * AES CBC API.
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

#ifndef _AES_CBC_PKCS_H_
#define _AES_CBC_PKCS_H_

#include <stdint.h>
#include <stdbool.h>

#ifndef AES_BLOCK_SIZE
#define AES_BLOCK_SIZE		(16)
#endif

/** allocate aes context.
 *
 * @param key		aes key.
 * @param keybits	bits of aes key, can be 128, 192, 256.
 * @param iv		initial vector, can be NULL or 16bytes.
 *
 * @retval !NULL	allocated aes_ctx, ready to aes_encrypt()/aes_decrypt().
 * @retval NULL		failed to allocate contex, may be invalid parameters
 *			or out of memory.
 */
struct aes_ctx *aes_alloc(const uint8_t *key, int keybits,
	const uint8_t iv[AES_BLOCK_SIZE]);


/** free aes_ctx allocated by aes_alloc().
 *
 * @param ctx		aes_ctx allocated by aes_alloc().
 */
void aes_free(struct aes_ctx *ctx);

/** encrypt data.
 *
 * @param ctx		aes_ctx allocated by aes_alloc().
 * @param in		input plaintext buffer.
 * @param inlen		length of plaintext.
 * @param out		output ciphertext buffer.
 * @param outlen	ciphertext buffer length.
 * @param last		whether it is last block. inlen can be 0 when last=true.
 *
 * @retval >0		output ciphertext length.
 * @retval <0		got errors.
 */
int aes_cbc_encrypt(struct aes_ctx *ctx, const uint8_t *in, int inlen,
	uint8_t *out, int outlen, bool last);

/** decrypt data.
 *
 * @param ctx		aes_ctx allocated by aes_alloc().
 * @param in		input ciphertext buffer.
 * @param inlen		length of ciphertext.
 * @param out		output decrypted text buffer.
 * @param outlen	decrypted text buffer length.
 * @param last		whether it is last block. inlen>=16 when last=true.
 *
 * @retval >0		output decrypted text length.
 * @retval -1		got errors.
 */
int aes_cbc_decrypt(struct aes_ctx *ctx, const uint8_t *in, int inlen,
	uint8_t *out, int outlen, bool last);

#endif /* _AES_CBC_PKCS_H_ */
