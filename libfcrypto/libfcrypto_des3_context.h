/*
 * DES3 (de/en)crypt functions
 *
 * Copyright (C) 2017-2022, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#if !defined( _LIBFCRYPTO_DES3_CONTEXT_H )
#define _LIBFCRYPTO_DES3_CONTEXT_H

#include <common.h>
#include <types.h>

#include "libfcrypto_extern.h"
#include "libfcrypto_libcerror.h"
#include "libfcrypto_types.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libfcrypto_internal_des3_context libfcrypto_internal_des3_context_t;

struct libfcrypto_internal_des3_context
{
	/* The keys
	 */
	uint64_t keys[ 3 ];
};

LIBFCRYPTO_EXTERN \
int libfcrypto_des3_context_initialize(
     libfcrypto_des3_context_t **context,
     libcerror_error_t **error );

LIBFCRYPTO_EXTERN \
int libfcrypto_des3_context_free(
     libfcrypto_des3_context_t **context,
     libcerror_error_t **error );

LIBFCRYPTO_EXTERN \
int libfcrypto_des3_context_set_key(
     libfcrypto_des3_context_t *context,
     const uint8_t *key,
     size_t key_bit_size,
     libcerror_error_t **error );

int libfcrypto_internal_des3_context_crypt_block(
     libfcrypto_internal_des3_context_t *internal_context,
     uint64_t key_value,
     int mode,
     uint64_t input_value,
     uint64_t *output_value,
     libcerror_error_t **error );

LIBFCRYPTO_EXTERN \
int libfcrypto_des3_crypt(
     libfcrypto_des3_context_t *context,
     int mode,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFCRYPTO_DES3_CONTEXT_H ) */

