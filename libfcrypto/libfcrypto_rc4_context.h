/*
 * RC4 (de/en)crypt functions
 *
 * Copyright (C) 2017-2020, Joachim Metz <joachim.metz@gmail.com>
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

#if !defined( _LIBFCRYPTO_RC4_CONTEXT_H )
#define _LIBFCRYPTO_RC4_CONTEXT_H

#include <common.h>
#include <types.h>

#include "libfcrypto_extern.h"
#include "libfcrypto_libcerror.h"
#include "libfcrypto_types.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libfcrypto_internal_rc4_context libfcrypto_internal_rc4_context_t;

struct libfcrypto_internal_rc4_context
{
	/* The permutations table
	 */
	uint8_t permutations[ 256 ];

	/* The permutations table indexes
	 */
	uint8_t index[ 2 ];
};

LIBFCRYPTO_EXTERN \
int libfcrypto_rc4_context_initialize(
     libfcrypto_rc4_context_t **context,
     libcerror_error_t **error );

LIBFCRYPTO_EXTERN \
int libfcrypto_rc4_context_free(
     libfcrypto_rc4_context_t **context,
     libcerror_error_t **error );

LIBFCRYPTO_EXTERN \
int libfcrypto_rc4_context_set_key(
     libfcrypto_rc4_context_t *context,
     const uint8_t *key,
     size_t key_bit_size,
     libcerror_error_t **error );

LIBFCRYPTO_EXTERN \
int libfcrypto_rc4_crypt(
     libfcrypto_rc4_context_t *context,
     const uint8_t *input_data,
     size_t input_data_size,
     uint8_t *output_data,
     size_t output_data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFCRYPTO_RC4_CONTEXT_H ) */

