/*
 * OSS-Fuzz target for libfcrypto Blowfish-ECB crypt function
 *
 * Copyright (C) 2011-2024, Joachim Metz <joachim.metz@gmail.com>
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

#include <stddef.h>
#include <stdint.h>

/* Note that some of the OSS-Fuzz engines use C++
 */
extern "C" {

#include "ossfuzz_libfcrypto.h"

int LLVMFuzzerTestOneInput(
     const uint8_t *data,
     size_t size )
{
	uint8_t encrypted_data[ 64 ];

	uint8_t key[ 4 ] = { 0x00, 0x01, 0x02, 0x03 };

	libfcrypto_blowfish_context_t *context = NULL;

	if( libfcrypto_blowfish_context_initialize(
	     &context,
	     NULL ) != 1 )
	{
		return( 0 );
	}
	if( libfcrypto_blowfish_context_set_key(
	     context,
	     key,
	     32,
	     NULL ) != 1 )
	{
		goto on_error_libfcrypto;
	}
	libfcrypto_blowfish_crypt_ecb(
	 context,
	 LIBFCRYPTO_BLOWFISH_CRYPT_MODE_ENCRYPT,
	 data,
	 size,
	 encrypted_data,
	 64,
	 NULL );

on_error_libfcrypto:
	libfcrypto_blowfish_context_free(
	 &context,
	 NULL );

	return( 0 );
}

} /* extern "C" */

